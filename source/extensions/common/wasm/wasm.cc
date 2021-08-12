#include "source/extensions/common/wasm/wasm.h"

#include <algorithm>
#include <chrono>
#include <memory>

#include "envoy/event/deferred_deletable.h"

#include "source/common/common/logger.h"
#include "source/extensions/common/wasm/plugin.h"
#include "source/extensions/common/wasm/stats_handler.h"

#include "absl/strings/str_cat.h"
#include "wasm_vm.h"

using proxy_wasm::FailState;
using proxy_wasm::Word;

namespace Envoy {

using ScopeWeakPtr = std::weak_ptr<Stats::Scope>;

namespace Extensions {
namespace Common {
namespace Wasm {
namespace {

struct CodeCacheEntry {
  std::string code;
  bool in_progress;
  MonotonicTime use_time;
  MonotonicTime fetch_time;
};

class RemoteDataFetcherAdapter : public Config::DataFetcher::RemoteDataFetcherCallback,
                                 public Event::DeferredDeletable {
public:
  RemoteDataFetcherAdapter(std::function<void(std::string cb)> cb) : cb_(cb) {}
  ~RemoteDataFetcherAdapter() override = default;
  void onSuccess(const std::string& data) override { cb_(data); }
  void onFailure(Config::DataFetcher::FailureReason) override { cb_(""); }
  void setFetcher(std::unique_ptr<Config::DataFetcher::RemoteDataFetcher>&& fetcher) {
    fetcher_ = std::move(fetcher);
  }

private:
  std::function<void(std::string)> cb_;
  std::unique_ptr<Config::DataFetcher::RemoteDataFetcher> fetcher_;
};

const std::string INLINE_STRING = "<inline>";
const int CODE_CACHE_SECONDS_NEGATIVE_CACHING = 10;
const int CODE_CACHE_SECONDS_CACHING_TTL = 24 * 3600; // 24 hours.
MonotonicTime::duration cache_time_offset_for_testing{};

std::mutex code_cache_mutex;
absl::flat_hash_map<std::string, CodeCacheEntry>* code_cache = nullptr;

} // namespace

void Wasm::initializeLifecycle(Server::ServerLifecycleNotifier& lifecycle_notifier) {
  auto weak = std::weak_ptr<Wasm>(std::static_pointer_cast<Wasm>(shared_from_this()));
  lifecycle_notifier.registerCallback(Server::ServerLifecycleNotifier::Stage::ShutdownExit,
                                      [this, weak](Event::PostCb post_cb) {
                                        auto lock = weak.lock();
                                        if (lock) { // See if we are still alive.
                                          server_shutdown_post_cb_ = post_cb;
                                        }
                                      });
}

Wasm::Wasm(WasmVmPtr wasm_vm, WasmConfig& config, absl::string_view vm_key,
           const Stats::ScopeSharedPtr& scope, Upstream::ClusterManager& cluster_manager,
           Event::Dispatcher& dispatcher)
    : WasmBase(std::move(wasm_vm), config.config().vm_config().vm_id(),
               MessageUtil::anyToBytes(config.config().vm_config().configuration()),
               toStdStringView(vm_key), config.environmentVariables(),
               config.allowedCapabilities()),
      cluster_manager_(cluster_manager), dispatcher_(dispatcher), scope_(scope),
      time_source_(dispatcher.timeSource()), lifecycle_stats_handler_(LifecycleStatsHandler(
                                                 scope, config.config().vm_config().runtime())) {
  lifecycle_stats_handler_.onEvent(WasmEvent::VmCreated);
  ENVOY_LOG(debug, "Base Wasm created {} now active", lifecycle_stats_handler_.getActiveVmCount());
}

void Wasm::error(std::string_view message) { ENVOY_LOG(error, "Wasm VM failed {}", message); }

void Wasm::setTimerPeriod(uint32_t context_id, std::chrono::milliseconds new_period) {
  auto& period = timer_period_[context_id];
  auto& timer = timer_[context_id];
  bool was_running = timer && period.count() > 0;
  period = new_period;
  if (was_running) {
    timer->disableTimer();
  }
  if (period.count() > 0) {
    timer = dispatcher_.createTimer(
        [weak = std::weak_ptr<Wasm>(std::static_pointer_cast<Wasm>(shared_from_this())),
         context_id]() {
          auto shared = weak.lock();
          if (shared) {
            shared->tickHandler(context_id);
          }
        });
    timer->enableTimer(period);
  }
}

void Wasm::tickHandler(uint32_t root_context_id) {
  auto period = timer_period_.find(root_context_id);
  auto timer = timer_.find(root_context_id);
  if (period == timer_period_.end() || timer == timer_.end() || !on_tick_) {
    return;
  }
  auto context = getContext(root_context_id);
  if (context) {
    context->onTick(0);
  }
  if (timer->second && period->second.count() > 0) {
    timer->second->enableTimer(period->second);
  }
}

Wasm::~Wasm() {
  lifecycle_stats_handler_.onEvent(WasmEvent::VmShutDown);
  ENVOY_LOG(debug, "~Wasm {} remaining active", lifecycle_stats_handler_.getActiveVmCount());
  if (server_shutdown_post_cb_) {
    dispatcher_.post(server_shutdown_post_cb_);
  }
}

// NOLINTNEXTLINE(readability-identifier-naming)
Word resolve_dns(Word dns_address_ptr, Word dns_address_size, Word token_ptr) {
  auto context = static_cast<Context*>(proxy_wasm::contextOrEffectiveContext());
  auto root_context = context->isRootContext() ? context : context->rootContext();
  auto address = context->wasmVm()->getMemory(dns_address_ptr, dns_address_size);
  if (!address) {
    return WasmResult::InvalidMemoryAccess;
  }
  // Verify set and verify token_ptr before initiating the async resolve.
  uint32_t token = context->wasm()->nextDnsToken();
  if (!context->wasm()->setDatatype(token_ptr, token)) {
    return WasmResult::InvalidMemoryAccess;
  }
  auto callback = [weak_wasm = std::weak_ptr<Wasm>(context->wasm()->sharedThis()), root_context,
                   context_id = context->id(),
                   token](Envoy::Network::DnsResolver::ResolutionStatus status,
                          std::list<Envoy::Network::DnsResponse>&& response) {
    auto wasm = weak_wasm.lock();
    if (!wasm) {
      return;
    }
    root_context->onResolveDns(token, status, std::move(response));
  };
  if (!context->wasm()->dnsResolver()) {
    context->wasm()->dnsResolver() = context->wasm()->dispatcher().createDnsResolver(
        {}, envoy::config::core::v3::DnsResolverOptions());
  }
  context->wasm()->dnsResolver()->resolve(std::string(address.value()),
                                          Network::DnsLookupFamily::Auto, callback);
  return WasmResult::Ok;
}

void Wasm::registerCallbacks() {
  WasmBase::registerCallbacks();
#define _REGISTER(_fn)                                                                             \
  wasm_vm_->registerCallback(                                                                      \
      "env", "envoy_" #_fn, &_fn,                                                                  \
      &proxy_wasm::ConvertFunctionWordToUint32<decltype(_fn), _fn>::convertFunctionWordToUint32)
  _REGISTER(resolve_dns);
#undef _REGISTER
}

void Wasm::getFunctions() {
  WasmBase::getFunctions();
#define _GET(_fn) wasm_vm_->getFunction("envoy_" #_fn, &_fn##_);
  _GET(on_resolve_dns)
  _GET(on_stats_update)
#undef _GET
}

proxy_wasm::CallOnThreadFunction Wasm::callOnThreadFunction() {
  auto& dispatcher = dispatcher_;
  return [&dispatcher](const std::function<void()>& f) { return dispatcher.post(f); };
}

ContextBase* Wasm::createContext(const std::shared_ptr<PluginBase>& plugin) {
  if (create_context_for_testing_) {
    return create_context_for_testing_(this, std::static_pointer_cast<Plugin>(plugin));
  }
  return new Context(this, std::static_pointer_cast<Plugin>(plugin));
}

ContextBase* Wasm::createRootContext(const std::shared_ptr<PluginBase>& plugin) {
  if (create_root_context_for_testing_) {
    return create_root_context_for_testing_(this, std::static_pointer_cast<Plugin>(plugin));
  }
  return new Context(this, std::static_pointer_cast<Plugin>(plugin));
}

ContextBase* Wasm::createVmContext() { return new Context(this); }

void Wasm::log(const PluginSharedPtr& plugin, const Http::RequestHeaderMap* request_headers,
               const Http::ResponseHeaderMap* response_headers,
               const Http::ResponseTrailerMap* response_trailers,
               const StreamInfo::StreamInfo& stream_info) {
  auto context = getRootContext(plugin, true);
  context->log(request_headers, response_headers, response_trailers, stream_info);
}

void Wasm::onStatsUpdate(const PluginSharedPtr& plugin, Envoy::Stats::MetricSnapshot& snapshot) {
  auto context = getRootContext(plugin, true);
  context->onStatsUpdate(snapshot);
}

bool VmCreationRatelimitterImpl::restartAllowed() {
  const auto now = dispatcher_.timeSource().monotonicTime();
  const auto current_window_key = std::chrono::floor<std::chrono::minutes>(now);
  const auto prev_window_key = current_window_key - std::chrono::minutes(1);

  // Take write lock since this might be called from any thread.
  absl::WriterMutexLock lock(&restart_counter_mutext_);
  if (current_restart_window_.window_key_ != current_window_key) {
    if (current_restart_window_.window_key_ == prev_window_key) {
      prev_restart_window_ = current_restart_window_;
    }
    current_restart_window_ =
        VmCreationRatelimitterImpl::RestartCountPerMinuteWindow{current_window_key, 0};
  }

  if (prev_restart_window_.window_key_ != prev_window_key) {
    prev_restart_window_ =
        VmCreationRatelimitterImpl::RestartCountPerMinuteWindow{prev_window_key, 0};
  }

  const double current_window_ratio =
      static_cast<double>((now - current_window_key).count()) /
      MonotonicTime(std::chrono::minutes(1)).time_since_epoch().count();
  const double prev_window_ratio = 1.0 - current_window_ratio;
  const double current_weight =
      static_cast<double>(current_restart_window_.count_ + 1) * current_window_ratio;
  const double prev_weight = static_cast<double>(prev_restart_window_.count_) * prev_window_ratio;
  const auto allowed = current_weight + prev_weight <= static_cast<double>(max_restart_per_minute_);

  if (allowed) {
    // Assume that the new VM will be created right after this function at call sites.
    current_restart_window_.count_++;
  }
  return allowed;
}

void clearCodeCacheForTesting() {
  std::lock_guard<std::mutex> guard(code_cache_mutex);
  if (code_cache) {
    delete code_cache;
    code_cache = nullptr;
  }
  getCreateStatsHandler().resetStatsForTesting();
}

// TODO: remove this post #4160: Switch default to SimulatedTimeSystem.
void setTimeOffsetForCodeCacheForTesting(MonotonicTime::duration d) {
  cache_time_offset_for_testing = d;
}

proxy_wasm::VmCreationRatelimitter getVmCreationRatelimitter(WasmConfig& wasm_config,
                                                             Wasm* base_wasm) {
  auto stats_handler = std::make_shared<LifecycleStatsHandler>(
      base_wasm->scope(), wasm_config.config().vm_config().runtime());

  // If the configuration is not given, then we do not rate-limit.
  if (!wasm_config.config().vm_config().has_restart_config()) {
    return [stats_handler]() -> bool {
      stats_handler->onEvent(WasmEvent::VmRestart);
      return true;
    };
  }
  // Otherwise, create the VmCreationRatelimitterImpl instance with the configuration.
  auto impl = std::make_shared<VmCreationRatelimitterImpl>(
      wasm_config.config().vm_config().restart_config().max_restart_per_minute(),
      base_wasm->dispatcher());
  return [stats_handler, impl]() -> bool {
    stats_handler->onEvent(WasmEvent::VmRestart);
    return impl->restartAllowed();
  };
}

static proxy_wasm::BaseWasmHandleFactory
getBaseWasmHandleFactory(WasmConfig& wasm_config, const Stats::ScopeSharedPtr& scope,
                         Upstream::ClusterManager& cluster_manager, Event::Dispatcher& dispatcher,
                         Server::ServerLifecycleNotifier& lifecycle_notifier) {
  return [&wasm_config, &scope, &cluster_manager, &dispatcher,
          &lifecycle_notifier](std::string_view vm_key) -> proxy_wasm::BaseWasmHandleSharedPtr {
    auto wasm_vm = createWasmVm(wasm_config.config().vm_config().runtime());
    auto wasm = std::make_unique<Wasm>(std::move(wasm_vm), wasm_config, toAbslStringView(vm_key),
                                       scope, cluster_manager, dispatcher);
    wasm->initializeLifecycle(lifecycle_notifier);
    auto rate_limitter = getVmCreationRatelimitter(wasm_config, wasm.get());
    return std::make_shared<proxy_wasm::BaseWasmHandle>(std::move(wasm), rate_limitter);
  };
}

static proxy_wasm::ThreadLocalWasmHandleFactory
getThreadLocalWasmHandleFactory(WasmConfig& wasm_config,
                                CreateContextFn create_root_context_for_testing) {
  return [&wasm_config,
          &create_root_context_for_testing](proxy_wasm::BaseWasmHandleSharedPtr base_wasm_handle)
             -> proxy_wasm::ThreadLocalWasmHandleSharedPtr {
    auto wasm_vm = base_wasm_handle->cloneWasmVm([&wasm_config]() {
      return createWasmVm(toAbslStringView(wasm_config.config().vm_config().runtime()));
    });

    auto base_wasm = static_cast<Wasm*>(base_wasm_handle->wasm());
    auto wasm = std::make_unique<Wasm>(std::move(wasm_vm), wasm_config,
                                       toAbslStringView(base_wasm->vmKey()), base_wasm->scope(),
                                       base_wasm->clusterManager(), base_wasm->dispatcher());
    wasm->setCreateContextForTesting(nullptr, create_root_context_for_testing);
    return std::make_shared<proxy_wasm::ThreadLocalWasmHandle>(std::move(wasm), base_wasm_handle);
  };
}

WasmEvent toWasmEvent(const proxy_wasm::BaseWasmHandleSharedPtr& base_wasm_handle) {
  if (!base_wasm_handle) {
    return WasmEvent::UnableToCreateVm;
  }
  switch (base_wasm_handle->wasm()->failState()) {
  case FailState::Ok:
    return WasmEvent::Ok;
  case FailState::UnableToCreateVm:
    return WasmEvent::UnableToCreateVm;
  case FailState::UnableToCloneVm:
    return WasmEvent::UnableToCloneVm;
  case FailState::MissingFunction:
    return WasmEvent::MissingFunction;
  case FailState::UnableToInitializeCode:
    return WasmEvent::UnableToInitializeCode;
  case FailState::StartFailed:
    return WasmEvent::StartFailed;
  case FailState::ConfigureFailed:
    return WasmEvent::ConfigureFailed;
  case FailState::RuntimeError:
    return WasmEvent::RuntimeError;
  }
  NOT_IMPLEMENTED_GCOVR_EXCL_LINE;
}

bool createWasm(const PluginSharedPtr& plugin, const Stats::ScopeSharedPtr& scope,
                Upstream::ClusterManager& cluster_manager, Init::Manager& init_manager,
                Event::Dispatcher& dispatcher, Api::Api& api,
                Server::ServerLifecycleNotifier& lifecycle_notifier,
                Config::DataSource::RemoteAsyncDataProviderPtr& remote_data_provider,
                CreateWasmCallback&& cb, CreateContextFn create_root_context_for_testing) {
  auto& stats_handler = getCreateStatsHandler();
  std::string source, code;
  auto config = plugin->wasmConfig();
  auto vm_config = config.config().vm_config();
  bool fetch = false;
  if (vm_config.code().has_remote()) {
    auto now = dispatcher.timeSource().monotonicTime() + cache_time_offset_for_testing;
    source = vm_config.code().remote().http_uri().uri();
    std::lock_guard<std::mutex> guard(code_cache_mutex);
    if (!code_cache) {
      code_cache = new std::remove_reference<decltype(*code_cache)>::type;
    }
    Stats::ScopeSharedPtr create_wasm_stats_scope = stats_handler.lockAndCreateStats(scope);
    // Remove entries older than CODE_CACHE_SECONDS_CACHING_TTL except for our target.
    for (auto it = code_cache->begin(); it != code_cache->end();) {
      if (now - it->second.use_time > std::chrono::seconds(CODE_CACHE_SECONDS_CACHING_TTL) &&
          it->first != vm_config.code().remote().sha256()) {
        code_cache->erase(it++);
      } else {
        ++it;
      }
    }
    stats_handler.onRemoteCacheEntriesChanged(code_cache->size());
    auto it = code_cache->find(vm_config.code().remote().sha256());
    if (it != code_cache->end()) {
      it->second.use_time = now;
      if (it->second.in_progress) {
        stats_handler.onEvent(WasmEvent::RemoteLoadCacheMiss);
        ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::wasm), warn,
                            "createWasm: failed to load (in progress) from {}", source);
        cb(std::make_shared<PluginHandleManager>(nullptr, nullptr, plugin));
      }
      code = it->second.code;
      if (code.empty()) {
        if (now - it->second.fetch_time <
            std::chrono::seconds(CODE_CACHE_SECONDS_NEGATIVE_CACHING)) {
          stats_handler.onEvent(WasmEvent::RemoteLoadCacheNegativeHit);
          ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::wasm), warn,
                              "createWasm: failed to load (cached) from {}", source);
          cb(std::make_shared<PluginHandleManager>(nullptr, nullptr, plugin));
        }
        fetch = true; // Fetch failed, retry.
        it->second.in_progress = true;
        it->second.fetch_time = now;
      } else {
        stats_handler.onEvent(WasmEvent::RemoteLoadCacheHit);
      }
    } else {
      fetch = true; // Not in cache, fetch.
      auto& e = (*code_cache)[vm_config.code().remote().sha256()];
      e.in_progress = true;
      e.use_time = e.fetch_time = now;
      stats_handler.onRemoteCacheEntriesChanged(code_cache->size());
      stats_handler.onEvent(WasmEvent::RemoteLoadCacheMiss);
    }
  } else if (vm_config.code().has_local()) {
    code = Config::DataSource::read(vm_config.code().local(), true, api);
    source = Config::DataSource::getPath(vm_config.code().local())
                 .value_or(code.empty() ? EMPTY_STRING : INLINE_STRING);
  }

  auto vm_key = proxy_wasm::makeVmKey(vm_config.vm_id(),
                                      MessageUtil::anyToBytes(vm_config.configuration()), code);
  auto complete_cb = [cb, vm_key, plugin, scope, &cluster_manager, &dispatcher, &lifecycle_notifier,
                      create_root_context_for_testing, &stats_handler](std::string code) -> bool {
    if (code.empty()) {
      cb(std::make_shared<PluginHandleManager>(nullptr, nullptr, plugin));
      return false;
    }

    auto config = plugin->wasmConfig();
    auto thread_local_plugin_handle_factory =
        getThreadLocalWasmHandleFactory(config, create_root_context_for_testing);
    proxy_wasm::BaseWasmHandleSharedPtr base_wasm_handle = proxy_wasm::createBaseWasmHandle(
        vm_key, code, plugin,
        getBaseWasmHandleFactory(config, scope, cluster_manager, dispatcher, lifecycle_notifier),
        thread_local_plugin_handle_factory, config.config().vm_config().allow_precompiled());
    Stats::ScopeSharedPtr create_wasm_stats_scope = stats_handler.lockAndCreateStats(scope);
    stats_handler.onEvent(toWasmEvent(base_wasm_handle));
    if (!base_wasm_handle || base_wasm_handle->wasm()->isFailed()) {
      ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::wasm), trace,
                          "Unable to create Wasm");
      cb(std::make_shared<PluginHandleManager>(nullptr, nullptr, plugin));
      return false;
    }
    cb(std::make_shared<PluginHandleManager>(thread_local_plugin_handle_factory, base_wasm_handle,
                                             plugin));
    return true;
  };

  if (fetch) {
    auto holder = std::make_shared<std::unique_ptr<Event::DeferredDeletable>>();
    auto fetch_callback = [vm_config, complete_cb, source, &dispatcher, scope, holder, plugin,
                           &stats_handler](const std::string& code) {
      {
        std::lock_guard<std::mutex> guard(code_cache_mutex);
        auto& e = (*code_cache)[vm_config.code().remote().sha256()];
        e.in_progress = false;
        e.code = code;
        Stats::ScopeSharedPtr create_wasm_stats_scope = stats_handler.lockAndCreateStats(scope);
        if (code.empty()) {
          stats_handler.onEvent(WasmEvent::RemoteLoadCacheFetchFailure);
        } else {
          stats_handler.onEvent(WasmEvent::RemoteLoadCacheFetchSuccess);
        }
        stats_handler.onRemoteCacheEntriesChanged(code_cache->size());
      }
      // NB: xDS currently does not support failing asynchronously, so we fail immediately
      // if remote Wasm code is not cached and do a background fill.
      if (!vm_config.nack_on_code_cache_miss()) {
        if (code.empty()) {
          ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::wasm), trace,
                              "Failed to load Wasm code (fetch failed) from {}", source);
        }
        complete_cb(code);
      }
      // NB: must be deleted explicitly.
      if (*holder) {
        dispatcher.deferredDelete(Envoy::Event::DeferredDeletablePtr{holder->release()});
      }
    };
    if (vm_config.nack_on_code_cache_miss()) {
      auto adapter = std::make_unique<RemoteDataFetcherAdapter>(fetch_callback);
      auto fetcher = std::make_unique<Config::DataFetcher::RemoteDataFetcher>(
          cluster_manager, vm_config.code().remote().http_uri(), vm_config.code().remote().sha256(),
          *adapter);
      auto fetcher_ptr = fetcher.get();
      adapter->setFetcher(std::move(fetcher));
      *holder = std::move(adapter);
      fetcher_ptr->fetch();
      ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::wasm), trace,
                          fmt::format("Failed to load Wasm code (fetching) from {}", source));
      cb(std::make_shared<PluginHandleManager>(nullptr, nullptr, plugin));
      return false;
    } else {
      remote_data_provider = std::make_unique<Config::DataSource::RemoteAsyncDataProvider>(
          cluster_manager, init_manager, vm_config.code().remote(), dispatcher,
          api.randomGenerator(), true, fetch_callback);
    }
  } else {
    return complete_cb(code);
  }
  return true;
}

} // namespace Wasm
} // namespace Common
} // namespace Extensions
} // namespace Envoy
