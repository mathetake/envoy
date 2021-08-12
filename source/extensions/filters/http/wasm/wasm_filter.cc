#include "source/extensions/filters/http/wasm/wasm_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Wasm {

FilterConfig::FilterConfig(const envoy::extensions::filters::http::wasm::v3::Wasm& config,
                           Server::Configuration::FactoryContext& context)
    : tls_slot_(ThreadLocal::TypedSlot<PluginHandleManager>::makeUnique(context.threadLocal())) {
  const auto plugin = std::make_shared<Common::Wasm::Plugin>(
      config.config(), context.direction(), context.localInfo(), &context.listenerMetadata());

  auto callback = [plugin, this](PluginHandleManagerSharedPtr plugin_handle_manager) {
    tls_slot_->set([plugin_handle_manager](Event::Dispatcher&) { return plugin_handle_manager; });
  };

  if (!Common::Wasm::createWasm(plugin, context.scope().createScope(""), context.clusterManager(),
                                context.initManager(), context.dispatcher(), context.api(),
                                context.lifecycleNotifier(), remote_data_provider_,
                                std::move(callback))) {
    throw Common::Wasm::WasmException(
        fmt::format("Unable to create Wasm HTTP filter {}", plugin->name_));
  }
}

} // namespace Wasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
