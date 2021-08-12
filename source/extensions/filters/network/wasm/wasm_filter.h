#pragma once

#include <memory>

#include "envoy/extensions/filters/network/wasm/v3/wasm.pb.validate.h"
#include "envoy/network/filter.h"
#include "envoy/server/filter_config.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/extensions/common/wasm/wasm.h"
#include "source/extensions/filters/network/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace Wasm {

using Envoy::Extensions::Common::Wasm::Context;
using Envoy::Extensions::Common::Wasm::ContextSharedPtr;
using Envoy::Extensions::Common::Wasm::PluginHandleManager;
using Envoy::Extensions::Common::Wasm::PluginHandleManagerSharedPtr;
using Envoy::Extensions::Common::Wasm::PluginHandleSharedPtr;
using Envoy::Extensions::Common::Wasm::PluginSharedPtr;

class FilterConfig : Logger::Loggable<Logger::Id::wasm> {
public:
  FilterConfig(const envoy::extensions::filters::network::wasm::v3::Wasm& proto_config,
               Server::Configuration::FactoryContext& context);

  std::shared_ptr<Context> createFilter() {
    // Note pluginHandle() returns always non-null.
    auto handle_manager = tls_slot_->get();
    if (handle_manager->pluginHandle()->isHealthy()) {
      return handle_manager->createContextFromHandle();
    } else if (handle_manager->tryRestartPlugin()) {
      // Restart succeeded.
      return handle_manager->createContextFromHandle();
    }

    if (handle_manager->pluginHandle()->plugin()->fail_open_) {
      return nullptr;
    } else {
      // Fail closed is handled by an empty Context.
      return std::make_shared<Context>(nullptr, 0, handle_manager->pluginHandle());
    }
  }

private:
  ThreadLocal::TypedSlotPtr<PluginHandleManager> tls_slot_;
  Config::DataSource::RemoteAsyncDataProviderPtr remote_data_provider_;
};

using FilterConfigSharedPtr = std::shared_ptr<FilterConfig>;

} // namespace Wasm
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
