#pragma once

#include <memory>

#include "envoy/extensions/filters/network/wasm/v3/wasm.pb.validate.h"
#include "envoy/stats/sink.h"

#include "source/extensions/common/wasm/wasm.h"

namespace Envoy {
namespace Extensions {
namespace StatSinks {
namespace Wasm {

using Envoy::Extensions::Common::Wasm::PluginHandleManagerSharedPtr;
using Envoy::Extensions::Common::Wasm::PluginSharedPtr;
using Envoy::Extensions::Common::Wasm::Wasm;

class WasmStatSink : public Stats::Sink {
public:
  WasmStatSink(const PluginSharedPtr& plugin, PluginHandleManagerSharedPtr singleton)
      : plugin_(plugin), singleton_(singleton) {}

  void flush(Stats::MetricSnapshot& snapshot) override {
    auto healthy = singleton_->pluginHandle()->isHealthy();
    if (!singleton_->pluginHandle()->isHealthy()) {
      // Try restarting.
      healthy = singleton_->tryRestartPlugin();
    }
    if (healthy) {
      auto wasm = static_cast<Wasm*>(singleton_->pluginHandle()->threadLocalWasmHandle()->wasm());
      wasm->onStatsUpdate(plugin_, snapshot);
    }
  }

  void setSingleton(PluginHandleManagerSharedPtr singleton) {
    ASSERT(singleton != nullptr);
    singleton_ = singleton;
  }

  void onHistogramComplete(const Stats::Histogram& histogram, uint64_t value) override {
    (void)histogram;
    (void)value;
  }

private:
  PluginSharedPtr plugin_;
  PluginHandleManagerSharedPtr singleton_;
};

} // namespace Wasm
} // namespace StatSinks
} // namespace Extensions
} // namespace Envoy
