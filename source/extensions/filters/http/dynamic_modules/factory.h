#pragma once

#include "envoy/extensions/filters/http/dynamic_modules/v3/dynamic_modules.pb.h"
#include "envoy/extensions/filters/http/dynamic_modules/v3/dynamic_modules.pb.validate.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/dynamic_modules/dynamic_modules.h"
#include "source/extensions/filters/http/dynamic_modules/filter_config.h"
#include "source/extensions/filters/http/common/factory_base.h"

namespace Envoy {
namespace Server {
namespace Configuration {

using FilterConfig = envoy::extensions::filters::http::dynamic_modules::v3::DynamicModuleFilter;
using DynamicModuleHttpFilterConfigSharedPtr =
    Envoy::Extensions::DynamicModules::HttpFilters::DynamicModuleHttpFilterConfigSharedPtr;

class DynamicModuleConfigFactory
    : public Extensions::HttpFilters::Common::DualFactoryBase<FilterConfig> {
public:
  DynamicModuleConfigFactory() : DualFactoryBase("envoy.extensions.filters.http.dynamic_modules") {}
  absl::StatusOr<Http::FilterFactoryCb>
  createFilterFactoryFromProtoTyped(const FilterConfig& raw_config, const std::string&, DualInfo,
                                    Server::Configuration::ServerFactoryContext& context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr{new FilterConfig()};
  }

  absl::StatusOr<Router::RouteSpecificFilterConfigConstSharedPtr>
  createRouteSpecificFilterConfigTyped(const FilterConfig& raw_config,
                                       Server::Configuration::ServerFactoryContext& context,
                                       ProtobufMessage::ValidationVisitor&) override {
    // Use the same config API, so almost all of the code is shared.
    absl::StatusOr<DynamicModuleHttpFilterConfigSharedPtr> ret =
        createFilterConfig(raw_config, context);
    return ret;
  }

  std::string name() const override { return "envoy.extensions.filters.http.dynamic_modules"; }

private:
  /**
   * createFilterConfig is a helper function to create the filter config shared between the normal
   * listner-level callback as well as the route-level callback.
   */
  absl::StatusOr<DynamicModuleHttpFilterConfigSharedPtr>
  createFilterConfig(const FilterConfig& raw_config,
                     Server::Configuration::ServerFactoryContext& context);
};
using UpstreamDynamicModuleConfigFactory = DynamicModuleConfigFactory;

} // namespace Configuration
} // namespace Server
} // namespace Envoy
