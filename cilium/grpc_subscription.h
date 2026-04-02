#pragma once

#include <memory>

#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/config/grpc_mux.h"
#include "envoy/config/subscription.h"
#include "envoy/ssl/context_manager.h"
#include "envoy/stats/scope.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Cilium {

std::unique_ptr<Config::Subscription>
subscribe(const absl::string_view type_url,
          const envoy::config::core::v3::ConfigSource& config_source,
          Server::Configuration::CommonFactoryContext& context, Stats::Scope& scope,
          Config::SubscriptionCallbacks& callbacks,
          Config::OpaqueResourceDecoderSharedPtr resource_decoder,
          Config::GrpcMuxStreamEventCallback on_stream_event = {});
} // namespace Cilium
} // namespace Envoy
