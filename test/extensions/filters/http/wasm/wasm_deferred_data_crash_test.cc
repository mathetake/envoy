// Regression test for the "bricking-wasm" crash: a deferred data-processing
// callback fires after the HTTP/2 stream's filter chain (including a Wasm
// filter) has been destroyed during connection close.  The Wasm filter receives
// proxy_on_request_body after proxy_on_delete, causing the proxy-wasm-rust-sdk
// to panic with "invalid context_id" — bricking the Wasm VM for all subsequent
// requests.
//
// Production stack trace being reproduced:
//   [critical][wasm] [context.cc:1146] wasm log …: panicked at
//     dispatcher.rs:352:13: invalid context_id
//   [error][wasm] [wasm_vm.cc:38] Function: proxy_on_request_body failed:
//     Uncaught RuntimeError: unreachable

#include <memory>
#include <string>

#include "envoy/http/filter.h"
#include "envoy/network/connection.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/common/wasm/wasm.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"

#include "test/extensions/common/wasm/wasm_runtime.h"
#include "test/extensions/filters/http/common/empty_http_filter_config.h"
#include "test/integration/http_protocol_integration.h"
#include "test/test_common/logging.h"
#include "test/test_common/registry.h"
#include "test/test_common/utility.h"

#include "absl/synchronization/mutex.h"
#include "absl/synchronization/notification.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace {

// ---------------------------------------------------------------------------
// C++ orchestrator filter: sets up the readDisable + connection-close race
// condition that triggers the deferred data callback on a destroyed stream.
// ---------------------------------------------------------------------------

struct OrchestratorFilterState {
  absl::Mutex mu;
  bool destroyed ABSL_GUARDED_BY(mu){false};
  bool decode_data_after_destroy ABSL_GUARDED_BY(mu){false};
  Http::StreamDecoderFilterCallbacks* callbacks ABSL_GUARDED_BY(mu){nullptr};
  Event::Dispatcher* dispatcher ABSL_GUARDED_BY(mu){nullptr};
  bool headers_processed ABSL_GUARDED_BY(mu){false};
};

class OrchestratorFilter : public Http::PassThroughFilter {
public:
  explicit OrchestratorFilter(std::shared_ptr<OrchestratorFilterState> state)
      : state_(std::move(state)) {}

  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap&, bool) override {
    decoder_callbacks_->onDecoderFilterAboveWriteBufferHighWatermark();
    {
      absl::MutexLock l(&state_->mu);
      state_->callbacks = decoder_callbacks_;
      state_->dispatcher = &decoder_callbacks_->dispatcher();
      state_->headers_processed = true;
    }
    return Http::FilterHeadersStatus::Continue;
  }

  Http::FilterDataStatus decodeData(Buffer::Instance&, bool) override {
    absl::MutexLock l(&state_->mu);
    if (state_->destroyed) {
      state_->decode_data_after_destroy = true;
    }
    return Http::FilterDataStatus::Continue;
  }

  void onDestroy() override {
    absl::MutexLock l(&state_->mu);
    state_->destroyed = true;
    state_->callbacks = nullptr;
  }

private:
  std::shared_ptr<OrchestratorFilterState> state_;
};

class OrchestratorFilterConfig
    : public Extensions::HttpFilters::Common::EmptyHttpFilterConfig {
public:
  explicit OrchestratorFilterConfig(std::shared_ptr<OrchestratorFilterState> state)
      : EmptyHttpFilterConfig("orchestrator-filter"), state_(std::move(state)) {}

  absl::StatusOr<Http::FilterFactoryCb>
  createFilter(const std::string&, Server::Configuration::FactoryContext&) override {
    return [state = state_](Http::FilterChainFactoryCallbacks& callbacks) -> void {
      callbacks.addStreamFilter(std::make_shared<OrchestratorFilter>(state));
    };
  }

private:
  std::shared_ptr<OrchestratorFilterState> state_;
};

// ---------------------------------------------------------------------------
// Test fixture — HTTP/2 downstream, HTTP/1 upstream.
// ---------------------------------------------------------------------------

class WasmDeferredDataCrashTest : public HttpProtocolIntegrationTest {};

INSTANTIATE_TEST_SUITE_P(
    IpVersions, WasmDeferredDataCrashTest,
    testing::ValuesIn(HttpProtocolIntegrationTest::getProtocolTestParams(
        {Http::CodecType::HTTP2}, {Http::CodecType::HTTP1})),
    HttpProtocolIntegrationTest::protocolTestParamsToString);

// Reproduces the exact production crash: proxy_on_request_body is called on a
// Rust Wasm filter after its context has been destroyed, causing the
// proxy-wasm-rust-sdk to panic with "invalid context_id".
//
// Filter chain: [Wasm passthrough filter] → [C++ orchestrator filter]
//
// Scenario:
//   1. C++ orchestrator calls readDisable(true) in decodeHeaders.
//   2. Client sends DATA + END_STREAM → codec buffers the frame.
//   3. A posted callback calls readDisable(false) (schedules
//      process_buffered_data_callback_) then closes the connection
//      (destroys filter chain → Wasm context is deleted via proxy_on_delete).
//   4. The deferred process_buffered_data_callback_ fires → calls decodeData
//      on the Wasm filter → proxy_on_request_body is called with the deleted
//      context_id → Rust panic "invalid context_id".
//
// With the upstream fix (b701b03368) or our patch: the deferred callback is a
// no-op and proxy_on_request_body is never called on the destroyed context.
TEST_P(WasmDeferredDataCrashTest, InvalidContextIdPanicOnDeferredData) {
  auto state = std::make_shared<OrchestratorFilterState>();

  // Register the C++ orchestrator filter.
  OrchestratorFilterConfig filter_config(state);
  Registry::InjectFactory<Server::Configuration::NamedHttpFilterConfigFactory> registered(
      filter_config);

  // Prepend the C++ orchestrator (will end up second in chain).
  config_helper_.prependFilter(R"EOF(
name: orchestrator-filter
)EOF");

  // Prepend the Wasm filter (will end up first in chain — hit by deferred data).
  const std::string wasm_filter = TestEnvironment::substitute(R"EOF(
name: envoy.filters.http.wasm
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
  config:
    vm_config:
      runtime: envoy.wasm.runtime.v8
      code:
        local:
          filename: "{{ test_rundir }}/test/extensions/filters/http/wasm/test_data/deferred_data_crash_rust.wasm"
)EOF");
  config_helper_.prependFilter(wasm_filter);

  // Wasm filters can be slow to start; increase timeout to avoid flakes.
  setListenersBoundTimeout(30 * TestUtility::DefaultTimeout);

  initialize();

  // Start log recording so we can check for the Wasm panic.
  Envoy::StartStopRecording recording(Envoy::GetLogSink());

  codec_client_ = makeHttpConnection(lookupPort("http"));

  // Send HEADERS only.  The Wasm filter passes through; the C++ orchestrator
  // calls readDisable(true) and sets headers_processed.
  auto [request_encoder, response_decoder] =
      codec_client_->startRequest(default_request_headers_);

  // Wait until the server has processed decodeHeaders and readDisable is on.
  {
    absl::MutexLock l(&state->mu);
    state->mu.Await(absl::Condition(&state->headers_processed));
  }

  // Record rx bytes before DATA so we can tell when it arrives.
  uint64_t bytes_before_data = 0;
  if (auto ctr = test_server_->counter(
          "http.config_test.downstream_cx_rx_bytes_total")) {
    bytes_before_data = ctr->value();
  }

  // Send DATA + END_STREAM.  Because readDisable is on, the codec buffers
  // the frame (body_buffered_ = true) instead of delivering to the filter chain.
  codec_client_->sendData(request_encoder, 1024, true);

  // Wait until the DATA frame (1024 payload + 9-byte frame header) has been
  // received by the server's HTTP/2 codec.
  test_server_->waitForCounterGe("http.config_test.downstream_cx_rx_bytes_total",
                                 bytes_before_data + 1033);

  // Grab the worker-thread dispatcher and callbacks.
  Event::Dispatcher* conn_dispatcher;
  Http::StreamDecoderFilterCallbacks* cbs;
  {
    absl::MutexLock l(&state->mu);
    conn_dispatcher = state->dispatcher;
    cbs = state->callbacks;
  }
  ASSERT_NE(conn_dispatcher, nullptr);
  ASSERT_NE(cbs, nullptr);

  // Post a callback to the connection's worker-thread dispatcher:
  //   (a) readDisable(false)  →  schedules process_buffered_data_callback_
  //   (b) Close connection    →  synchronously destroys filter chain
  // After the callback returns, the event loop fires the deferred
  // process_buffered_data_callback_.  Without the fix this calls
  // proxy_on_request_body on the destroyed Wasm context.
  absl::Notification first_callback_done;
  conn_dispatcher->post([cbs, &first_callback_done]() {
    cbs->onDecoderFilterBelowWriteBufferLowWatermark();
    auto conn_ref = cbs->connection();
    if (conn_ref.has_value()) {
      const_cast<Network::Connection&>(conn_ref.ref())
          .close(Network::ConnectionCloseType::NoFlush,
                 "wasm-deferred-data-crash-test");
    }
    first_callback_done.Notify();
  });

  // Wait for the client to see the disconnect.
  ASSERT_TRUE(codec_client_->waitForDisconnect());
  first_callback_done.WaitForNotification();

  // Post a fence callback: because process_buffered_data_callback_ was
  // scheduled via scheduleCallbackCurrentIteration() before this post(), the
  // event loop will fire it BEFORE this fence.  Waiting guarantees that the
  // deferred decodeData (and any resulting Wasm panic) has already happened.
  absl::Notification event_loop_drained;
  conn_dispatcher->post([&event_loop_drained]() { event_loop_drained.Notify(); });
  event_loop_drained.WaitForNotification();

  // Check 1: the C++ orchestrator must not have seen decodeData after destroy.
  {
    absl::MutexLock l(&state->mu);
    EXPECT_FALSE(state->decode_data_after_destroy)
        << "decodeData was invoked after onDestroy — deferred processing "
           "callback fired on the destroyed filter chain (use-after-free bug)";
  }

  // Check 2: no Wasm panic "invalid context_id" in the logs.
  // This is the exact error from the production incident:
  //   [error][wasm] Function: proxy_on_request_body failed
  //   [critical][wasm] panicked at … invalid context_id
  auto messages = recording.messages();
  bool found_wasm_panic = false;
  std::string panic_message;
  for (const auto& msg : messages) {
    if (msg.find("proxy_on_request_body failed") != std::string::npos ||
        msg.find("invalid context_id") != std::string::npos) {
      found_wasm_panic = true;
      panic_message = msg;
      break;
    }
  }
  EXPECT_FALSE(found_wasm_panic)
      << "Wasm filter panicked with 'invalid context_id' — "
         "proxy_on_request_body was called after the Wasm context was "
         "destroyed via proxy_on_delete. This is the exact crash observed in "
         "the bricking-wasm incident.\nLog: "
      << panic_message;
}

} // namespace
} // namespace Envoy
