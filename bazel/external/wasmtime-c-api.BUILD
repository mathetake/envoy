load("@rules_cc//cc:defs.bzl", "cc_library")

licenses(["notice"])  # Apache 2

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "lib",
    hdrs = [
        "include/wasm.h",
    ],
    defines = [
        "ENVOY_WASM_WAVM",  # TODO: delete
        "ENVOY_WASM_WASMTIME",
    ],
    include_prefix = "wasmtime",
    deps = [
        "@com_github_wasmtime//:rust_c_api",
    ],
)
