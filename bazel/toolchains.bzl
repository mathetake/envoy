load("@envoy_repo//:compiler.bzl", "LLVM_PATH", "USE_LOCAL_SYSROOT")
load("@envoy_toolshed//:versions.bzl", "VERSIONS")
load("@envoy_toolshed//repository:utils.bzl", "arch_alias")
load("@toolchains_llvm//toolchain:rules.bzl", "llvm_toolchain")
load("//bazel:cross.bzl", "LLVM_AARCH64_SHA256", "aarch64_sysroot_with_libcxx")

def envoy_toolchains():
    native.register_toolchains("@envoy//bazel/rbe/toolchains/configs/linux/gcc/config:cc-toolchain")
    arch_alias(
        name = "clang_platform",
        aliases = {
            "amd64": "@envoy//bazel/platforms/rbe:linux_x64",
            "aarch64": "@envoy//bazel/platforms/rbe:linux_arm64",
        },
    )

    # Combined aarch64 sysroot: OS sysroot + aarch64 libc++/libc++abi/libunwind
    # from the official LLVM aarch64 distribution.
    #
    # Versions are sourced from @envoy_toolshed//:versions.bzl (VERSIONS["llvm"]
    # and VERSIONS["bins_release"]) so they stay in sync with the rest of the
    # toolchain when the toolshed is updated.
    #
    # This repository is only fetched when actually cross-compiling for aarch64;
    # native x86_64 builds do not trigger the download.
    #
    # We use libc++ instead of libstdc++ to match the native x86_64 build
    # (which uses builtin-libc++) and to avoid duplicate operator new/delete
    # symbol conflicts with TCMalloc that arise when statically linking
    # libstdc++.a (libstdc++ defines strong new/delete; so does TCMalloc).
    # libc++abi defines new/delete as weak symbols, so TCMalloc's overrides win.
    if not USE_LOCAL_SYSROOT:
        _llvm_ver = VERSIONS["llvm"]
        _bins_ver = VERSIONS["bins_release"]
        _arm64_os_sha256 = VERSIONS["sysroot_hashes"]["2.31"]["13"]["arm64"]
        aarch64_sysroot_with_libcxx(
            name = "sysroot_linux_arm64_with_libcxx",
            # Envoy toolshed arm64 OS sysroot (glibc 2.31, libstdc++13 headers
            # are present but we will use libc++ headers from the LLVM toolchain).
            os_sysroot_url = "https://github.com/envoyproxy/toolshed/releases/download/bins-v{ver}/sysroot-glibc2.31-libstdc++13-arm64.tar.xz".format(ver = _bins_ver),
            os_sysroot_sha256 = _arm64_os_sha256,
            # Official LLVM aarch64 distribution — source of aarch64 libc++.
            # The SHA256 is from LLVM_AARCH64_SHA256 in //bazel:cross.bzl.
            llvm_url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-{ver}/clang+llvm-{ver}-aarch64-linux-gnu.tar.xz".format(ver = _llvm_ver),
            llvm_sha256 = LLVM_AARCH64_SHA256[_llvm_ver],
            llvm_strip_prefix = "clang+llvm-{ver}-aarch64-linux-gnu".format(ver = _llvm_ver),
        )

    llvm_toolchain(
        name = "llvm_toolchain",
        llvm_version = VERSIONS["llvm"],
        cxx_standard = {"": "c++20"},
        # Use libc++ for aarch64 cross-compilation to match the native x86_64
        # build (which uses builtin-libc++).  toolchains_llvm v1.6 downgrades
        # builtin-libc++ → stdc++ for cross-compilation, so we set libc++
        # (system) explicitly for linux-aarch64.  The aarch64 libc++.a and
        # libc++abi.a are provided by the combined sysroot
        # @sysroot_linux_arm64_with_libcxx at usr/lib/aarch64-linux-gnu/.
        stdlib = {"linux-aarch64": "libc++"},
        sysroot = {} if USE_LOCAL_SYSROOT else {
            "linux-x86_64": "@sysroot_linux_amd64//:sysroot",
            "linux-aarch64": "@sysroot_linux_arm64_with_libcxx//:sysroot",
        },
        toolchain_roots = {"": LLVM_PATH} if LLVM_PATH else {},
    )
