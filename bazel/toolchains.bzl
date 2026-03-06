load("@envoy_repo//:compiler.bzl", "LLVM_PATH", "USE_LOCAL_SYSROOT")
load("@envoy_toolshed//repository:utils.bzl", "arch_alias")
load("@toolchains_llvm//toolchain:rules.bzl", "llvm_toolchain")
load("//bazel:cross.bzl", "aarch64_sysroot_with_libcxx")

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
    # from the official LLVM 18.1.8 aarch64 distribution.
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
        aarch64_sysroot_with_libcxx(
            name = "sysroot_linux_arm64_with_libcxx",
            # Envoy toolshed arm64 OS sysroot (glibc 2.31, libstdc++13 headers
            # are present but we will use libc++ headers from the LLVM toolchain).
            os_sysroot_url = "https://github.com/envoyproxy/toolshed/releases/download/bins-v0.1.44/sysroot-glibc2.31-libstdc++13-arm64.tar.xz",
            os_sysroot_sha256 = "d318acbf4a78b9334b71e8c5436aab6a583af27a8ff447f1813db09733d92445",
            # LLVM 18.1.8 aarch64 distribution — source of aarch64 libc++.
            llvm_url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/clang+llvm-18.1.8-aarch64-linux-gnu.tar.xz",
            llvm_sha256 = "dcaa1bebbfbb86953fdfbdc7f938800229f75ad26c5c9375ef242edad737d999",
            llvm_strip_prefix = "clang+llvm-18.1.8-aarch64-linux-gnu",
        )

    llvm_toolchain(
        name = "llvm_toolchain",
        llvm_version = "18.1.8",
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
