"""Repository rule for cross-compilation support.

Creates a combined aarch64 sysroot that includes the OS sysroot files
plus aarch64 libc++/libc++abi/libunwind from the LLVM distribution.
This lets us use libc++ (matching native x86_64 builds) instead of
libstdc++, avoiding duplicate-symbol conflicts with TCMalloc.
"""

def _aarch64_sysroot_with_libcxx_impl(ctx):
    # Step 1: Download and extract the OS sysroot at the repository root.
    ctx.download_and_extract(
        url = ctx.attr.os_sysroot_url,
        sha256 = ctx.attr.os_sysroot_sha256,
        stripPrefix = "",
        output = "",
    )

    # Step 2: Download the LLVM aarch64 tarball.
    # We only extract the three library files we need, keeping disk usage low.
    ctx.download(
        url = ctx.attr.llvm_url,
        output = "_llvm_aarch64.tar.xz",
        sha256 = ctx.attr.llvm_sha256,
        executable = False,
    )

    # Step 3: Extract libc++.a, libc++abi.a, libunwind.a from the LLVM tarball
    # into the sysroot's aarch64 lib directory.
    #
    # strip_prefix is e.g. "clang+llvm-18.1.8-aarch64-linux-gnu" (1 component).
    # The path inside the tarball is
    #   "{strip_prefix}/lib/aarch64-unknown-linux-gnu/{lib}"
    # so we need --strip-components=3 (prefix + "lib/" + "aarch64-unknown-linux-gnu/")
    # to land the files directly in -C usr/lib/aarch64-linux-gnu.
    num_strip = len(ctx.attr.llvm_strip_prefix.split("/")) + 2
    result = ctx.execute(["mkdir", "-p", "usr/lib/aarch64-linux-gnu"])
    if result.return_code != 0:
        fail("mkdir failed: " + result.stderr)

    tar_args = [
        "tar",
        "-xf", "_llvm_aarch64.tar.xz",
        "--strip-components", str(num_strip),
        "-C", "usr/lib/aarch64-linux-gnu",
    ] + [
        ctx.attr.llvm_strip_prefix + "/lib/" + ctx.attr.llvm_lib_subdir + "/" + lib
        for lib in ctx.attr.llvm_libs
    ]
    result = ctx.execute(tar_args)
    if result.return_code != 0:
        fail("Failed to extract LLVM libs from tarball:\n" + result.stderr)

    # Step 4: Extract the aarch64 __config_site from the LLVM tarball.
    #
    # clang's libc++ __config includes <__config_site> which is arch-specific.
    # The x86_64 LLVM toolchain has include/x86_64-unknown-linux-gnu/c++/v1/__config_site
    # but NOT the aarch64 variant. We pull the aarch64 one from the LLVM aarch64
    # distribution.
    #
    # clang searches <__config_site> via angle-bracket includes, which includes
    # {sysroot}/usr/include as a standard search path. So we place __config_site
    # directly at usr/include/__config_site in the combined sysroot — no extra
    # -isystem flags needed.
    config_site_path = (
        ctx.attr.llvm_strip_prefix + "/include/" + ctx.attr.llvm_lib_subdir + "/c++/v1/__config_site"
    )
    result = ctx.execute([
        "tar",
        "-xf", "_llvm_aarch64.tar.xz",
        "--strip-components",
        str(len(ctx.attr.llvm_strip_prefix.split("/")) + 4),  # strip: prefix/include/{triple}/c++/v1
        "-C", "usr/include",
        config_site_path,
    ])
    if result.return_code != 0:
        fail("Failed to extract __config_site from tarball:\n" + result.stderr)

    # Remove the tarball to keep the repository directory small.
    ctx.execute(["rm", "_llvm_aarch64.tar.xz"])

    # Step 4: Create a BUILD file exposing the combined sysroot filegroup.
    ctx.file("BUILD.bazel", """\
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "sysroot",
    srcs = glob(
        ["**"],
        exclude = [
            "**/*:*",
            "**/*.pl",
        ],
    ),
)
""")

aarch64_sysroot_with_libcxx = repository_rule(
    implementation = _aarch64_sysroot_with_libcxx_impl,
    attrs = {
        "os_sysroot_url": attr.string(mandatory = True),
        "os_sysroot_sha256": attr.string(mandatory = True),
        "llvm_url": attr.string(mandatory = True),
        "llvm_sha256": attr.string(mandatory = True),
        "llvm_strip_prefix": attr.string(mandatory = True),
        "llvm_libs": attr.string_list(
            default = ["libc++.a", "libc++abi.a", "libunwind.a"],
        ),
        "llvm_lib_subdir": attr.string(
            default = "aarch64-unknown-linux-gnu",
        ),
    },
    doc = """\
Downloads an OS sysroot tarball and overlays aarch64 libc++/libc++abi/libunwind
from the LLVM distribution into usr/lib/aarch64-linux-gnu/.

This enables cross-compilation with libc++ (matching native x86_64 builds)
instead of libstdc++, which avoids duplicate operator new/delete symbol
conflicts with TCMalloc when linking statically.
""",
)
