const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    // ── x32 plugin (.dp32) ──────────────────────────────────────────
    //
    // The plugin is not single-threaded: the MCP server runs on its own
    // thread and one thread per HTTP connection, concurrently with
    // x64dbg's debugger callbacks.  The shared state is protected by
    // SRWLOCK-based locks (src/core/sync.zig).
    const x32_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .x86,
            .os_tag = .windows,
            .abi = .gnu,
        }),
        .optimize = optimize,
    });
    x32_mod.linkSystemLibrary("kernel32", .{});
    x32_mod.linkSystemLibrary("ws2_32", .{});
    x32_mod.linkSystemLibrary("user32", .{});

    const x32 = b.addLibrary(.{
        .name = "x64dbg-MCP-Server",
        .root_module = x32_mod,
        .linkage = .dynamic,
    });

    const install_x32 = b.addInstallArtifact(x32, .{
        .dest_dir = .{ .override = .{ .custom = "x32/plugins" } },
        .dest_sub_path = "x64dbg-MCP-Server.dp32",
        .implib_dir = .disabled,
        .pdb_dir = .disabled,
    });

    // ── x64 plugin (.dp64) ──────────────────────────────────────────
    const x64_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .x86_64,
            .os_tag = .windows,
            .abi = .gnu,
        }),
        .optimize = optimize,
    });
    x64_mod.linkSystemLibrary("kernel32", .{});
    x64_mod.linkSystemLibrary("ws2_32", .{});
    x64_mod.linkSystemLibrary("user32", .{});

    const x64 = b.addLibrary(.{
        .name = "x64dbg-MCP-Server",
        .root_module = x64_mod,
        .linkage = .dynamic,
    });

    const install_x64 = b.addInstallArtifact(x64, .{
        .dest_dir = .{ .override = .{ .custom = "x64/plugins" } },
        .dest_sub_path = "x64dbg-MCP-Server.dp64",
        .implib_dir = .disabled,
        .pdb_dir = .disabled,
    });

    b.default_step.dependOn(&install_x32.step);
    b.default_step.dependOn(&install_x64.step);

    // ── Tests (host target, no Win32 deps) ───────────────────────────
    const test_step = b.step("test", "Run unit tests");
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/mcp/json.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const unit_tests = b.addTest(.{ .root_module = test_mod });
    const run_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_tests.step);

    // The JSON-RPC responses are built by the server module, and they
    // are worth testing without a live debugger: the tool list has to
    // come out complete and parseable.  The root is main.zig so that
    // the whole plugin is inside the module path; the test blocks live
    // in the file they cover.
    const server_test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    server_test_mod.linkSystemLibrary("kernel32", .{});
    server_test_mod.linkSystemLibrary("ws2_32", .{});
    server_test_mod.linkSystemLibrary("user32", .{});
    const server_tests = b.addTest(.{ .root_module = server_test_mod });
    const run_server_tests = b.addRunArtifact(server_tests);
    test_step.dependOn(&run_server_tests.step);
}
