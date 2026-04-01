const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "zcash-addr",
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = false,
    });
    b.installArtifact(lib);

    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = false,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    const example_sources = [_]struct { name: []const u8, path: []const u8 }{
        .{ .name = "example-transparent", .path = "examples/transparent.zig" },
        .{ .name = "example-sapling", .path = "examples/sapling.zig" },
        .{ .name = "example-unified", .path = "examples/unified.zig" },
        .{ .name = "example-autodetect", .path = "examples/autodetect.zig" },
    };

    const examples_step = b.step("examples", "Build all examples");
    for (example_sources) |ex| {
        const exe = b.addExecutable(.{
            .name = ex.name,
            .root_source_file = b.path(ex.path),
            .target = target,
            .optimize = optimize,
            .link_libc = false,
        });
        exe.root_module.addImport("zcash_addr", b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = false,
        }));
        examples_step.dependOn(&exe.step);
        b.installArtifact(exe);

        const run_artifact = b.addRunArtifact(exe);
        const run_step_name = b.fmt("run-{s}", .{ex.name});
        const run_step_desc = b.fmt("Run {s}", .{ex.name});
        const run_step = b.step(run_step_name, run_step_desc);
        run_step.dependOn(&run_artifact.step);
    }
}
