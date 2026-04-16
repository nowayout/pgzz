const std = @import("std");

/// Main build function for Zig build system
pub fn build(b: *std.Build) void {
    // Configure build target and optimization level from command-line options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Add dependency on pgzz PostgreSQL library
    const psql_dep = b.dependency("pgzz", .{ .target = target, .optimize = optimize });
    const psql_lib = psql_dep.module("pgzz");

    // Create main executable module
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Import pgzz library into executable module
    exe_mod.addImport("pgzz", psql_lib);

    // Configure executable output
    const exe = b.addExecutable(.{
        .name = "example",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    // Create 'check' build step to verify compilation
    const check_step = b.step("check", "checks if the library compiles");
    check_step.dependOn(&exe.step);

    // Configure run command for executable
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    // Pass command-line arguments to executable if provided
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Create 'run' build step
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Configure unit tests
    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Create 'test' build step
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
