const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const pq_module = b.addModule("pgzz", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "pgzz",
        .root_module = pq_module,
    });
    lib.root_module.link_libc = true;

    b.installArtifact(lib);
}
