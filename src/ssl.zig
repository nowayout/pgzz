//! PostgreSQL SSL/TLS support.
//! Handles SSL upgrade according to sslmode, client certificates, and CA verification.
//! Based on the Go `pq` driver's SSL logic.
//!
//! Note: Zig's std.crypto.tls is experimental and incomplete. This implementation
//! currently only supports `sslmode=disable`. Any other mode will return an error.

const std = @import("std");
const net = std.net;
const fs = std.fs;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

pub const SSLError = error{
    UnsupportedSSLMode,
    SSLNotSupported,
    MissingSSLRootCert,
    InvalidPEM,
    TLSHandshakeFailed,
    CertificateVerificationFailed,
    KeyFilePermissions,
    FileNotFound,
    IOError,
};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

pub const SSLConfig = struct {
    mode: SSLMode,
    server_name: []const u8,
    root_ca_path: ?[]const u8 = null,
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
};

pub const SSLMode = enum {
    disable,
    require,
    verify_ca,
    verify_full,
};

pub fn parseSSLMode(mode_str: []const u8) SSLError!SSLMode {
    if (std.mem.eql(u8, mode_str, "disable")) return .disable;
    if (std.mem.eql(u8, mode_str, "require") or mode_str.len == 0) return .require;
    if (std.mem.eql(u8, mode_str, "verify-ca")) return .verify_ca;
    if (std.mem.eql(u8, mode_str, "verify-full")) return .verify_full;
    return error.UnsupportedSSLMode;
}

/// Upgrade a raw connection to TLS based on the options.
/// Currently only supports `sslmode=disable`. For any other mode, returns `error.SSLNotSupported`.
pub fn upgrade(conn: net.Stream, o: anytype) !?net.Stream {
    _ = conn;

    const mode_str = if (@hasField(@TypeOf(o), "get"))
        o.get("sslmode") orelse ""
    else
        "";
    const mode = parseSSLMode(mode_str) catch return error.UnsupportedSSLMode;
    if (mode == .disable) return null;

    // Zig's TLS implementation is not ready for production use.
    return error.SSLNotSupported;
}

/// Check private key file permissions (Unix only).
fn checkKeyPermissions(path: []const u8) !void {
    if (isWindows()) return;
    const stat = fs.statFile(path) catch return error.FileNotFound;
    const mode = stat.mode;
    if ((mode & 0o077) != 0) {
        return error.KeyFilePermissions;
    }
}

fn isWindows() bool {
    return comptime std.Target.current.os.tag == .windows;
}

/// Get default certificate paths from user's home directory.
/// The returned strings must be freed by the caller.
pub fn getDefaultCertPaths(allocator: std.mem.Allocator) !struct { cert: []const u8, key: []const u8 } {
    const home = std.os.getenv("HOME") orelse std.os.getenv("USERPROFILE") orelse return error.MissingHomeDir;
    const cert_path = try std.fmt.allocPrint(allocator, "{s}/.postgresql/postgresql.crt", .{home});
    const key_path = try std.fmt.allocPrint(allocator, "{s}/.postgresql/postgresql.key", .{home});
    return .{ .cert = cert_path, .key = key_path };
}

/// Apply SSL settings to a connection: returns an upgraded connection if needed.
pub fn maybeUpgrade(conn: net.Stream, o: anytype) !net.Stream {
    const upgraded = try upgrade(conn, o);
    return upgraded orelse conn;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

test "parseSSLMode" {
    try testing.expectEqual(SSLMode.disable, try parseSSLMode("disable"));
    try testing.expectEqual(SSLMode.require, try parseSSLMode("require"));
    try testing.expectEqual(SSLMode.require, try parseSSLMode(""));
    try testing.expectEqual(SSLMode.verify_ca, try parseSSLMode("verify-ca"));
    try testing.expectEqual(SSLMode.verify_full, try parseSSLMode("verify-full"));
    try testing.expectError(error.UnsupportedSSLMode, parseSSLMode("invalid"));
}
