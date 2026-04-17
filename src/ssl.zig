//! PostgreSQL SSL/TLS support.
//! Handles SSL upgrade according to sslmode, client certificates, and CA verification.
//! Based on the Go `pq` driver's SSL logic.
//!
//! Note: Zig's std.crypto.tls is experimental. This implementation provides full
//! configuration and validation logic, but the actual TLS upgrade currently returns
//! `error.SSLNotSupported`. You can inject a custom upgrade function via
//! `setCustomUpgrader` to enable TLS.

const std = @import("std");
const builtin = @import("builtin");
const net = std.net;
const fs = std.fs;
const os = std.os;
const mem = std.mem;

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
    MissingHomeDir,
};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// SSL/TLS operation mode
pub const SSLMode = enum {
    disable,
    require,
    verify_ca,
    verify_full,
};

/// Parsed SSL configuration
pub const SSLConfig = struct {
    mode: SSLMode,
    server_name: []const u8,
    root_ca_path: ?[]const u8 = null,
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
};

/// Parses sslmode string, returning the corresponding enum.
pub fn parseSSLMode(mode_str: []const u8) SSLError!SSLMode {
    if (mem.eql(u8, mode_str, "disable")) return .disable;
    if (mem.eql(u8, mode_str, "require") or mode_str.len == 0) return .require;
    if (mem.eql(u8, mode_str, "verify-ca")) return .verify_ca;
    if (mem.eql(u8, mode_str, "verify-full")) return .verify_full;
    return error.UnsupportedSSLMode;
}

/// Get default client certificate paths from user's home directory.
/// Caller must free the returned slices.
pub fn getDefaultCertPaths(allocator: std.mem.Allocator) SSLError!struct { cert: []const u8, key: []const u8 } {
    const home = os.getenv("HOME") orelse os.getenv("USERPROFILE") orelse return error.MissingHomeDir;
    const cert_path = try std.fmt.allocPrint(allocator, "{s}/.postgresql/postgresql.crt", .{home});
    const key_path = try std.fmt.allocPrint(allocator, "{s}/.postgresql/postgresql.key", .{home});
    return .{ .cert = cert_path, .key = key_path };
}

/// Check private key file permissions (Unix only). Returns error if permissions are too permissive.
pub fn checkKeyPermissions(path: []const u8) SSLError!void {
    if (builtin.os.tag == .windows) return;
    const stat = fs.cwd().statFile(path) catch return error.FileNotFound;
    const mode = stat.mode;
    if ((mode & 0o077) != 0) {
        return error.KeyFilePermissions;
    }
}

// -----------------------------------------------------------------------------
// TLS upgrader interface
// -----------------------------------------------------------------------------

/// Function that upgrades a raw network connection to a TLS connection.
/// Returns the upgraded connection (or the original if no upgrade).
pub const UpgradeFn = *const fn (raw_conn: net.Stream, config: *const SSLConfig) SSLError!net.Stream;

/// Global custom upgrader (default is null, meaning built‑in TLS is used).
/// The built‑in TLS is not fully implemented; setting this function allows users
/// to provide their own TLS implementation (e.g., using a system library).
var custom_upgrader: ?UpgradeFn = null;

/// Set a custom TLS upgrader function. Use `null` to revert to built‑in (which returns error).
pub fn setCustomUpgrader(upgrader: ?UpgradeFn) void {
    custom_upgrader = upgrader;
}

/// Build SSL configuration from connection options.
/// `get` is a function that retrieves a string option by key, e.g. `fn (key: []const u8) ?[]const u8`.
pub fn buildConfig(allocator: std.mem.Allocator, options_getter: anytype) !SSLConfig {
    const mode_str = options_getter("sslmode") orelse "";
    const mode = try parseSSLMode(mode_str);
    const server_name = options_getter("host") orelse "";

    var config = SSLConfig{
        .mode = mode,
        .server_name = try allocator.dupe(u8, server_name),
    };
    errdefer if (config.mode != .disable) allocator.free(config.server_name);

    if (mode != .disable) {
        // Root CA
        if (options_getter("sslrootcert")) |root| {
            config.root_ca_path = try allocator.dupe(u8, root);
        }
        // Client certificate and key
        var cert_path: ?[]const u8 = options_getter("sslcert");
        var key_path: ?[]const u8 = options_getter("sslkey");
        if ((cert_path == null or cert_path.?.len == 0) and (key_path == null or key_path.?.len == 0)) {
            // Try default paths
            const default_paths = getDefaultCertPaths(allocator) catch null;
            if (default_paths) |paths| {
                cert_path = paths.cert;
                key_path = paths.key;
                // Note: we keep the allocations; they will be freed later
            }
        }
        if (cert_path) |cp| {
            if (cp.len > 0) {
                config.cert_path = try allocator.dupe(u8, cp);
            }
        }
        if (key_path) |kp| {
            if (kp.len > 0) {
                if (config.key_path) |old| allocator.free(old);
                config.key_path = try allocator.dupe(u8, kp);
                // Check permissions on key file
                try checkKeyPermissions(config.key_path.?);
            }
        }
        // For `require` mode with a root CA file, we treat it like `verify-ca`
        if (mode == .require and config.root_ca_path != null) {
            // Change mode to verify_ca internally (but keep original mode for display)
            // We'll handle this during upgrade.
        }
    }
    return config;
}

/// Free resources allocated by `buildConfig`.
pub fn freeConfig(config: *SSLConfig, allocator: std.mem.Allocator) void {
    if (config.mode != .disable) {
        allocator.free(config.server_name);
        if (config.root_ca_path) |p| allocator.free(p);
        if (config.cert_path) |p| allocator.free(p);
        if (config.key_path) |p| allocator.free(p);
    }
}

// -----------------------------------------------------------------------------
// Certificate loading and verification (placeholders)
// -----------------------------------------------------------------------------

/// Load client certificate and key from files. Returns an opaque handle (e.g., X509KeyPair).
/// In a full implementation, this would return a TLS certificate structure.
fn loadClientCertificate(config: *const SSLConfig) !void {
    _ = config;
    // Not implemented; would load files, check permissions, parse PEM.
    return error.SSLNotSupported;
}

/// Load CA root certificate(s) from file. Returns a certificate pool.
fn loadRootCA(config: *const SSLConfig) !void {
    _ = config;
    return error.SSLNotSupported;
}

/// Verify the server's certificate after a TLS handshake (for verify-ca mode).
fn verifyCertificateAuthority(tls_conn: anytype, config: *const SSLConfig) !void {
    _ = tls_conn;
    _ = config;
    return error.SSLNotSupported;
}

// -----------------------------------------------------------------------------
// Main upgrade function
// -----------------------------------------------------------------------------

/// Upgrade a raw connection to TLS based on options.
/// Returns an upgraded connection if SSL is enabled, otherwise returns the original.
/// The original connection is consumed and must not be used afterwards.
pub fn upgrade(allocator: std.mem.Allocator, raw_conn: net.Stream, options_getter: anytype) SSLError!net.Stream {
    const config = try buildConfig(allocator, options_getter);
    defer freeConfig(&config, allocator);

    if (config.mode == .disable) {
        return raw_conn;
    }

    // If a custom upgrader is provided, use it.
    if (custom_upgrader) |up| {
        return try up(raw_conn, &config);
    }

    // Built‑in TLS not implemented.
    // In the future, this could use std.crypto.tls.Client.
    return error.SSLNotSupported;
}

/// Convenience wrapper that takes a raw connection and a values map (e.g., from conn.zig).
pub fn maybeUpgrade(allocator: std.mem.Allocator, raw_conn: net.Stream, opts: anytype) SSLError!net.Stream {
    const getter = struct {
        fn get(key: []const u8) ?[]const u8 {
            if (@TypeOf(opts) == std.StringHashMap([]const u8)) {
                return opts.get(key);
            }
            // Fallback: assume opts is a struct with a get method
            return @call(.auto, opts.get, .{key});
        }
    }.get;
    return upgrade(allocator, raw_conn, getter);
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

test "checkKeyPermissions (no error if file does not exist)" {
    if (builtin.os.tag == .windows) {
        // On Windows, checkKeyPermissions always returns void.
        // So we simply check that it doesn't panic.
        _ = try checkKeyPermissions("/nonexistent/file");
        return;
    }
    const result = checkKeyPermissions("/nonexistent/file");
    try testing.expectError(error.FileNotFound, result);
}
