//! PostgreSQL URL parsing.
//! Converts a `postgres://` or `postgresql://` URL into a connection string
//! suitable for `pq.dialOpen` or other PostgreSQL clients.

const std = @import("std");

/// Parse a PostgreSQL URL into a space-separated key-value connection string.
/// The returned string must be freed by the caller using `allocator.free`.
pub fn parseURL(allocator: std.mem.Allocator, url_str: []const u8) ![]u8 {
    if (std.mem.eql(u8, url_str, "postgres://") or std.mem.eql(u8, url_str, "postgresql://")) {
        return allocator.dupe(u8, "");
    }

    const uri = try std.Uri.parse(url_str);
    if (!std.mem.eql(u8, uri.scheme, "postgres") and !std.mem.eql(u8, uri.scheme, "postgresql")) {
        return error.InvalidScheme;
    }

    var kvs = std.array_list.Managed([]const u8).init(allocator);
    defer {
        for (kvs.items) |item| allocator.free(item);
        kvs.deinit();
    }

    // Helper to get component string
    const getCompStr = struct {
        fn call(comp: std.Uri.Component) []const u8 {
            return switch (comp) {
                .raw => |s| s,
                .percent_encoded => |s| s,
            };
        }
    }.call;

    // Helper to escape values for libpq connection string
    const escapeValue = struct {
        fn call(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
            var buf = std.array_list.Managed(u8).init(alloc);
            defer buf.deinit();
            for (s) |ch| {
                switch (ch) {
                    ' ' => try buf.appendSlice("\\ "),
                    '\'' => try buf.appendSlice("\\'"),
                    '\\' => try buf.appendSlice("\\\\"),
                    else => try buf.append(ch),
                }
            }
            return buf.toOwnedSlice();
        }
    }.call;

    // Helper to add a key-value pair
    const addKV = struct {
        fn call(alloc: std.mem.Allocator, list: *std.array_list.Managed([]const u8), key: []const u8, value: []const u8) !void {
            const escaped = try escapeValue(alloc, value);
            defer alloc.free(escaped);
            const kv = try std.fmt.allocPrint(alloc, "{s}={s}", .{ key, escaped });
            try list.append(kv);
        }
    }.call;

    // User info
    if (uri.user) |user| {
        try addKV(allocator, &kvs, "user", getCompStr(user));
        if (uri.password) |password| {
            try addKV(allocator, &kvs, "password", getCompStr(password));
        }
    }

    // Host and port
    if (uri.host) |host_comp| {
        const host_str = getCompStr(host_comp);
        if (uri.port) |port| {
            const port_str = try std.fmt.allocPrint(allocator, "{}", .{port});
            defer allocator.free(port_str);
            try addKV(allocator, &kvs, "host", host_str);
            try addKV(allocator, &kvs, "port", port_str);
        } else {
            try addKV(allocator, &kvs, "host", host_str);
        }
    }

    // Database name from path
    const path_raw = getCompStr(uri.path);
    if (path_raw.len > 1) {
        const dbname = path_raw[1..];
        try addKV(allocator, &kvs, "dbname", dbname);
    }

    // Query parameters
    if (uri.query) |query_comp| {
        const query_str = getCompStr(query_comp);
        if (query_str.len > 0) {
            var it = std.mem.splitScalar(u8, query_str, '&');
            while (it.next()) |pair| {
                const eq_pos = std.mem.indexOfScalar(u8, pair, '=');
                if (eq_pos) |pos| {
                    const key = pair[0..pos];
                    const value = pair[pos + 1 ..];
                    try addKV(allocator, &kvs, key, value);
                } else {
                    try addKV(allocator, &kvs, pair, "");
                }
            }
        }
    }

    // Sort keys
    std.mem.sort([]const u8, kvs.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            const a_key = a[0..std.mem.indexOfScalar(u8, a, '=').?];
            const b_key = b[0..std.mem.indexOfScalar(u8, b, '=').?];
            return std.mem.lessThan(u8, a_key, b_key);
        }
    }.less);

    const result = try std.mem.join(allocator, " ", kvs.items);
    return result;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

test "parseURL - basic" {
    const alloc = testing.allocator;
    const url = "postgres://bob:secret@localhost:5432/mydb?sslmode=disable";
    const conn_str = try parseURL(alloc, url);
    defer alloc.free(conn_str);
    // The order of keys is sorted, so we can test for contains or split.
    // Since we sorted, dbname comes before host, etc.
    // Expected: "dbname=mydb host=localhost password=secret port=5432 sslmode=verify-full user=bob"
    // But because we sort lexicographically: dbname, host, password, port, sslmode, user.
    try testing.expect(std.mem.containsAtLeast(u8, conn_str, 1, "dbname=mydb"));
    try testing.expect(std.mem.containsAtLeast(u8, conn_str, 1, "host=localhost"));
    try testing.expect(std.mem.containsAtLeast(u8, conn_str, 1, "password=secret"));
    try testing.expect(std.mem.containsAtLeast(u8, conn_str, 1, "port=5432"));
    try testing.expect(std.mem.containsAtLeast(u8, conn_str, 1, "sslmode=disable"));
    try testing.expect(std.mem.containsAtLeast(u8, conn_str, 1, "user=bob"));
}

test "parseURL - minimal" {
    const alloc = testing.allocator;
    const url = "postgres://";
    const conn_str = try parseURL(alloc, url);
    defer alloc.free(conn_str);
    try testing.expectEqualStrings("", conn_str);
}

test "parseURL - with IPv6 host" {
    const alloc = testing.allocator;
    const url = "postgresql://[::1]:5433/mydb";
    const conn_str = try parseURL(alloc, url);
    defer alloc.free(conn_str);
    try testing.expect(std.mem.containsAtLeast(u8, conn_str, 1, "host=[::1]"));
    try testing.expect(std.mem.containsAtLeast(u8, conn_str, 1, "port=5433"));
    try testing.expect(std.mem.containsAtLeast(u8, conn_str, 1, "dbname=mydb"));
}

test "parseURL - escaped characters" {
    const alloc = testing.allocator;
    const url = "postgres://user:'password with spaces'@host/db";
    const conn_str = try parseURL(alloc, url);
    defer alloc.free(conn_str);
    // Password should be escaped: \'password\ with\ spaces\'
    // Check that it contains "password=\\'password\\ with\\ spaces\\'"
    try testing.expect(std.mem.indexOf(u8, conn_str, "password=\\'password\\ with\\ spaces\\'") != null);
}
