const std = @import("std");

/// Hstore represents a PostgreSQL hstore value, which is a key-value map stored as text.
/// The value can be NULL (map == null) or a non-null map from string keys to optional string values.
/// When a value in the map is null, it represents SQL NULL (not an empty string).
pub const Hstore = struct {
    allocator: std.mem.Allocator,
    map: ?std.StringHashMap(?[]const u8),

    /// Initializes an empty, non-null Hstore (equivalent to PostgreSQL hstore '').
    pub fn init(allocator: std.mem.Allocator) Hstore {
        return Hstore{
            .allocator = allocator,
            .map = std.StringHashMap(?[]const u8).init(allocator),
        };
    }

    /// Initializes a NULL Hstore (represents database NULL, not an empty map).
    pub fn initNull(allocator: std.mem.Allocator) Hstore {
        return Hstore{
            .allocator = allocator,
            .map = null,
        };
    }

    /// Releases all memory owned by the Hstore, including all keys and values.
    /// Must be called when the Hstore is no longer needed to prevent memory leaks.
    pub fn deinit(self: *Hstore) void {
        if (self.map) |*m| {
            var it = m.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                if (entry.value_ptr.*) |v| {
                    self.allocator.free(v);
                }
            }
            m.deinit();
        }
        self.* = undefined;
    }

    /// Parses a PostgreSQL hstore text representation into the Hstore structure.
    /// The format is: "key1"=>"value1", "key2"=>NULL, "key3"=>""
    /// If `value` is null, the Hstore becomes NULL (map = null).
    /// If parsing fails, returns an error (usually OutOfMemory).
    pub fn scan(self: *Hstore, _value: ?[]const u8) !void {
        // Clean up any existing map data
        if (self.map) |*m| {
            var it = m.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                if (entry.value_ptr.*) |v| {
                    self.allocator.free(v);
                }
            }
            m.deinit();
        }

        // Handle NULL input
        if (_value == null) {
            self.map = null;
            return;
        }

        // Create new map for parsed data
        self.map = std.StringHashMap(?[]const u8).init(self.allocator);
        var map = &self.map.?;

        const bytes = _value.?;
        var i: usize = 0;
        var parsing_key = true; // true = parsing key, false = parsing value
        var in_quote = false;
        var value_was_quoted = false;
        var saw_backslash = false;

        // Buffers for building key and value strings
        var key_buf = std.array_list.Managed(u8).init(self.allocator);
        defer key_buf.deinit();
        var val_buf = std.array_list.Managed(u8).init(self.allocator);
        defer val_buf.deinit();

        // Parse the hstore text representation
        while (i < bytes.len) : (i += 1) {
            const b = bytes[i];

            // Handle escaped characters
            if (saw_backslash) {
                if (parsing_key) {
                    try key_buf.append(b);
                } else {
                    try val_buf.append(b);
                }
                saw_backslash = false;
                continue;
            }

            switch (b) {
                '\\' => {
                    saw_backslash = true;
                    continue;
                },
                '"' => {
                    in_quote = !in_quote;
                    if (!value_was_quoted) value_was_quoted = true;
                    continue;
                },
                else => {
                    if (!in_quote) {
                        // Outside quotes, these are separators
                        switch (b) {
                            ' ', '\t', '\n', '\r' => continue, // Skip whitespace
                            '=' => continue, // Part of "=>"
                            '>' => {
                                // Transition from key to value
                                parsing_key = false;
                                value_was_quoted = false;
                                continue;
                            },
                            ',' => {
                                // End of current key-value pair
                                const key = try key_buf.toOwnedSlice();
                                const val_str = try val_buf.toOwnedSlice();
                                const val = if (!value_was_quoted and std.ascii.eqlIgnoreCase(val_str, "null")) blk: {
                                    self.allocator.free(val_str);
                                    break :blk null;
                                } else val_str;
                                try map.put(key, val);
                                // Reset for next pair
                                key_buf.clearRetainingCapacity();
                                val_buf.clearRetainingCapacity();
                                parsing_key = true;
                                value_was_quoted = false;
                                continue;
                            },
                            else => {},
                        }
                    }
                    // Add character to current key or value
                    if (parsing_key) {
                        try key_buf.append(b);
                    } else {
                        try val_buf.append(b);
                    }
                },
            }
        }

        // Handle the last pair (if any)
        if (key_buf.items.len > 0 or val_buf.items.len > 0) {
            const key = try key_buf.toOwnedSlice();
            const val_str = try val_buf.toOwnedSlice();
            const val = if (!value_was_quoted and std.ascii.eqlIgnoreCase(val_str, "null")) blk: {
                self.allocator.free(val_str);
                break :blk null;
            } else val_str;
            try map.put(key, val);
        }
    }

    /// Converts the Hstore to its PostgreSQL text representation for storage.
    /// Returns null if the Hstore is NULL, otherwise returns an allocated string.
    /// Caller is responsible for freeing the returned slice with the same allocator.
    pub fn value(self: Hstore) !?[]const u8 {
        const m = self.map orelse return null;

        // Empty map produces empty string
        if (m.count() == 0) {
            const s = try self.allocator.dupe(u8, "");
            return @as(?[]const u8, s);
        }

        var parts = std.array_list.Managed(u8).init(self.allocator);
        defer parts.deinit();

        var it = m.iterator();
        var first = true;
        while (it.next()) |entry| {
            if (!first) {
                try parts.appendSlice(",");
            }
            first = false;

            // Quote and escape the key
            const quoted_key = try quote(self.allocator, entry.key_ptr.*);
            defer self.allocator.free(quoted_key);
            try parts.appendSlice(quoted_key);

            // Add separator
            try parts.appendSlice("=>");

            // Quote and escape the value (or use "NULL" for null)
            const quoted_val = try quoteOptional(self.allocator, entry.value_ptr.*);
            defer self.allocator.free(quoted_val);
            try parts.appendSlice(quoted_val);
        }

        const result = try parts.toOwnedSlice();
        return @as(?[]const u8, result);
    }

    /// Removes all key-value pairs from the Hstore, making it empty but non-null.
    pub fn clear(self: *Hstore) void {
        if (self.map) |*m| {
            var it = m.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                if (entry.value_ptr.*) |v| {
                    self.allocator.free(v);
                }
            }
            m.clearRetainingCapacity();
        } else {
            // Convert NULL hstore to empty hstore
            self.map = std.StringHashMap(?[]const u8).init(self.allocator);
        }
    }
};

/// Quotes and escapes a string for use in an hstore literal.
/// Strings with special characters (", \) are escaped.
/// Returns an allocated slice that must be freed by the caller.
fn quote(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf = std.array_list.Managed(u8).init(allocator);
    defer buf.deinit();
    try buf.append('"');
    for (s) |c| {
        switch (c) {
            '\\' => try buf.appendSlice("\\\\"),
            '"' => try buf.appendSlice("\\\""),
            else => try buf.append(c),
        }
    }
    try buf.append('"');
    return buf.toOwnedSlice();
}

/// Quotes an optional string for hstore output.
/// If the value is null, returns the unquoted string "NULL".
/// Returns an allocated slice that must be freed by the caller.
fn quoteOptional(allocator: std.mem.Allocator, v: ?[]const u8) ![]u8 {
    if (v) |s| {
        return quote(allocator, s);
    } else {
        return allocator.dupe(u8, "NULL");
    }
}

test "Hstore scan and value" {
    const allocator = std.testing.allocator;
    var h = Hstore.init(allocator);
    defer h.deinit();

    // Parse a simple hstore
    const input = "\"key1\"=>\"value1\", \"key2\"=>NULL";
    try h.scan(input);

    try std.testing.expect(h.map != null);
    var map = h.map.?;
    try std.testing.expectEqual(map.count(), 2);

    const val1 = map.get("key1").?;
    try std.testing.expect(val1 != null);
    try std.testing.expectEqualStrings("value1", val1.?);

    const val2 = map.get("key2").?;
    try std.testing.expect(val2 == null);

    // Convert back to text
    const output = try h.value();
    defer if (output) |o| allocator.free(o);
    try std.testing.expect(output != null);
    // Note: order of keys is not guaranteed; we accept either ordering
    const out_str = output.?;
    const ok = std.mem.eql(u8, out_str, "\"key1\"=>\"value1\",\"key2\"=>NULL") or
        std.mem.eql(u8, out_str, "\"key2\"=>NULL,\"key1\"=>\"value1\"");
    try std.testing.expect(ok);

    // Test NULL Hstore
    var hnull = Hstore.initNull(allocator);
    defer hnull.deinit();
    try std.testing.expect(hnull.map == null);
    const null_val = try hnull.value();
    try std.testing.expect(null_val == null);

    // Test empty Hstore
    var hempty = Hstore.init(allocator);
    defer hempty.deinit();
    const empty_val = try hempty.value();
    defer if (empty_val) |ev| allocator.free(ev);
    try std.testing.expect(empty_val != null);
    try std.testing.expectEqualStrings("", empty_val.?);
}
