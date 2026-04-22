//! PostgreSQL array type support.
//! Provides parsing of PostgreSQL array text format and serialization to that format.
//! Common array types (bool, f64, i64, []u8, string) are provided with dedicated types.
//! A generic `GenericArray(T)` is also available for other element types.

const std = @import("std");
const ArrayList = std.ArrayList;

// -----------------------------------------------------------------------------
// Core parsing and serialization
// -----------------------------------------------------------------------------

/// Parses a PostgreSQL array in text format.
/// Returns a slice of flattened elements (as []const u8) and an array of dimensions.
/// The caller must free the returned slices using the provided allocator.
///
/// Array format examples:
///   - Simple array: "{1,2,3}"
///   - With NULL: "{1,NULL,3}"
///   - Quoted strings: "{\"hello\",\"world\"}"
///   - Multi-dimensional: "{{1,2},{3,4}}"
///
/// The delimiter is typically "," for most array types.
pub fn parseArray(allocator: std.mem.Allocator, src: []const u8, delimiter: []const u8) !struct { dims: []usize, elems: []?[]const u8 } {
    var dims_buf = ArrayList(usize).empty;
    var elems_buf = ArrayList(?[]const u8).empty;

    // Ensure cleanup on error
    errdefer {
        for (elems_buf.items) |elem| {
            if (elem) |e| allocator.free(e);
        }
        elems_buf.deinit(allocator);
        dims_buf.deinit(allocator);
    }

    var i: usize = 0;
    var depth: usize = 0;

    // Arrays must start with '{'
    if (src.len == 0 or src[0] != '{') {
        return error.InvalidArrayFormat;
    }

    // Parse dimensions: count opening braces before first element
    while (i < src.len) {
        switch (src[i]) {
            '{' => {
                depth += 1;
                i += 1;
            },
            '}' => {
                // Empty array case: "{}"
                return .{ .dims = try dims_buf.toOwnedSlice(allocator), .elems = try elems_buf.toOwnedSlice(allocator) };
            },
            else => break,
        }
    }

    // Initialize dimension counts
    try dims_buf.resize(allocator, depth);
    @memset(dims_buf.items, 0);

    // Helper to read a quoted string element (returns allocated string)
    const readQuoted = struct {
        fn read(alloc: std.mem.Allocator, s: []const u8, idx: *usize) ![]const u8 {
            idx.* += 1; // Skip initial quote
            var buf = ArrayList(u8).empty;
            defer buf.deinit(alloc);
            var escape = false;
            while (idx.* < s.len) {
                const c = s[idx.*];
                idx.* += 1;
                if (escape) {
                    try buf.append(alloc, c);
                    escape = false;
                } else {
                    switch (c) {
                        '\\' => escape = true,
                        '"' => break, // End of quoted string
                        else => try buf.append(alloc, c),
                    }
                }
            }
            return try buf.toOwnedSlice(alloc);
        }
    }.read;

    // Helper to read a non-quoted element (until delimiter or '}')
    // Returns the slice into `src` (no allocation) or null for "NULL".
    const readUnquoted = struct {
        fn read(s: []const u8, idx: *usize, del: []const u8) !?[]const u8 {
            const start = idx.*;
            while (idx.* < s.len) {
                if (s[idx.*] == '}') break;
                if (idx.* + del.len <= s.len and std.mem.eql(u8, s[idx.* .. idx.* + del.len], del)) break;
                idx.* += 1;
            }
            if (start == idx.*) return error.EmptyElement;
            const slice = s[start..idx.*];
            if (std.mem.eql(u8, slice, "NULL")) {
                return null;
            }
            return slice;
        }
    }.read;

    // Main parsing loop
    while (i < src.len) {
        const c = src[i];
        switch (c) {
            '{' => {
                if (depth == dims_buf.items.len) break; // Nested array, not yet fully supported
                depth += 1;
                i += 1;
                dims_buf.items[depth - 1] = 0;
            },
            '"' => {
                // Quoted string element
                const elem = try readQuoted(allocator, src, &i);
                try elems_buf.append(allocator, elem);
                dims_buf.items[depth - 1] += 1;

                // Skip whitespace after element
                while (i < src.len and (src[i] == ' ' or src[i] == '\t' or src[i] == '\n' or src[i] == '\r')) i += 1;

                if (i < src.len and src[i] == '}') {
                    i += 1;
                    depth -= 1;
                } else if (i < src.len and std.mem.startsWith(u8, src[i..], delimiter)) {
                    i += delimiter.len;
                } else {
                    // End of array or error
                    if (depth == 0) break;
                }
            },
            '}' => {
                // End of current dimension
                dims_buf.items[depth - 1] += 1;
                depth -= 1;
                i += 1;
            },
            else => {
                // Non-quoted element (numeric, NULL, or unquoted string)
                const maybe_elem = try readUnquoted(src, &i, delimiter);
                if (maybe_elem) |elem_slice| {
                    // Copy the slice because it points into src which may be freed later
                    const elem = try allocator.dupe(u8, elem_slice);
                    try elems_buf.append(allocator, elem);
                } else {
                    try elems_buf.append(allocator, null);
                }
                dims_buf.items[depth - 1] += 1;

                // Skip whitespace after element
                while (i < src.len and (src[i] == ' ' or src[i] == '\t' or src[i] == '\n' or src[i] == '\r')) i += 1;

                if (i < src.len and src[i] == '}') {
                    i += 1;
                    depth -= 1;
                } else if (i < src.len and std.mem.startsWith(u8, src[i..], delimiter)) {
                    i += delimiter.len;
                } else if (i >= src.len) {
                    break; // End of input
                } else {
                    return error.InvalidArrayFormat;
                }
            },
        }
    }

    // Handle remaining closing braces
    while (i < src.len) {
        if (src[i] == '}') {
            depth -= 1;
            i += 1;
        } else {
            break;
        }
    }

    if (depth != 0) return error.UnclosedArray;

    return .{ .dims = try dims_buf.toOwnedSlice(allocator), .elems = try elems_buf.toOwnedSlice(allocator) };
}

/// Serializes a slice of elements into a PostgreSQL array string.
/// `elem_serializer` is a function that takes an allocator, a buffer, and an element,
/// and writes its quoted/escaped representation to the buffer.
/// Returns a string that must be freed by the caller.
pub fn serializeArray(allocator: std.mem.Allocator, elems: anytype, delimiter: []const u8, elem_serializer: fn (allocator: std.mem.Allocator, buf: *ArrayList(u8), elem: @TypeOf(elems[0])) anyerror!void) ![]u8 {
    var buf = ArrayList(u8).empty;
    defer buf.deinit(allocator);
    try buf.append(allocator, '{');
    if (elems.len > 0) {
        try elem_serializer(allocator, &buf, elems[0]);
        for (elems[1..]) |e| {
            try buf.appendSlice(allocator, delimiter);
            try elem_serializer(allocator, &buf, e);
        }
    }
    try buf.append(allocator, '}');
    return try buf.toOwnedSlice(allocator);
}

/// Quotes and escapes a string for PostgreSQL array format.
/// Returns an allocated string that must be freed.
/// Handles escaping of quotes and backslashes.
fn quoteArrayElement(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf = ArrayList(u8).empty;
    defer buf.deinit(allocator);
    try buf.append(allocator, '"');
    var i: usize = 0;
    while (i < s.len) {
        switch (s[i]) {
            '"' => {
                try buf.appendSlice(allocator, "\\\"");
                i += 1;
            },
            '\\' => {
                try buf.appendSlice(allocator, "\\\\");
                i += 1;
            },
            else => {
                try buf.append(allocator, s[i]);
                i += 1;
            },
        }
    }
    try buf.append(allocator, '"');
    return try buf.toOwnedSlice(allocator);
}

// -----------------------------------------------------------------------------
// BoolArray - PostgreSQL boolean[] type
// -----------------------------------------------------------------------------

pub const BoolArray = struct {
    items: []bool,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) BoolArray {
        return .{ .items = &[_]bool{}, .allocator = allocator };
    }

    pub fn deinit(self: *BoolArray) void {
        self.allocator.free(self.items);
        self.* = undefined;
    }

    pub fn scan(self: *BoolArray, src: ?[]const u8) !void {
        if (src == null) {
            self.items = &[_]bool{};
            return;
        }
        const parsed = try parseArray(self.allocator, src.?, ",");
        defer {
            self.allocator.free(parsed.dims);
            for (parsed.elems) |e| {
                if (e) |elem| self.allocator.free(elem);
            }
            self.allocator.free(parsed.elems);
        }
        var new_items = try self.allocator.alloc(bool, parsed.elems.len);
        for (parsed.elems, 0..) |elem, i| {
            const v = elem orelse return error.NullElementNotAllowed;
            if (v.len != 1) return error.InvalidBoolean;
            new_items[i] = switch (v[0]) {
                't' => true,
                'f' => false,
                else => return error.InvalidBoolean,
            };
        }
        self.allocator.free(self.items);
        self.items = new_items;
    }

    pub fn value(self: BoolArray, allocator: std.mem.Allocator) !?[]u8 {
        if (self.items.len == 0) return @as(?[]u8, try allocator.dupe(u8, "{}"));
        return @as(?[]u8, try serializeArray(allocator, self.items, ",", struct {
            fn ser(alloc: std.mem.Allocator, buf: *ArrayList(u8), v: bool) !void {
                try buf.appendSlice(alloc, if (v) "t" else "f");
            }
        }.ser));
    }
};

// -----------------------------------------------------------------------------
// Float64Array - PostgreSQL double precision[] type
// -----------------------------------------------------------------------------

pub const Float64Array = struct {
    items: []f64,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Float64Array {
        return .{ .items = &[_]f64{}, .allocator = allocator };
    }

    pub fn deinit(self: *Float64Array) void {
        self.allocator.free(self.items);
        self.* = undefined;
    }

    pub fn scan(self: *Float64Array, src: ?[]const u8) !void {
        if (src == null) {
            self.items = &[_]f64{};
            return;
        }
        const parsed = try parseArray(self.allocator, src.?, ",");
        defer {
            self.allocator.free(parsed.dims);
            for (parsed.elems) |e| {
                if (e) |elem| self.allocator.free(elem);
            }
            self.allocator.free(parsed.elems);
        }
        var new_items = try self.allocator.alloc(f64, parsed.elems.len);
        for (parsed.elems, 0..) |elem, i| {
            const v = elem orelse return error.NullElementNotAllowed;
            new_items[i] = try std.fmt.parseFloat(f64, v);
        }
        self.allocator.free(self.items);
        self.items = new_items;
    }

    pub fn value(self: Float64Array, allocator: std.mem.Allocator) !?[]u8 {
        if (self.items.len == 0) return @as(?[]u8, try allocator.dupe(u8, "{}"));
        return @as(?[]u8, try serializeArray(allocator, self.items, ",", struct {
            fn ser(alloc: std.mem.Allocator, buf: *ArrayList(u8), v: f64) !void {
                const str = try std.fmt.allocPrint(alloc, "{d}", .{v});
                defer alloc.free(str);
                try buf.appendSlice(alloc, str);
            }
        }.ser));
    }
};

// -----------------------------------------------------------------------------
// Int64Array - PostgreSQL bigint[] type
// -----------------------------------------------------------------------------

pub const Int64Array = struct {
    items: []i64,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Int64Array {
        return .{ .items = &[_]i64{}, .allocator = allocator };
    }

    pub fn deinit(self: *Int64Array) void {
        self.allocator.free(self.items);
        self.* = undefined;
    }

    pub fn scan(self: *Int64Array, src: ?[]const u8) !void {
        if (src == null) {
            self.items = &[_]i64{};
            return;
        }
        const parsed = try parseArray(self.allocator, src.?, ",");
        defer {
            self.allocator.free(parsed.dims);
            for (parsed.elems) |e| {
                if (e) |elem| self.allocator.free(elem);
            }
            self.allocator.free(parsed.elems);
        }
        var new_items = try self.allocator.alloc(i64, parsed.elems.len);
        for (parsed.elems, 0..) |elem, i| {
            const v = elem orelse return error.NullElementNotAllowed;
            new_items[i] = try std.fmt.parseInt(i64, v, 10);
        }
        self.allocator.free(self.items);
        self.items = new_items;
    }

    pub fn value(self: Int64Array, allocator: std.mem.Allocator) !?[]u8 {
        if (self.items.len == 0) return @as(?[]u8, try allocator.dupe(u8, "{}"));
        return @as(?[]u8, try serializeArray(allocator, self.items, ",", struct {
            fn ser(alloc: std.mem.Allocator, buf: *ArrayList(u8), v: i64) !void {
                const str = try std.fmt.allocPrint(alloc, "{d}", .{v});
                defer alloc.free(str);
                try buf.appendSlice(alloc, str);
            }
        }.ser));
    }
};

// -----------------------------------------------------------------------------
// StringArray - PostgreSQL text[] type
// -----------------------------------------------------------------------------

pub const StringArray = struct {
    items: [][]const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) StringArray {
        return .{ .items = &[_][]const u8{}, .allocator = allocator };
    }

    pub fn deinit(self: *StringArray) void {
        for (self.items) |item| {
            self.allocator.free(item);
        }
        self.allocator.free(self.items);
        self.* = undefined;
    }

    pub fn scan(self: *StringArray, src: ?[]const u8) !void {
        if (src == null) {
            self.items = &[_][]const u8{};
            return;
        }
        const parsed = try parseArray(self.allocator, src.?, ",");
        defer {
            self.allocator.free(parsed.dims);
            // Transfer ownership: parsed.elems strings are now owned by self.items
            self.allocator.free(parsed.elems);
        }
        var new_items = try self.allocator.alloc([]const u8, parsed.elems.len);
        for (parsed.elems, 0..) |elem, i| {
            new_items[i] = elem orelse return error.NullElementNotAllowed;
        }
        // Free old items
        for (self.items) |old| self.allocator.free(old);
        self.allocator.free(self.items);
        self.items = new_items;
    }

    pub fn value(self: StringArray, allocator: std.mem.Allocator) !?[]u8 {
        if (self.items.len == 0) return @as(?[]u8, try allocator.dupe(u8, "{}"));
        return @as(?[]u8, try serializeArray(allocator, self.items, ",", struct {
            fn ser(alloc: std.mem.Allocator, buf: *ArrayList(u8), v: []const u8) !void {
                const quoted = try quoteArrayElement(alloc, v);
                defer alloc.free(quoted);
                try buf.appendSlice(alloc, quoted);
            }
        }.ser));
    }
};

// -----------------------------------------------------------------------------
// ByteaArray - PostgreSQL bytea[] type (hex format)
// -----------------------------------------------------------------------------

pub const ByteaArray = struct {
    items: [][]const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ByteaArray {
        return .{ .items = &[_][]const u8{}, .allocator = allocator };
    }

    pub fn deinit(self: *ByteaArray) void {
        for (self.items) |item| {
            self.allocator.free(item);
        }
        self.allocator.free(self.items);
        self.* = undefined;
    }

    /// Parses PostgreSQL bytea hex format ("\\xDEADBEEF") into raw bytes
    fn parseBytea(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
        if (!std.mem.startsWith(u8, src, "\\x")) return error.InvalidBytea;
        const hex_str = src[2..];
        if (hex_str.len % 2 != 0) return error.InvalidBytea;
        const out = try allocator.alloc(u8, hex_str.len / 2);
        _ = try std.fmt.hexToBytes(out, hex_str);
        return out;
    }

    pub fn scan(self: *ByteaArray, src: ?[]const u8) !void {
        if (src == null) {
            self.items = &[_][]const u8{};
            return;
        }
        const parsed = try parseArray(self.allocator, src.?, ",");
        defer {
            self.allocator.free(parsed.dims);
            for (parsed.elems) |e| {
                if (e) |elem| self.allocator.free(elem);
            }
            self.allocator.free(parsed.elems);
        }
        var new_items = try self.allocator.alloc([]u8, parsed.elems.len);
        for (parsed.elems, 0..) |elem, i| {
            const v = elem orelse return error.NullElementNotAllowed;
            new_items[i] = try parseBytea(self.allocator, v);
        }
        for (self.items) |old| self.allocator.free(old);
        self.allocator.free(self.items);
        self.items = new_items;
    }

    pub fn value(self: ByteaArray, allocator: std.mem.Allocator) !?[]u8 {
        if (self.items.len == 0) return @as(?[]u8, try allocator.dupe(u8, "{}"));
        return @as(?[]u8, try serializeArray(allocator, self.items, ",", struct {
            fn ser(alloc: std.mem.Allocator, buf: *ArrayList(u8), v: []const u8) !void {
                try buf.appendSlice(alloc, "\"\\\\x");
                const hex = std.fmt.bytesToHex(v, .lower);
                try buf.appendSlice(alloc, hex);
                try buf.append(alloc, '"');
            }
        }.ser));
    }
};

// -----------------------------------------------------------------------------
// GenericArray - Generic array for any element type
// -----------------------------------------------------------------------------

/// Generic array that works with any element type that provides serialization/deserialization.
/// Requires custom parser and serializer functions to be passed.
pub fn GenericArray(comptime T: type) type {
    return struct {
        items: []T,
        allocator: std.mem.Allocator,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .items = &[_]T{}, .allocator = allocator };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.items);
            self.* = undefined;
        }

        /// Scans a PostgreSQL array string into the generic array.
        /// `elem_parser` is a function that parses a string into a value of type T.
        pub fn scan(self: *Self, src: ?[]const u8, elem_parser: fn (allocator: std.mem.Allocator, str: []const u8) anyerror!T) !void {
            if (src == null) {
                self.items = &[_]T{};
                return;
            }
            const parsed = try parseArray(self.allocator, src.?, ",");
            defer {
                self.allocator.free(parsed.dims);
                for (parsed.elems) |e| {
                    if (e) |elem| self.allocator.free(elem);
                }
                self.allocator.free(parsed.elems);
            }
            var new_items = try self.allocator.alloc(T, parsed.elems.len);
            for (parsed.elems, 0..) |elem, i| {
                const str = elem orelse return error.NullElementNotAllowed;
                new_items[i] = try elem_parser(self.allocator, str);
            }
            self.allocator.free(self.items);
            self.items = new_items;
        }

        /// Serializes the array to PostgreSQL text format.
        /// `elem_serializer` is a function that writes a value of type T to a buffer.
        pub fn value(self: Self, allocator: std.mem.Allocator, elem_serializer: fn (allocator: std.mem.Allocator, buf: *ArrayList(u8), elem: T) anyerror!void) !?[]u8 {
            if (self.items.len == 0) return @as(?[]u8, try allocator.dupe(u8, "{}"));
            return @as(?[]u8, try serializeArray(allocator, self.items, ",", elem_serializer));
        }
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

test "parseArray simple" {
    const alloc = testing.allocator;
    const src = "{1,2,3}";
    const parsed = try parseArray(alloc, src, ",");
    defer {
        alloc.free(parsed.dims);
        for (parsed.elems) |e| if (e) |elem| alloc.free(elem);
        alloc.free(parsed.elems);
    }
    try testing.expectEqual(parsed.elems.len, 3);
    try testing.expectEqualStrings("1", parsed.elems[0].?);
    try testing.expectEqualStrings("2", parsed.elems[1].?);
    try testing.expectEqualStrings("3", parsed.elems[2].?);
}

test "parseArray with quotes" {
    const alloc = testing.allocator;
    const src = "{\"hello\",\"world\"}";
    const parsed = try parseArray(alloc, src, ",");
    defer {
        alloc.free(parsed.dims);
        for (parsed.elems) |e| if (e) |elem| alloc.free(elem);
        alloc.free(parsed.elems);
    }
    try testing.expectEqual(parsed.elems.len, 2);
    try testing.expectEqualStrings("hello", parsed.elems[0].?);
    try testing.expectEqualStrings("world", parsed.elems[1].?);
}

test "parseArray NULL" {
    const alloc = testing.allocator;
    const src = "{1,NULL,3}";
    const parsed = try parseArray(alloc, src, ",");
    defer {
        alloc.free(parsed.dims);
        for (parsed.elems) |e| if (e) |elem| alloc.free(elem);
        alloc.free(parsed.elems);
    }
    try testing.expectEqual(parsed.elems.len, 3);
    try testing.expectEqualStrings("1", parsed.elems[0].?);
    try testing.expect(parsed.elems[1] == null);
    try testing.expectEqualStrings("3", parsed.elems[2].?);
}

test "BoolArray scan and value" {
    const alloc = testing.allocator;
    var arr = BoolArray.init(alloc);
    defer arr.deinit();

    try arr.scan("{t,f,t}");
    try testing.expectEqual(arr.items.len, 3);
    try testing.expect(arr.items[0] == true);
    try testing.expect(arr.items[1] == false);
    try testing.expect(arr.items[2] == true);

    const val = try arr.value(alloc);
    defer if (val) |v| alloc.free(v);
    try testing.expect(val != null);
    try testing.expectEqualStrings("{t,f,t}", val.?);
}

test "Int64Array scan and value" {
    const alloc = testing.allocator;
    var arr = Int64Array.init(alloc);
    defer arr.deinit();

    try arr.scan("{1,-2,3}");
    try testing.expectEqual(arr.items.len, 3);
    try testing.expectEqual(arr.items[0], 1);
    try testing.expectEqual(arr.items[1], -2);
    try testing.expectEqual(arr.items[2], 3);

    const val = try arr.value(alloc);
    defer if (val) |v| alloc.free(v);
    try testing.expectEqualStrings("{1,-2,3}", val.?);
}

test "StringArray scan and value" {
    const alloc = testing.allocator;
    var arr = StringArray.init(alloc);
    defer arr.deinit();

    try arr.scan("{\"hello\",\"world\"}");
    try testing.expectEqual(arr.items.len, 2);
    try testing.expectEqualStrings("hello", arr.items[0]);
    try testing.expectEqualStrings("world", arr.items[1]);

    const val = try arr.value(alloc);
    defer if (val) |v| alloc.free(v);
    try testing.expectEqualStrings("{\"hello\",\"world\"}", val.?);
}
