//! PostgreSQL data type encoding and decoding.
//! Supports text and binary formats for common types:
//! - int2, int4, int8
//! - float4, float8
//! - bool
//! - text, varchar, char
//! - bytea (hex and escape formats)
//! - timestamp, timestamptz, date, time, timetz
//! - uuid (binary only)
//!
//! Dependencies: oid.zig

const std = @import("std");
const oid = @import("oid.zig");
const ArrayList = std.ArrayList;

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

/// Format of a value (text or binary)
pub const Format = enum(i16) {
    text = 0,
    binary = 1,
};

/// Server parameter status (version, timezone, etc.)
pub const ParameterStatus = struct {
    serverVersion: i32 = 0,
    timezoneOffset: i32 = 0, // offset in seconds from UTC
};

// Infinity timestamp support (nanoseconds since Unix epoch)
var infinityTsEnabled: bool = false;
var infinityTsNegative: i128 = undefined;
var infinityTsPositive: i128 = undefined;

/// Enable infinity timestamp handling. Must be called before any connection uses timestamps.
pub fn enableInfinityTs(negative: i128, positive: i128) !void {
    if (infinityTsEnabled) return error.InfinityAlreadyEnabled;
    if (negative >= positive) return error.InfinityOrder;
    infinityTsEnabled = true;
    infinityTsNegative = negative;
    infinityTsPositive = positive;
}

/// Disable infinity timestamp handling.
pub fn disableInfinityTs() void {
    infinityTsEnabled = false;
}

// -----------------------------------------------------------------------------
// Public encoding/decoding functions
// -----------------------------------------------------------------------------

/// Binary encode a value for a parameter (uses binaryEncode internally).
pub fn binaryEncode(allocator: std.mem.Allocator, ps: *const ParameterStatus, value: anytype) ![]u8 {
    const T = @TypeOf(value);
    switch (T) {
        []u8 => return try allocator.dupe(u8, value),
        else => return encode(allocator, ps, value, oid.T_unknown),
    }
}

/// General encode: returns a byte slice that must be freed by caller.
/// The returned slice is allocated with the given allocator.
pub fn encode(allocator: std.mem.Allocator, ps: *const ParameterStatus, value: anytype, pgtypOid: oid.Oid) ![]u8 {
    const T = @TypeOf(value);
    switch (T) {
        i64 => return try std.fmt.allocPrint(allocator, "{d}", .{value}),
        i32 => return try std.fmt.allocPrint(allocator, "{d}", .{value}),
        i16 => return try std.fmt.allocPrint(allocator, "{d}", .{value}),
        f64 => return try std.fmt.allocPrint(allocator, "{d}", .{value}),
        f32 => return try std.fmt.allocPrint(allocator, "{d}", .{value}),
        i128 => return try formatTimestamp(allocator, value),
        []u8 => {
            if (pgtypOid == oid.T_bytea) {
                return try encodeBytea(allocator, ps.serverVersion, value);
            }
            return try allocator.dupe(u8, value);
        },
        []const u8 => {
            if (pgtypOid == oid.T_bytea) {
                return try encodeBytea(allocator, ps.serverVersion, value);
            }
            return try allocator.dupe(u8, value);
        },
        bool => return try std.fmt.allocPrint(allocator, "{s}", .{if (value) "t" else "f"}),
        else => @compileError("encode: unsupported type " ++ @typeName(T)),
    }
}

/// Decode a value from a byte slice according to format and OID.
/// The returned value is a tagged union; caller must handle each type.
pub fn decode(allocator: std.mem.Allocator, ps: *const ParameterStatus, data: []const u8, typ: oid.Oid, fmt: Format) !DecodedValue {
    return switch (fmt) {
        .binary => try binaryDecode(allocator, ps, data, typ),
        .text => try textDecode(allocator, ps, data, typ),
    };
}

/// DecodedValue is a tagged union representing all possible decoded types.
pub const DecodedValue = union(enum) {
    int: i64,
    float: f64,
    bool: bool,
    string: []const u8, // owned by the caller (allocated)
    bytes: []u8, // owned by caller
    timestamp: i128, // nanoseconds since Unix epoch
    null,
    infinity: enum { negative, positive },

    pub fn deinit(self: DecodedValue, allocator: std.mem.Allocator) void {
        switch (self) {
            .string => |s| allocator.free(s),
            .bytes => |b| allocator.free(b),
            else => {},
        }
    }
};

// -----------------------------------------------------------------------------
// Binary decode
// -----------------------------------------------------------------------------

fn binaryDecode(allocator: std.mem.Allocator, ps: *const ParameterStatus, data: []const u8, typ: oid.Oid) !DecodedValue {
    _ = ps;
    switch (typ) {
        oid.T_bytea => return .{ .bytes = try allocator.dupe(u8, data) },
        oid.T_int8 => {
            if (data.len != 8) return error.InvalidBinaryLength;
            const bytes = data[0..8];
            const n = std.mem.readInt(i64, &[_]u8{
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            }, .big);
            return .{ .int = n };
        },
        oid.T_int4 => {
            if (data.len != 4) return error.InvalidBinaryLength;
            const bytes = data[0..4];
            const n = std.mem.readInt(i32, &[_]u8{ bytes[0], bytes[1], bytes[2], bytes[3] }, .big);
            return .{ .int = n };
        },
        oid.T_int2 => {
            if (data.len != 2) return error.InvalidBinaryLength;
            const bytes = data[0..2];
            const n = std.mem.readInt(i16, &[_]u8{ bytes[0], bytes[1] }, .big);
            return .{ .int = n };
        },
        oid.T_uuid => {
            const uuid_str = try decodeUUIDBinary(allocator, data);
            return .{ .string = uuid_str };
        },
        else => return error.UnsupportedBinaryType,
    }
}

/// Decode a UUID from binary format (16 bytes) into a hyphenated string.
fn decodeUUIDBinary(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    if (data.len != 16) return error.InvalidUUID;
    var out = try allocator.alloc(u8, 36);
    const hex = "0123456789abcdef";
    var src_idx: usize = 0;
    var dst_idx: usize = 0;
    while (src_idx < 16) : (src_idx += 1) {
        if (src_idx == 4 or src_idx == 6 or src_idx == 8 or src_idx == 10) {
            out[dst_idx] = '-';
            dst_idx += 1;
        }
        const b = data[src_idx];
        out[dst_idx] = hex[(b >> 4) & 0x0F];
        out[dst_idx + 1] = hex[b & 0x0F];
        dst_idx += 2;
    }
    return out;
}

// -----------------------------------------------------------------------------
// Text decode
// -----------------------------------------------------------------------------

fn textDecode(allocator: std.mem.Allocator, ps: *const ParameterStatus, data: []const u8, typ: oid.Oid) !DecodedValue {
    const s = data;
    switch (typ) {
        oid.T_char, oid.T_varchar, oid.T_text => return .{ .string = try allocator.dupe(u8, s) },
        oid.T_bytea => {
            const b = try parseBytea(allocator, s);
            return .{ .bytes = b };
        },
        oid.T_timestamptz => {
            const offset = if (ps.timezoneOffset != 0) ps.timezoneOffset else null;
            const ts = try parseTimestamp(allocator, offset, s);
            return .{ .timestamp = ts };
        },
        oid.T_timestamp, oid.T_date => {
            const ts = try parseTimestamp(allocator, null, s);
            return .{ .timestamp = ts };
        },
        oid.T_time => {
            const t = try mustParseTime(allocator, s, false);
            return .{ .timestamp = t };
        },
        oid.T_timetz => {
            const t = try mustParseTime(allocator, s, true);
            return .{ .timestamp = t };
        },
        oid.T_bool => {
            if (s.len == 0) return error.InvalidBool;
            return .{ .bool = s[0] == 't' };
        },
        oid.T_int8, oid.T_int4, oid.T_int2 => {
            const i = try std.fmt.parseInt(i64, s, 10);
            return .{ .int = i };
        },
        oid.T_float4, oid.T_float8 => {
            const f = try std.fmt.parseFloat(f64, s);
            return .{ .float = f };
        },
        oid.T_uuid => {
            return .{ .string = try allocator.dupe(u8, s) };
        },
        else => return .{ .string = try allocator.dupe(u8, s) },
    }
}

/// Parse a time string (HH:MM:SS) into a nanosecond timestamp (nanoseconds since midnight).
fn mustParseTime(allocator: std.mem.Allocator, s: []const u8, has_tz: bool) !i128 {
    _ = has_tz;
    const full_str = try std.fmt.allocPrint(allocator, "1970-01-01 {s}", .{s});
    defer allocator.free(full_str);
    const ts = try parseTimestamp(allocator, null, full_str);
    return @mod(ts, std.time.ns_per_day);
}

// -----------------------------------------------------------------------------
// Timestamp parsing (Postgres ISO, MDY style)
// -----------------------------------------------------------------------------

/// Convert a Gregorian date to days since Unix epoch (1970-01-01).
fn daysSinceEpoch(year: i32, month: u4, day: u5) i64 {
    const adjusted_year = if (year <= 0) year + 1 else year;

    const a = @divFloor(14 - @as(i32, month), 12);
    const y = adjusted_year + 4800 - a;
    const m = @as(i32, month) + 12 * a - 3;
    const jdn = @as(i64, day) +
        @divFloor(153 * m + 2, 5) +
        365 * y +
        @divFloor(y, 4) - @divFloor(y, 100) + @divFloor(y, 400) -
        32045;
    const unix_epoch_jdn = 2440588;
    return jdn - unix_epoch_jdn;
}

/// Parse a PostgreSQL timestamp string into a Unix timestamp in nanoseconds (i128).
/// Supports ISO format: YYYY-MM-DD HH:MM:SS.SSS[+/-HH:MM:SS] and BC/AD suffixes.
/// Also handles 24:00 time (rolls to next day).
pub fn parseTimestamp(allocator: std.mem.Allocator, timezoneOffset: ?i32, str: []const u8) !i128 {
    var input = std.mem.trim(u8, str, " \t\r\n");

    // Handle infinity
    if (std.mem.eql(u8, input, "-infinity")) {
        if (infinityTsEnabled) return infinityTsNegative;
        return error.InfinityNotEnabled;
    }
    if (std.mem.eql(u8, input, "infinity")) {
        if (infinityTsEnabled) return infinityTsPositive;
        return error.InfinityNotEnabled;
    }

    // Handle 24:00 time by replacing "24:00" with "00:00" and adjusting later
    var is2400Time = false;
    var owned_input: []u8 = undefined;
    if (std.mem.indexOf(u8, input, "24:00")) |idx| {
        is2400Time = true;
        var new_input = ArrayList(u8).empty;
        defer new_input.deinit(allocator);
        try new_input.appendSlice(allocator, input[0..idx]);
        try new_input.appendSlice(allocator, "00:00");
        if (idx + 5 < input.len) {
            try new_input.appendSlice(allocator, input[idx + 5 ..]);
        }
        owned_input = try new_input.toOwnedSlice(allocator);
        input = owned_input;
    }
    defer if (is2400Time) allocator.free(owned_input);

    var isBC = false;
    if (input.len >= 3 and std.mem.eql(u8, input[input.len - 3 ..], " BC")) {
        isBC = true;
        input = input[0 .. input.len - 3];
        input = std.mem.trim(u8, input, " \t");
    }

    // Parse YYYY-MM-DD
    var pos: usize = 0;
    const year = try parseNumber(input, &pos, 4);
    try expectChar(input, &pos, '-');
    const month = try parseNumber(input, &pos, 2);
    try expectChar(input, &pos, '-');
    const day = try parseNumber(input, &pos, 2);

    // Optional time part
    var hour: i32 = 0;
    var minute: i32 = 0;
    var second: i32 = 0;
    var nano: i32 = 0;
    var tzOffset: i32 = 0;

    if (pos < input.len and (input[pos] == ' ' or input[pos] == 'T')) {
        if (input[pos] == ' ' or input[pos] == 'T') pos += 1;
        hour = try parseNumber(input, &pos, 2);
        try expectChar(input, &pos, ':');
        minute = try parseNumber(input, &pos, 2);
        try expectChar(input, &pos, ':');
        second = try parseNumber(input, &pos, 2);

        // Fractional seconds
        if (pos < input.len and input[pos] == '.') {
            pos += 1;
            const frac_start = pos;
            while (pos < input.len and std.ascii.isDigit(input[pos])) pos += 1;
            const frac_str = input[frac_start..pos];
            if (frac_str.len > 0) {
                const frac_val = try std.fmt.parseInt(i32, frac_str, 10);
                const scale = std.math.pow(i32, 10, 9 - @as(i32, @intCast(frac_str.len)));
                nano = frac_val * scale;
            }
        }

        // Timezone offset
        if (pos < input.len and (input[pos] == '+' or input[pos] == '-')) {
            const sign: i32 = if (input[pos] == '-') -1 else 1;
            pos += 1;
            const tz_hour = try parseNumber(input, &pos, 2);
            var tz_min: i32 = 0;
            var tz_sec: i32 = 0;
            if (pos < input.len and input[pos] == ':') {
                pos += 1;
                tz_min = try parseNumber(input, &pos, 2);
                if (pos < input.len and input[pos] == ':') {
                    pos += 1;
                    tz_sec = try parseNumber(input, &pos, 2);
                }
            }
            tzOffset = sign * (tz_hour * 3600 + tz_min * 60 + tz_sec);
        }
    }

    // Basic range checks
    if (year < 1 or month < 1 or month > 12 or day < 1 or day > 31) return error.InvalidTimestamp;
    if (hour < 0 or hour > 23 or minute < 0 or minute > 59 or second < 0 or second > 60) return error.InvalidTimestamp;

    const abs_year = if (isBC) 1 - year else year;
    const days = daysSinceEpoch(abs_year, @intCast(month), @intCast(day));
    const day_seconds = @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
    var utc_seconds = days * 86400 + day_seconds;
    if (is2400Time) {
        // Add 24 hours (86400 seconds) because we replaced 24:00 with 00:00
        utc_seconds += 86400;
    }
    var total_nanos = @as(i128, utc_seconds) * std.time.ns_per_s + nano;

    // Apply timezone offset if present
    if (tzOffset != 0) {
        total_nanos -= @as(i128, tzOffset) * std.time.ns_per_s;
    }
    if (timezoneOffset) |tz_off| {
        if (tzOffset == 0) {
            total_nanos -= @as(i128, tz_off) * std.time.ns_per_s;
        }
    }
    return total_nanos;
}

// Helper: parse a fixed-width number from the string
fn parseNumber(s: []const u8, pos: *usize, max_digits: usize) !i32 {
    const start = pos.*;
    while (pos.* < s.len and pos.* - start < max_digits and std.ascii.isDigit(s[pos.*])) {
        pos.* += 1;
    }
    if (pos.* == start) return error.InvalidTimestamp;
    return std.fmt.parseInt(i32, s[start..pos.*], 10);
}

// Helper: expect a specific character at current position
fn expectChar(s: []const u8, pos: *usize, expected: u8) !void {
    if (pos.* >= s.len or s[pos.*] != expected) return error.InvalidTimestamp;
    pos.* += 1;
}

/// Format a timestamp as a PostgreSQL text string (UTC, with +00 timezone).
pub fn formatTimestamp(allocator: std.mem.Allocator, timestamp_ns: i128) ![]u8 {
    if (infinityTsEnabled) {
        if (timestamp_ns <= infinityTsNegative) {
            return allocator.dupe(u8, "-infinity");
        }
        if (timestamp_ns >= infinityTsPositive) {
            return allocator.dupe(u8, "infinity");
        }
    }

    const seconds = @divFloor(timestamp_ns, std.time.ns_per_s);
    const nanos = @as(u32, @intCast(@mod(timestamp_ns, std.time.ns_per_s)));

    const epoch_secs = std.time.epoch.EpochSeconds{ .secs = @as(u64, @intCast(seconds)) };
    const epoch_day = epoch_secs.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const year = year_day.year;
    const month = @intFromEnum(month_day.month);
    const day = month_day.day_index + 1;
    const day_seconds = epoch_secs.getDaySeconds();
    const hour = day_seconds.getHoursIntoDay();
    const minute = day_seconds.getMinutesIntoHour();
    const second = day_seconds.getSecondsIntoMinute();

    var buf = ArrayList(u8).empty;
    defer buf.deinit(allocator);

    const date_part = try std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        year, month, day, hour, minute, second,
    });
    defer allocator.free(date_part);
    try buf.appendSlice(allocator, date_part);

    if (nanos != 0) {
        const frac = @divFloor(nanos, 1000);
        if (frac != 0) {
            const frac_str = try std.fmt.allocPrint(allocator, ".{d:0>6}", .{frac});
            defer allocator.free(frac_str);
            try buf.appendSlice(allocator, frac_str);
        }
    }

    try buf.appendSlice(allocator, "+00");

    return try buf.toOwnedSlice(allocator);
}

// -----------------------------------------------------------------------------
// Bytea encoding/decoding
// -----------------------------------------------------------------------------

/// Parse a bytea from text representation (hex or escape).
pub fn parseBytea(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    if (s.len >= 2 and std.mem.eql(u8, s[0..2], "\\x")) {
        // hex format
        const hex = s[2..];
        if (hex.len % 2 != 0) return error.InvalidBytea;
        const out_len = hex.len / 2;
        const out = try allocator.alloc(u8, out_len);
        for (0..out_len) |i| {
            const high = try charToNibble(hex[2 * i]);
            const low = try charToNibble(hex[2 * i + 1]);
            out[i] = (high << 4) | low;
        }
        return out;
    } else {
        // escape format
        var out = ArrayList(u8).empty;
        defer out.deinit(allocator);
        var i: usize = 0;
        while (i < s.len) {
            if (s[i] == '\\') {
                i += 1;
                if (i >= s.len) return error.InvalidBytea;
                if (s[i] == '\\') {
                    try out.append(allocator, '\\');
                    i += 1;
                } else if (i + 3 <= s.len and std.ascii.isDigit(s[i]) and std.ascii.isDigit(s[i + 1]) and std.ascii.isDigit(s[i + 2])) {
                    const oct = try std.fmt.parseInt(u8, s[i .. i + 3], 8);
                    try out.append(allocator, oct);
                    i += 3;
                } else {
                    return error.InvalidBytea;
                }
            } else {
                try out.append(allocator, s[i]);
                i += 1;
            }
        }
        return try out.toOwnedSlice(allocator);
    }
}

/// Convert a hex character to its nibble value.
fn charToNibble(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidHex,
    };
}

/// Encode bytea to text format, using hex if server version >= 9.0.
pub fn encodeBytea(allocator: std.mem.Allocator, serverVersion: i32, v: []const u8) ![]u8 {
    if (serverVersion >= 90000) {
        // hex format: \x + hex
        const hex_len = 2 + v.len * 2;
        var out = try allocator.alloc(u8, hex_len);
        out[0] = '\\';
        out[1] = 'x';
        const hex = "0123456789abcdef";
        for (v, 0..) |b, i| {
            out[2 + i * 2] = hex[(b >> 4) & 0x0F];
            out[2 + i * 2 + 1] = hex[b & 0x0F];
        }
        return out;
    } else {
        // escape format
        var out = ArrayList(u8).empty;
        defer out.deinit(allocator);
        for (v) |b| {
            if (b == '\\') {
                try out.appendSlice(allocator, "\\\\");
            } else if (b < 0x20 or b > 0x7e) {
                const oct_str = try std.fmt.allocPrint(allocator, "\\{o:0>3}", .{b});
                defer allocator.free(oct_str);
                try out.appendSlice(allocator, oct_str);
            } else {
                try out.append(allocator, b);
            }
        }
        return try out.toOwnedSlice(allocator);
    }
}

// -----------------------------------------------------------------------------
// Append text encoding (for COPY)
// -----------------------------------------------------------------------------

/// Append text-encoded value to a buffer (allocates internally).
/// The buffer is assumed to be an ArrayList(u8) that already has capacity.
pub fn appendEncodedText(ps: *const ParameterStatus, buf: *ArrayList(u8), value: anytype) !void {
    const alloc = buf.allocator;
    const T = @TypeOf(value);

    switch (T) {
        i64, i32, i16 => {
            const str = try std.fmt.allocPrint(alloc, "{d}", .{value});
            defer alloc.free(str);
            try buf.appendSlice(alloc, str);
        },
        f64, f32 => {
            const str = try std.fmt.allocPrint(alloc, "{d}", .{value});
            defer alloc.free(str);
            try buf.appendSlice(alloc, str);
        },
        i128 => {
            const ts_str = try formatTimestamp(alloc, value);
            defer alloc.free(ts_str);
            try buf.appendSlice(alloc, ts_str);
        },
        []u8, []const u8 => {
            const bytes = if (T == []u8) value else value;
            const encoded = try encodeBytea(alloc, ps.serverVersion, bytes);
            defer alloc.free(encoded);
            try appendEscapedText(buf, encoded);
        },
        bool => {
            const str = if (value) "t" else "f";
            try buf.appendSlice(alloc, str);
        },
        ?void => try buf.appendSlice(alloc, "\\N"),
        else => {
            if (@typeInfo(T) == .optional) {
                if (value) |v| {
                    try appendEncodedText(ps, buf, v);
                } else {
                    try buf.appendSlice(alloc, "\\N");
                }
            } else {
                @compileError("appendEncodedText: unsupported type " ++ @typeName(T));
            }
        },
    }
}

/// Append escaped text (for COPY text format) to buffer.
/// Escapes backslashes, newlines, carriage returns, and tabs.
pub fn appendEscapedText(buf: *ArrayList(u8), text: []const u8) !void {
    var need_escape = false;
    for (text) |c| {
        if (c == '\\' or c == '\n' or c == '\r' or c == '\t') {
            need_escape = true;
            break;
        }
    }
    if (!need_escape) {
        try buf.appendSlice(buf.allocator, text);
        return;
    }
    for (text) |c| {
        switch (c) {
            '\\' => try buf.appendSlice(buf.allocator, "\\\\"),
            '\n' => try buf.appendSlice(buf.allocator, "\\n"),
            '\r' => try buf.appendSlice(buf.allocator, "\\r"),
            '\t' => try buf.appendSlice(buf.allocator, "\\t"),
            else => try buf.append(buf.allocator, c),
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

test "encode int64 text" {
    const alloc = testing.allocator;
    const ps = ParameterStatus{};
    const encoded = try encode(alloc, &ps, @as(i64, 12345), oid.T_int8);
    defer alloc.free(encoded);
    try testing.expectEqualStrings("12345", encoded);
}

test "decode int64 text" {
    const alloc = testing.allocator;
    const ps = ParameterStatus{};
    const dec = try textDecode(alloc, &ps, "12345", oid.T_int8);
    defer dec.deinit(alloc);
    try testing.expect(dec == .int);
    try testing.expectEqual(@as(i64, 12345), dec.int);
}

test "bytea hex encode/decode" {
    const alloc = testing.allocator;
    const ps = ParameterStatus{ .serverVersion = 90000 };
    const input = &[_]u8{ 0x00, 0x01, 0x02, 0xFF };
    const encoded = try encodeBytea(alloc, ps.serverVersion, input);
    defer alloc.free(encoded);
    try testing.expectEqualStrings("\\x000102ff", encoded);
    const decoded = try parseBytea(alloc, encoded);
    defer alloc.free(decoded);
    try testing.expectEqualSlices(u8, input, decoded);
}

test "timestamp parse" {
    const alloc = testing.allocator;
    const ts = try parseTimestamp(alloc, null, "2024-01-15 12:30:45");
    try testing.expect(ts > 0);
}

test "uuid binary decode" {
    const alloc = testing.allocator;
    const uuid_bytes = &[_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
    const uuid_str = try decodeUUIDBinary(alloc, uuid_bytes);
    defer alloc.free(uuid_str);
    try testing.expectEqualStrings("12345678-9abc-def0-1234-56789abcdef0", uuid_str);
}
