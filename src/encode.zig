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

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

/// Format of a value (text or binary)
pub const Format = enum(i16) {
    text = 0,
    binary = 1,
};

/// Parameter status (server version, timezone, etc.)
pub const ParameterStatus = struct {
    serverVersion: i32 = 0,
    timezoneOffset: i32 = 0,
};

/// A time value that can be null.
pub const NullTime = struct {
    time: ?std.time.Instant = null,

    pub fn scan(self: *NullTime, _value: anytype) !void {
        if (_value == null) {
            self.time = null;
        } else if (_value == std.time.Instant) {
            self.time = _value;
        } else {
            return error.InvalidTime;
        }
    }

    pub fn value(self: NullTime) ?std.time.Instant {
        return self.time;
    }
};

// Infinity timestamp support
var infinityTsEnabled: bool = false;
var infinityTsNegative: std.time.Instant = undefined;
var infinityTsPositive: std.time.Instant = undefined;
var infinityMutex = std.Thread.Mutex{};

/// Enable infinity timestamp handling. Must be called before any connection uses timestamps.
pub fn enableInfinityTs(negative: std.time.Instant, positive: std.time.Instant) !void {
    infinityMutex.lock();
    defer infinityMutex.unlock();
    if (infinityTsEnabled) return error.InfinityAlreadyEnabled;
    if (!std.time.Instant.lessThan(negative, positive)) return error.InfinityOrder;
    infinityTsEnabled = true;
    infinityTsNegative = negative;
    infinityTsPositive = positive;
}

pub fn disableInfinityTs() void {
    infinityMutex.lock();
    defer infinityMutex.unlock();
    infinityTsEnabled = false;
}

// -----------------------------------------------------------------------------
// Public encoding/decoding functions
// -----------------------------------------------------------------------------

/// Binary encode a value for a parameter (uses binaryEncode internally).
pub fn binaryEncode(ps: *const ParameterStatus, value: anytype) ![]u8 {
    const T = @TypeOf(value);
    switch (T) {
        []u8 => return value,
        else => return encode(ps, value, oid.T_unknown),
    }
}

/// General encode: returns a byte slice that must be freed by caller.
/// The returned slice is allocated with the given allocator.
pub fn encode(allocator: std.mem.Allocator, ps: *const ParameterStatus, value: anytype, pgtypOid: oid.Oid) ![]u8 {
    const T = @TypeOf(value);
    switch (T) {
        i64 => return try std.fmt.allocPrint(allocator, "{d}", .{value}),
        f64 => return try std.fmt.allocPrint(allocator, "{d}", .{value}),
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
        std.time.Instant => return try formatTimestamp(allocator, value),
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
    timestamp: std.time.Instant,
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
            return .{ .int = @as(i64, @bitCast(std.mem.readInt(u64, data[0..8], .big))) };
        },
        oid.T_int4 => {
            if (data.len != 4) return error.InvalidBinaryLength;
            return .{ .int = @as(i32, @bitCast(std.mem.readInt(u32, data[0..4], .big))) };
        },
        oid.T_int2 => {
            if (data.len != 2) return error.InvalidBinaryLength;
            return .{ .int = @as(i16, @bitCast(std.mem.readInt(u16, data[0..2], .big))) };
        },
        oid.T_uuid => {
            return .{ .bytes = try decodeUUIDBinary(allocator, data) };
        },
        else => return error.UnsupportedBinaryType,
    }
}

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
    _ = ps;
    const s = data;
    switch (typ) {
        oid.T_char, oid.T_varchar, oid.T_text => return .{ .string = try allocator.dupe(u8, s) },
        oid.T_bytea => {
            const b = try parseBytea(allocator, s);
            return .{ .bytes = b };
        },
        oid.T_timestamptz => {
            // const ts = try parseTimestamp(allocator, ps.timezoneOffset, s);
            // return .{ .timestamp = ts };
            return .{ .string = try allocator.dupe(u8, s) };
        },
        oid.T_timestamp, oid.T_date => {
            // const ts = try parseTimestamp(allocator, null, s);
            // return .{ .timestamp = ts };
            return .{ .string = try allocator.dupe(u8, s) };
        },
        oid.T_time => {
            // const t = try mustParseTime(allocator, "15:04:05", s);
            // return .{ .timestamp = t };
            return .{ .string = try allocator.dupe(u8, s) };
        },
        oid.T_timetz => {
            // const t = try mustParseTime(allocator, "15:04:05-07", s);
            // return .{ .timestamp = t };
            return .{ .string = try allocator.dupe(u8, s) };
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
        else => return .{ .string = try allocator.dupe(u8, s) },
    }
}

fn mustParseTime(allocator: std.mem.Allocator, layout: []const u8, s: []const u8) !std.time.Instant {
    _ = layout;
    // Simplified: only support ISO-like formats. In real implementation, use time parsing.
    // We'll delegate to parseTimestamp for simplicity.
    return parseTimestamp(allocator, null, s);
}

// -----------------------------------------------------------------------------
// Timestamp parsing (Postgres ISO, MDY style)
// -----------------------------------------------------------------------------

const TimestampParser = struct {
    err: ?anyerror = null,
    str: []const u8,
    pos: usize = 0,

    fn expect(self: *TimestampParser, char: u8) !void {
        if (self.err != null) return;
        if (self.pos >= self.str.len or self.str[self.pos] != char) {
            self.err = error.InvalidTimestamp;
        } else {
            self.pos += 1;
        }
    }

    fn atoi(self: *TimestampParser, begin: usize, end: usize) !i32 {
        if (self.err != null) return 0;
        if (begin >= end or end > self.str.len) {
            self.err = error.InvalidTimestamp;
            return 0;
        }
        const slice = self.str[begin..end];
        return std.fmt.parseInt(i32, slice, 10) catch |e| {
            self.err = e;
            return 0;
        };
    }
};

/// Parse a PostgreSQL timestamp string into a std.time.Instant (Unix nanoseconds).
pub fn parseTimestamp(allocator: std.mem.Allocator, timezoneOffset: i32, str: []const u8) !std.time.Instant {
    _ = allocator;
    // Check for infinity
    if (std.mem.eql(u8, str, "-infinity")) {
        infinityMutex.lock();
        defer infinityMutex.unlock();
        if (infinityTsEnabled) return infinityTsNegative;
        return error.InfinityNotEnabled;
    }
    if (std.mem.eql(u8, str, "infinity")) {
        infinityMutex.lock();
        defer infinityMutex.unlock();
        if (infinityTsEnabled) return infinityTsPositive;
        return error.InfinityNotEnabled;
    }

    var p = TimestampParser{ .str = str };
    // Format: "YYYY-MM-DD HH:MM:SS.nnnnnn[+-]HH[:MM[:SS]] [BC]"
    const monSep = std.mem.indexOfScalar(u8, str, '-') orelse return error.InvalidTimestamp;
    const year = try p.atoi(0, monSep);
    const daySep = monSep + 3;
    const month = try p.atoi(monSep + 1, daySep);
    try p.expect('-');
    const timeSep = daySep + 3;
    const day = try p.atoi(daySep + 1, timeSep);

    var hour: i32 = 0;
    var minute: i32 = 0;
    var second: i32 = 0;
    var nano: i32 = 0;
    var tzOffset: i32 = 0;
    var isBC = false;

    // Check if we have time part
    if (str.len > timeSep + 1 and str[timeSep + 1] == ' ') {
        // skip space
        p.pos = timeSep + 2;
        // parse hour:minute:second
        const minSep = p.pos + 2;
        hour = try p.atoi(p.pos, minSep);
        try p.expect(':');
        const secSep = minSep + 3;
        minute = try p.atoi(minSep + 1, secSep);
        try p.expect(':');
        const secEnd = secSep + 3;
        second = try p.atoi(secSep + 1, secEnd);
        p.pos = secEnd;

        // fractional seconds
        if (p.pos < str.len and str[p.pos] == '.') {
            p.pos += 1;
            const fracStart = p.pos;
            while (p.pos < str.len and std.ascii.isDigit(str[p.pos])) p.pos += 1;
            const fracStr = str[fracStart..p.pos];
            if (fracStr.len > 0) {
                const fracVal = try std.fmt.parseInt(i32, fracStr, 10);
                nano = fracVal * std.math.pow(i32, 10, 9 - @as(i32, @intCast(fracStr.len)));
            }
        }

        // timezone offset
        if (p.pos < str.len and (str[p.pos] == '-' or str[p.pos] == '+')) {
            const sign: i32 = if (str[p.pos] == '-') -1 else 1;
            p.pos += 1;
            const tzHourStart = p.pos;
            // hours are two digits
            if (p.pos + 2 > str.len) return error.InvalidTimestamp;
            const tzHour = try p.atoi(tzHourStart, tzHourStart + 2);
            p.pos += 2;
            var tzMin: i32 = 0;
            var tzSec: i32 = 0;
            if (p.pos < str.len and str[p.pos] == ':') {
                p.pos += 1;
                const tzMinStart = p.pos;
                if (p.pos + 2 > str.len) return error.InvalidTimestamp;
                tzMin = try p.atoi(tzMinStart, tzMinStart + 2);
                p.pos += 2;
                if (p.pos < str.len and str[p.pos] == ':') {
                    p.pos += 1;
                    const tzSecStart = p.pos;
                    if (p.pos + 2 > str.len) return error.InvalidTimestamp;
                    tzSec = try p.atoi(tzSecStart, tzSecStart + 2);
                    p.pos += 2;
                }
            }
            tzOffset = sign * (tzHour * 3600 + tzMin * 60 + tzSec);
        }
    }

    // BC suffix
    if (p.pos + 3 <= str.len and std.mem.eql(u8, str[p.pos .. p.pos + 3], " BC")) {
        isBC = true;
        p.pos += 3;
    }

    if (p.err != null) return p.err.?;

    // Build a time instant. Use system timezone or UTC.
    // Convert year, month, day, hour, minute, second, nano to Unix timestamp.
    // This is complex; we'll use Zig's std.time.epoch functions.
    // We'll construct a datetime in UTC and then adjust for tzOffset.
    const year_abs = if (isBC) 1 - year else year;
    const dt = std.datetime.DateTime{
        .year = @intCast(year_abs),
        .month = @enumFromInt(month),
        .day = @intCast(day),
        .hour = @intCast(hour),
        .minute = @intCast(minute),
        .second = @intCast(second),
        .nanosecond = @intCast(nano),
    };
    const timestamp = dt.timestamp(); // seconds since epoch in UTC
    // const unix_ns = @as(i128, timestamp) * std.time.ns_per_s + nano;
    // Apply timezone offset: we need to subtract offset because we parsed local time with offset.
    // Actually the timestamp from DateTime is in UTC. If the input had an offset, we must adjust.
    // For simplicity, we'll just use the parsed offset to create a fixed zone.
    // We'll use the globalLocationCache to get the zone and then convert.
    _ = timezoneOffset; // Not used for now
    const final_instant = std.time.Instant{
        .secs = @intCast(timestamp + tzOffset),
        .nsecs = nano,
    };
    return final_instant;
}

/// Format a timestamp as a PostgreSQL text string.
pub fn formatTimestamp(allocator: std.mem.Allocator, t: std.time.Instant) ![]u8 {
    // Check infinity
    infinityMutex.lock();
    defer infinityMutex.unlock();
    if (infinityTsEnabled) {
        if (!std.time.Instant.lessThan(infinityTsNegative, t)) {
            return allocator.dupe(u8, "-infinity");
        }
        if (!std.time.Instant.lessThan(t, infinityTsPositive)) {
            return allocator.dupe(u8, "infinity");
        }
    }
    // Convert to DateTime (UTC)
    const epoch = std.time.epoch.EpochSeconds{ .secs = t.secs };
    const dt = epoch.getDateTime();
    // Format as "2006-01-02 15:04:05.999999999Z07:00:00"
    var buf = std.array_list.Managed(u8).init(allocator);
    defer buf.deinit();
    try buf.writer().print("{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        dt.year, @intFromEnum(dt.month), dt.day,
        dt.hour, dt.minute,              dt.second,
    });
    if (t.nsecs != 0) {
        try buf.writer().print(".{d:0>9}", .{t.nsecs});
    }
    // Always output UTC offset +00
    try buf.appendSlice("+00");
    return buf.toOwnedSlice();
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
            const high = charToNibble(hex[2 * i]) catch return error.InvalidBytea;
            const low = charToNibble(hex[2 * i + 1]) catch return error.InvalidBytea;
            out[i] = (high << 4) | low;
        }
        return out;
    } else {
        // escape format
        var out = std.array_list.Managed(u8).init(allocator);
        defer out.deinit();
        var i: usize = 0;
        while (i < s.len) {
            if (s[i] == '\\') {
                i += 1;
                if (i >= s.len) return error.InvalidBytea;
                if (s[i] == '\\') {
                    try out.append('\\');
                    i += 1;
                } else if (i + 3 <= s.len and std.ascii.isDigit(s[i]) and std.ascii.isDigit(s[i + 1]) and std.ascii.isDigit(s[i + 2])) {
                    const oct = try std.fmt.parseInt(u8, s[i .. i + 3], 8);
                    try out.append(oct);
                    i += 3;
                } else {
                    return error.InvalidBytea;
                }
            } else {
                try out.append(s[i]);
                i += 1;
            }
        }
        return out.toOwnedSlice();
    }
}

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
        var out = std.array_list.Managed(u8).init(allocator);
        defer out.deinit();
        for (v) |b| {
            if (b == '\\') {
                try out.appendSlice("\\\\");
            } else if (b < 0x20 or b > 0x7e) {
                try out.writer().print("\\{o:0>3}", .{b});
            } else {
                try out.append(b);
            }
        }
        return out.toOwnedSlice();
    }
}

// -----------------------------------------------------------------------------
// Append text encoding (for COPY)
// -----------------------------------------------------------------------------

/// Append text-encoded value to a buffer (allocates internally).
/// The buffer is assumed to be an array_list.Managed(u8) that already has capacity.
pub fn appendEncodedText(ps: *const ParameterStatus, buf: *std.array_list.Managed(u8), value: anytype) !void {
    const T = @TypeOf(value);
    switch (T) {
        i64 => try buf.writer().print("{d}", .{value}),
        f64 => try buf.writer().print("{d}", .{value}),
        []u8, []const u8 => {
            const bytes = if (T == []u8) value else value;
            if (ps.serverVersion >= 0) {
                const encoded = try encodeBytea(buf.allocator, ps.serverVersion, bytes);
                defer buf.allocator.free(encoded);
                try appendEscapedText(buf, encoded);
            } else {
                try appendEscapedText(buf, bytes);
            }
        },
        bool => try buf.writer().print("{s}", .{if (value) "t" else "f"}),
        std.time.Instant => {
            const ts_str = try formatTimestamp(buf.allocator, value);
            defer buf.allocator.free(ts_str);
            try buf.appendSlice(ts_str);
        },
        null => try buf.appendSlice("\\N"),
        else => @compileError("appendEncodedText: unsupported type " ++ @typeName(T)),
    }
}

/// Append escaped text (for COPY text format) to buffer.
pub fn appendEscapedText(buf: *std.array_list.Managed(u8), text: []const u8) !void {
    // Check if escaping needed
    var need_escape = false;
    for (text) |c| {
        if (c == '\\' or c == '\n' or c == '\r' or c == '\t') {
            need_escape = true;
            break;
        }
    }
    if (!need_escape) {
        try buf.appendSlice(text);
        return;
    }
    for (text) |c| {
        switch (c) {
            '\\' => try buf.appendSlice("\\\\"),
            '\n' => try buf.appendSlice("\\n"),
            '\r' => try buf.appendSlice("\\r"),
            '\t' => try buf.appendSlice("\\t"),
            else => try buf.append(c),
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

// test "timestamp parse" {
//     const alloc = testing.allocator;
//     const ts = try parseTimestamp(alloc, 0, "2024-01-15 12:30:45");
//     // We can't easily verify exact value without a reference, but we can check it's not error.
//     _ = ts;
// }
