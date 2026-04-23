const std = @import("std");
const Oid = @import("oid.zig").Oid;
const ArrayList = std.ArrayList;

// -----------------------------------------------------------------------------
// ReadBuf: Read binary data from byte slices in big-endian order
// -----------------------------------------------------------------------------

/// ReadBuf provides methods for reading PostgreSQL wire protocol data.
/// The protocol uses big-endian byte order for multi-byte integers.
pub const ReadBuf = struct {
    /// Remaining data to be read
    data: []const u8,

    /// Initialize a ReadBuf with the given data slice
    pub fn init(data: []const u8) ReadBuf {
        return .{ .data = data };
    }

    /// Read a 32-bit signed integer (big-endian)
    /// Returns error.InsufficientData if not enough bytes remain
    pub fn int32(self: *ReadBuf) !i32 {
        if (self.data.len < 4) return error.InsufficientData;
        const bytes = self.data[0..4];
        const n = std.mem.readInt(i32, &[_]u8{ bytes[0], bytes[1], bytes[2], bytes[3] }, .big);
        self.data = self.data[4..];
        return n;
    }

    /// Read a PostgreSQL OID (32-bit unsigned integer, big-endian)
    /// Returns error.InsufficientData if not enough bytes remain
    pub fn oid(self: *ReadBuf) !Oid {
        if (self.data.len < 4) return error.InsufficientData;
        const bytes = self.data[0..4];
        const n = std.mem.readInt(u32, &[_]u8{ bytes[0], bytes[1], bytes[2], bytes[3] }, .big);
        self.data = self.data[4..];
        return n;
    }

    /// Read a 16-bit signed integer (big-endian)
    /// Returns error.InsufficientData if not enough bytes remain
    pub fn int16(self: *ReadBuf) !i16 {
        if (self.data.len < 2) return error.InsufficientData;
        const bytes = self.data[0..2];
        const n = std.mem.readInt(i16, &[_]u8{ bytes[0], bytes[1] }, .big);
        self.data = self.data[2..];
        return n;
    }

    /// Read a null-terminated string
    /// Returns the string (without the null terminator)
    /// Returns error.MissingStringTerminator if no null byte is found
    pub fn string(self: *ReadBuf) ![]const u8 {
        var i: usize = 0;
        while (i < self.data.len) : (i += 1) {
            if (self.data[i] == 0) {
                const s = self.data[0..i];
                self.data = self.data[i + 1 ..];
                return s;
            }
        }
        return error.MissingStringTerminator;
    }

    /// Read the next n bytes as a slice
    /// Returns error.InsufficientData if not enough bytes remain
    pub fn next(self: *ReadBuf, n: usize) ![]const u8 {
        if (self.data.len < n) return error.InsufficientData;
        const v = self.data[0..n];
        self.data = self.data[n..];
        return v;
    }

    /// Read a single byte
    /// Returns error.InsufficientData if no bytes remain
    pub fn byte(self: *ReadBuf) !u8 {
        if (self.data.len == 0) return error.InsufficientData;
        const b = self.data[0];
        self.data = self.data[1..];
        return b;
    }
};

// -----------------------------------------------------------------------------
// WriteBuf: Build PostgreSQL protocol messages
// -----------------------------------------------------------------------------

/// WriteBuf provides methods for constructing PostgreSQL wire protocol messages.
/// Automatically calculates and inserts message lengths.
pub const WriteBuf = struct {
    allocator: std.mem.Allocator,
    buf: ArrayList(u8),

    /// Position in buffer where the current message's length should be written
    /// null when no message is currently being constructed
    msg_len_pos: ?usize,

    /// Initialize a WriteBuf with the given allocator
    pub fn init(allocator: std.mem.Allocator) WriteBuf {
        return .{
            .allocator = allocator,
            .buf = ArrayList(u8).empty,
            .msg_len_pos = null,
        };
    }

    /// Release all resources associated with the WriteBuf
    pub fn deinit(self: *WriteBuf) void {
        self.buf.deinit(self.allocator);
        self.* = undefined;
    }

    /// Start a new message with the given type code
    /// If a message is already in progress, its length is finalized
    pub fn next(self: *WriteBuf, typ: u8) !void {
        // Finalize previous message if one exists
        if (self.msg_len_pos) |len_pos| {
            const total_len = self.buf.items.len;
            const msg_len = @as(u32, @intCast(total_len - len_pos));
            var len_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &len_bytes, msg_len, .big);
            @memcpy(self.buf.items[len_pos .. len_pos + 4], &len_bytes);
            self.msg_len_pos = null;
        }

        // Start new message: write type byte and placeholder for length
        try self.buf.append(self.allocator, typ);
        const new_len_pos = self.buf.items.len;
        try self.buf.appendSlice(self.allocator, &[_]u8{ 0, 0, 0, 0 });
        self.msg_len_pos = new_len_pos;
    }

    /// Finalize the current message and return the complete buffer
    /// Returns error.NoActiveMessage if no message is in progress
    pub fn wrap(self: *WriteBuf) ![]const u8 {
        const len_pos = self.msg_len_pos orelse return error.NoActiveMessage;
        const total_len = self.buf.items.len;
        const msg_len = @as(u32, @intCast(total_len - len_pos));
        var len_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_bytes, msg_len, .big);
        @memcpy(self.buf.items[len_pos .. len_pos + 4], &len_bytes);
        self.msg_len_pos = null;
        return self.buf.items;
    }

    /// Write a 32-bit signed integer (big-endian)
    pub fn int32(self: *WriteBuf, n: i32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(i32, &b, n, .big);
        try self.buf.appendSlice(self.allocator, &b);
    }

    /// Write a 16-bit signed integer (big-endian)
    pub fn int16(self: *WriteBuf, n: i16) !void {
        var b: [2]u8 = undefined;
        std.mem.writeInt(i16, &b, n, .big);
        try self.buf.appendSlice(self.allocator, &b);
    }

    /// Write a null-terminated string
    pub fn string(self: *WriteBuf, s: []const u8) !void {
        try self.buf.appendSlice(self.allocator, s);
        try self.buf.append(self.allocator, 0);
    }

    /// Write a single byte
    pub fn byte(self: *WriteBuf, c: u8) !void {
        try self.buf.append(self.allocator, c);
    }

    /// Write raw bytes without any formatting
    pub fn bytes(self: *WriteBuf, v: []const u8) !void {
        try self.buf.appendSlice(self.allocator, v);
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------
const testing = std.testing;

test "WriteBuf: single message" {
    const alloc = testing.allocator;
    var wb = WriteBuf.init(alloc);
    defer wb.deinit();

    // Create a simple query message
    try wb.next('Q'); // 'Q' = SimpleQuery message
    try wb.string("SELECT 1");
    const full = try wb.wrap();

    // Verify message structure
    try testing.expectEqual(@as(u8, 'Q'), full[0]);
    const msg_len = std.mem.readInt(u32, &[_]u8{ full[1], full[2], full[3], full[4] }, .big);
    try testing.expectEqual(@as(u32, 13), msg_len); // 8 chars + null + 4 bytes for len

    const expected = "SELECT 1" ++ "\x00";
    try testing.expectEqualSlices(u8, expected, full[5..]);
}

test "WriteBuf: multiple messages" {
    const alloc = testing.allocator;
    var wb = WriteBuf.init(alloc);
    defer wb.deinit();

    // First message: Parse
    try wb.next('P'); // 'P' = Parse message
    try wb.string("stmt1");
    try wb.string("SELECT $1");
    try wb.int16(0); // Number of parameter OIDs
    const msg1 = try wb.wrap();

    // Verify first message
    try testing.expectEqual(@as(u8, 'P'), msg1[0]);
    const len1 = std.mem.readInt(u32, &[_]u8{ msg1[1], msg1[2], msg1[3], msg1[4] }, .big);
    try testing.expectEqual(@as(u32, 22), len1);

    // Second message: Bind
    try wb.next('B'); // 'B' = Bind message
    try wb.byte(0); // Portal name (empty)
    try wb.string("stmt1");
    try wb.int16(0); // Number of format codes
    try wb.int16(1); // Number of parameters
    try wb.int32(3); // Parameter length
    try wb.bytes("foo"); // Parameter value
    try wb.bytes(&[_]u8{ 0, 0 }); // Result format codes
    const msg2 = try wb.wrap();

    // Verify second message
    try testing.expectEqual(@as(u8, 'B'), msg2[msg1.len]);
    const len_bytes = msg2[msg1.len + 1 .. msg1.len + 5];
    const len2 = std.mem.readInt(u32, &[_]u8{
        len_bytes[0],
        len_bytes[1],
        len_bytes[2],
        len_bytes[3],
    }, .big);
    try testing.expect(len2 > 0);
}
