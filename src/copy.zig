//! PostgreSQL COPY FROM STDIN support.
//! Provides functionality to efficiently insert many rows using the COPY protocol.

const std = @import("std");
const conn = @import("conn.zig");
const buff = @import("buff.zig");
const ArrayList = std.ArrayList;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

pub const CopyError = error{
    CopyInClosed,
    BinaryCopyNotSupported,
    CopyToNotSupported,
    CopyNotSupportedOutsideTxn,
    CopyInProgress,
    BadConnection,
    UnexpectedMessage,
    CopyFailed,
    UnexpectedReady,
};

// -----------------------------------------------------------------------------
// Public functions to generate COPY SQL statements
// -----------------------------------------------------------------------------

/// Returns a SQL string for COPY table (columns...) FROM STDIN.
/// Caller is responsible for freeing the returned string.
pub fn copyIn(allocator: std.mem.Allocator, table: []const u8, columns: []const []const u8) ![]const u8 {
    var buf = ArrayList(u8).empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, "COPY ");
    try appendQuotedIdentifier(allocator, &buf, table);
    if (columns.len > 0) {
        try buf.appendSlice(allocator, " (");
        for (columns, 0..) |col, i| {
            if (i > 0) try buf.appendSlice(allocator, ", ");
            try appendQuotedIdentifier(allocator, &buf, col);
        }
        try buf.appendSlice(allocator, ")");
    }
    try buf.appendSlice(allocator, " FROM STDIN");
    return try buf.toOwnedSlice(allocator);
}

/// Returns a SQL string for COPY schema.table (columns...) FROM STDIN.
/// Caller is responsible for freeing the returned string.
pub fn copyInSchema(allocator: std.mem.Allocator, schema: []const u8, table: []const u8, columns: []const []const u8) ![]const u8 {
    var buf = ArrayList(u8).empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, "COPY ");
    try appendQuotedIdentifier(allocator, &buf, schema);
    try buf.appendSlice(allocator, ".");
    try appendQuotedIdentifier(allocator, &buf, table);
    if (columns.len > 0) {
        try buf.appendSlice(allocator, " (");
        for (columns, 0..) |col, i| {
            if (i > 0) try buf.appendSlice(allocator, ", ");
            try appendQuotedIdentifier(allocator, &buf, col);
        }
        try buf.appendSlice(allocator, ")");
    }
    try buf.appendSlice(allocator, " FROM STDIN");
    return try buf.toOwnedSlice(allocator);
}

/// Append a quoted PostgreSQL identifier to an array list.
/// Doubles quotes within the identifier and surrounds with double quotes.
fn appendQuotedIdentifier(allocator: std.mem.Allocator, buf: *ArrayList(u8), name: []const u8) !void {
    try buf.append(allocator, '"');
    var it = std.mem.splitScalar(u8, name, '"');
    var first = true;
    while (it.next()) |part| {
        if (!first) try buf.append(allocator, '"'); // Double the quote
        first = false;
        try buf.appendSlice(allocator, part);
        if (it.index == null) break;
        try buf.append(allocator, '"');
    }
    try buf.append(allocator, '"');
}

/// Write a quoted PostgreSQL identifier to a writer.
/// Doubles quotes within the identifier and surrounds with double quotes.
pub fn quoteIdentifierWriter(writer: anytype, name: []const u8) !void {
    try writer.writeByte('"');
    var it = std.mem.splitScalar(u8, name, '"');
    var first = true;
    while (it.next()) |part| {
        if (!first) try writer.writeByte('"'); // Double the quote
        first = false;
        try writer.writeAll(part);
        if (it.index == null) break;
        try writer.writeByte('"');
    }
    try writer.writeByte('"');
}

// -----------------------------------------------------------------------------
// CopyIn structure and implementation
// -----------------------------------------------------------------------------

const CiBufferSize = 64 * 1024; // Buffer size for COPY data
const CiBufferFlushSize = 63 * 1024; // Threshold for flushing buffer

/// CopyIn manages a PostgreSQL COPY FROM STDIN operation.
/// Provides high-performance bulk data insertion.
/// Note: This implementation is synchronous (no background thread) for simplicity.
pub const CopyIn = struct {
    cn: *conn.Conn,
    buffer: ArrayList(u8),
    closed: bool = false,
    bad: bool = false,

    /// Initialize a new COPY FROM STDIN operation.
    /// The connection must be in a transaction block.
    pub fn init(cn: *conn.Conn, query: []const u8) !*CopyIn {
        if (!cn.txnStatus.isInTransaction()) {
            return error.CopyNotSupportedOutsideTxn;
        }

        // Send the COPY query to PostgreSQL
        var w = buff.WriteBuf.init(cn.allocator);
        defer w.deinit();
        try w.next('Q'); // 'Q' = Simple Query message
        try w.string(query);
        try cn.send(&w);

        // Wait for CopyInResponse ('G') or error
        while (true) {
            const msg = try cn.recv1();
            switch (msg.typ) {
                'G' => {
                    const format = try msg.buf.byte(); // 0 = text, 1 = binary
                    if (format != 0) return error.BinaryCopyNotSupported;

                    // Start COPY IN operation
                    var ci = try cn.allocator.create(CopyIn);
                    ci.* = CopyIn{
                        .cn = cn,
                        .buffer = ArrayList(u8).empty,
                    };
                    errdefer ci.buffer.deinit(cn.allocator);

                    // Reserve space for CopyData header (5 bytes: 'd' + length)
                    try ci.buffer.append(cn.allocator, 'd');
                    try ci.buffer.appendSlice(cn.allocator, &[_]u8{ 0, 0, 0, 0 });

                    cn.inCopy = true;
                    return ci;
                },
                'H' => return error.CopyToNotSupported, // COPY TO not supported
                'E' => { // ErrorResponse
                    const err_msg = try parseErrorMessage(&msg.buf);
                    _ = err_msg; // Could log or store the error message
                    return error.CopyFailed;
                },
                'Z' => { // ReadyForQuery
                    try cn.processReadyForQuery(&msg.buf);
                    return error.UnexpectedReady;
                },
                else => return error.UnexpectedMessage,
            }
        }
    }

    /// Clean up the CopyIn operation and associated resources.
    pub fn deinit(self: *CopyIn) void {
        self.close() catch {};
        self.buffer.deinit(self.cn.allocator);
        self.cn.allocator.destroy(self);
    }

    /// Insert a row into the COPY stream.
    /// Each element in `v` represents a column value.
    /// Call with an empty slice (v.len == 0) to flush and close the COPY operation.
    /// Returns 0 for COPY operations (no row count available).
    pub fn exec(self: *CopyIn, v: []const []const u8) !i64 {
        if (self.closed) return error.CopyInClosed;
        if (self.bad) return error.BadConnection;

        if (v.len == 0) {
            // Flush and close the COPY operation
            try self.close();
            return 0;
        }

        // Append each value as text, separated by tabs, ending with newline
        for (v, 0..) |value, i| {
            if (i > 0) try self.buffer.append(self.cn.allocator, '\t');
            try appendEncodedText(self.cn, &self.buffer, value);
        }
        try self.buffer.append(self.cn.allocator, '\n');

        // Flush if buffer is large enough
        if (self.buffer.items.len > CiBufferFlushSize) {
            try self.flush();
        }
        return 0;
    }

    /// Flush buffered data to the PostgreSQL server.
    fn flush(self: *CopyIn) !void {
        const items = self.buffer.items;
        if (items.len <= 5) return; // Nothing to flush (only header)

        // Update message length (excluding the 'd' identifier)
        const len = items.len - 1; // Length of payload
        std.mem.writeInt(u32, @constCast(items[1..5]), @intCast(len), .big);

        // Write to connection
        var writer = self.cn.socket.writer(self.cn.io, &[_]u8{});
        try writer.interface.writeAll(items);

        // Reset buffer, keep header
        self.buffer.clearRetainingCapacity();
        try self.buffer.append(self.cn.allocator, 'd');
        try self.buffer.appendSlice(self.cn.allocator, &[_]u8{ 0, 0, 0, 0 });
    }

    /// Close the COPY operation and wait for completion.
    /// Sends CopyDone message to server and waits for response.
    pub fn close(self: *CopyIn) !void {
        if (self.closed) return;
        self.closed = true;
        if (self.bad) return error.BadConnection;

        // Flush any remaining data
        if (self.buffer.items.len > 5) {
            try self.flush();
        }

        // Send CopyDone ('c') to indicate end of COPY data
        var w = buff.WriteBuf.init(self.cn.allocator);
        defer w.deinit();
        try w.next('c');
        try self.cn.send(&w);

        // Read responses until ReadyForQuery
        while (true) {
            const msg = try self.cn.recv1();
            switch (msg.typ) {
                'C' => {
                    // CommandComplete - ignore
                    continue;
                },
                'N' => { // NoticeResponse - call notice handler if set
                    if (self.cn.notice_handler) |handler| {
                        const notice_msg = try parseErrorMessage(&msg.buf);
                        // notice_msg is borrowed, must be copied if needed later
                        handler(self.cn, notice_msg);
                    }
                },
                'Z' => { // ReadyForQuery
                    try self.cn.processReadyForQuery(&msg.buf);
                    self.cn.inCopy = false;
                    return;
                },
                'E' => { // ErrorResponse
                    const err_msg = try parseErrorMessage(&msg.buf);
                    _ = err_msg;
                    self.bad = true;
                    self.cn.bad = true;
                    return error.CopyFailed;
                },
                else => {
                    return error.UnexpectedMessage;
                },
            }
        }
    }

    /// Returns -1 to indicate variable number of arguments for COPY.
    pub fn numInput() i32 {
        return -1;
    }
};

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Append text encoding of a value to the buffer according to PostgreSQL COPY text format.
/// Handles NULL values and escapes special characters.
fn appendEncodedText(cn: *conn.Conn, buf: *ArrayList(u8), value: []const u8) !void {
    _ = cn;
    // NULL values are represented as \N in COPY text format
    if (value.len == 0 and value.ptr == null) {
        try buf.appendSlice(buf.allocator, "\\N");
        return;
    }

    // Escape backslashes (\) as \\ for PostgreSQL COPY text format
    var i: usize = 0;
    while (i < value.len) {
        const c = value[i];
        if (c == '\\') {
            try buf.appendSlice(buf.allocator, "\\\\");
        } else {
            try buf.append(buf.allocator, c);
        }
        i += 1;
    }
}

/// Parse an ErrorResponse message and return the error message.
fn parseErrorMessage(r: *buff.ReadBuf) ![]const u8 {
    while (true) {
        const field = try r.byte();
        if (field == 0) break; // Null terminator
        const val = try r.string();
        if (field == 'M') { // 'M' = error message
            return val;
        }
    }
    return "unknown error";
}

// -----------------------------------------------------------------------------
// Extension to conn.Conn to support COPY
// -----------------------------------------------------------------------------

/// Prepare a COPY FROM STDIN operation.
/// This would typically be a method on the Conn struct in conn.zig.
pub fn prepareCopyIn(cn: *conn.Conn, query: []const u8) !*CopyIn {
    return CopyIn.init(cn, query);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

test "copyIn SQL generation" {
    const alloc = testing.allocator;
    const cols = [_][]const u8{ "id", "name" };
    const sql = try copyIn(alloc, "users", &cols);
    defer alloc.free(sql);
    try testing.expectEqualStrings("COPY \"users\" (\"id\", \"name\") FROM STDIN", sql);
}
