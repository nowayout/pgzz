//! PostgreSQL COPY FROM STDIN support.
//! Provides functionality to efficiently insert many rows using the COPY protocol.

const std = @import("std");
const conn = @import("conn.zig");
const buff = @import("buff.zig");

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
};

// -----------------------------------------------------------------------------
// Public functions to generate COPY SQL statements
// -----------------------------------------------------------------------------

/// Returns a SQL string for COPY table (columns...) FROM STDIN.
/// Caller is responsible for freeing the returned string.
pub fn copyIn(allocator: std.mem.Allocator, table: []const u8, columns: []const []const u8) ![]const u8 {
    var buf = std.array_list.Managed(u8).init(allocator);
    defer buf.deinit();
    try buf.appendSlice("COPY ");
    try appendQuotedIdentifier(&buf, table);
    if (columns.len > 0) {
        try buf.appendSlice(" (");
        for (columns, 0..) |col, i| {
            if (i > 0) try buf.appendSlice(", ");
            try appendQuotedIdentifier(&buf, col);
        }
        try buf.appendSlice(")");
    }
    try buf.appendSlice(" FROM STDIN");
    return buf.toOwnedSlice();
}

/// Returns a SQL string for COPY schema.table (columns...) FROM STDIN.
/// Caller is responsible for freeing the returned string.
pub fn copyInSchema(allocator: std.mem.Allocator, schema: []const u8, table: []const u8, columns: []const []const u8) ![]const u8 {
    var buf = std.array_list.Managed(u8).init(allocator);
    defer buf.deinit();
    try buf.appendSlice("COPY ");
    try appendQuotedIdentifier(&buf, schema);
    try buf.appendSlice(".");
    try appendQuotedIdentifier(&buf, table);
    if (columns.len > 0) {
        try buf.appendSlice(" (");
        for (columns, 0..) |col, i| {
            if (i > 0) try buf.appendSlice(", ");
            try appendQuotedIdentifier(&buf, col);
        }
        try buf.appendSlice(")");
    }
    try buf.appendSlice(" FROM STDIN");
    return buf.toOwnedSlice();
}

/// Append a quoted PostgreSQL identifier to an array list.
/// Doubles quotes within the identifier and surrounds with double quotes.
fn appendQuotedIdentifier(buf: *std.array_list.Managed(u8), name: []const u8) !void {
    try buf.append('"');
    var it = std.mem.splitScalar(u8, name, '"');
    var first = true;
    while (it.next()) |part| {
        if (!first) try buf.append('"'); // Double the quote
        first = false;
        try buf.appendSlice(part);
        if (it.index == null) break;
        try buf.append('"');
    }
    try buf.append('"');
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
pub const CopyIn = struct {
    cn: *conn.Conn,
    buffer: std.array_list.Managed(u8),

    // Background thread for reading PostgreSQL responses
    responseThread: ?std.Thread = null,
    responseDone: std.Thread.ResetEvent = .{},
    responseError: ?anyerror = null,

    mutex: std.Thread.Mutex = .{},
    closed: bool = false,
    bad: bool = false,

    /// Initialize a new COPY FROM STDIN operation.
    /// The connection must be in a transaction block.
    pub fn init(cn: *conn.Conn, query: []const u8) !*CopyIn {
        if (!cn.isInTransaction()) {
            return error.CopyNotSupportedOutsideTxn;
        }

        // Send the COPY query to PostgreSQL
        var w = buff.WriteBuf.init(cn.allocator);
        defer w.deinit();
        w.byte('Q'); // 'Q' = Simple Query message
        w.string(query);
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
                        .buffer = std.array_list.Managed(u8).init(cn.allocator),
                    };

                    // Reserve space for CopyData header (5 bytes: 'd' + length)
                    errdefer ci.buffer.deinit();
                    try ci.buffer.append('d');
                    try ci.buffer.appendSlice(&[_]u8{ 0, 0, 0, 0 });

                    // Start background thread to read server responses
                    ci.responseThread = try std.Thread.spawn(.{}, responseLoop, .{ci});
                    return ci;
                },
                'H' => return error.CopyToNotSupported, // COPY TO not supported
                'E' => { // ErrorResponse
                    const err_msg = try parseErrorMessage(msg.buf);
                    _ = err_msg; // Could log or store the error message
                    return error.CopyFailed;
                },
                'Z' => { // ReadyForQuery
                    try cn.processReadyForQuery(msg.buf);
                    return error.UnexpectedReady;
                },
                else => return error.UnexpectedMessage,
            }
        }
    }

    /// Clean up the CopyIn operation and associated resources.
    pub fn deinit(self: *CopyIn) void {
        self.close() catch {};
        if (self.responseThread) |th| {
            th.join();
        }
        self.buffer.deinit();
        self.cn.allocator.destroy(self);
    }

    /// Insert a row into the COPY stream.
    /// Each element in `v` represents a column value.
    /// Call with an empty slice (v.len == 0) to flush and close the COPY operation.
    /// Returns 0 for COPY operations (no row count available).
    pub fn exec(self: *CopyIn, v: []const []const u8) !i64 {
        if (self.closed) return error.CopyInClosed;
        if (self.bad) return error.BadConnection;

        // Check if error was set by the response thread
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.responseError != null) return self.responseError.?;
        }

        if (v.len == 0) {
            // Flush and close the COPY operation
            try self.close();
            return 0;
        }

        // Append each value as text, separated by tabs, ending with newline
        for (v, 0..) |value, i| {
            if (i > 0) try self.buffer.append('\t');
            try appendEncodedText(self.cn, &self.buffer, value);
        }
        try self.buffer.append('\n');

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
        std.mem.writeInt(u32, items[1..5][0..4], @intCast(len), .big);

        // Write to connection
        try self.cn.socket.writeAll(items);

        // Reset buffer, keep header
        self.buffer.clearRetainingCapacity();
        try self.buffer.append('d');
        try self.buffer.appendSlice(&[_]u8{ 0, 0, 0, 0 });
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
        try self.cn.sendSimpleMessage('c');

        // Wait for response thread to finish
        if (self.responseThread) |th| {
            th.join();
            self.responseThread = null;
        }

        // Check for error from response thread
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.responseError != null) return self.responseError.?;
        }

        self.cn.inCopy = false;
    }

    /// Returns -1 to indicate variable number of arguments for COPY.
    pub fn numInput() i32 {
        return -1;
    }

    /// Background thread that reads PostgreSQL responses during COPY.
    /// Runs in a separate thread to avoid blocking the main thread.
    fn responseLoop(self: *CopyIn) void {
        defer self.responseDone.set();
        while (true) {
            const msg = self.cn.recv1() catch |err| {
                self.setError(err);
                return;
            };
            defer if (msg.buf.data.len > 0) self.cn.allocator.free(msg.buf.data);
            switch (msg.typ) {
                'C', 'N' => {
                    // CommandComplete or NoticeResponse - ignore
                },
                'Z' => { // ReadyForQuery
                    self.cn.processReadyForQuery(msg.buf) catch |err| {
                        self.setError(err);
                    };
                    return;
                },
                'E' => { // ErrorResponse
                    const err_msg = parseErrorMessage(msg.buf) catch |err| {
                        self.setError(err);
                        return;
                    };
                    _ = err_msg;
                    self.setError(error.CopyFailed);
                    return;
                },
                else => {
                    self.setError(error.UnexpectedMessage);
                    return;
                },
            }
        }
    }

    /// Set an error from the response thread.
    fn setError(self: *CopyIn, err: anyerror) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.responseError == null) {
            self.responseError = err;
            self.bad = true;
            self.cn.bad = true;
        }
    }
};

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Append text encoding of a value to the buffer according to PostgreSQL COPY text format.
/// Handles NULL values and escapes special characters.
fn appendEncodedText(cn: *conn.Conn, buf: *std.array_list.Managed(u8), value: []const u8) !void {
    _ = cn;
    // NULL values are represented as \N in COPY text format
    if (value.len == 0 and value.ptr == null) {
        try buf.appendSlice("\\N");
        return;
    }

    // Escape backslashes (\) as \\ for PostgreSQL COPY text format
    var i: usize = 0;
    while (i < value.len) {
        const c = value[i];
        if (c == '\\') {
            try buf.appendSlice("\\\\");
        } else {
            try buf.append(c);
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
