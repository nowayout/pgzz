//! Notice handler support for PostgreSQL connections.
//! Provides functions to get and set notice handlers on connections,
//! as well as a connector wrapper to automatically set notice handlers
//! when establishing connections.
//!
//! Based on the Go implementation in `notice.go`.

const std = @import("std");
const conn = @import("conn.zig");

/// Type of notice handler function.
/// Receives the connection and the notice message as a string.
/// The handler is executed synchronously, so it should not block.
pub const NoticeHandler = *const fn (*conn.Conn, []const u8) void;

// -----------------------------------------------------------------------------
// Connection-level handler getter/setter
// -----------------------------------------------------------------------------

/// Returns the current notice handler on the connection, or null if none.
pub fn noticeHandler(c: *conn.Conn) ?NoticeHandler {
    return c.notice_handler;
}

/// Sets the notice handler on the connection. Pass null to unset.
pub fn setNoticeHandler(c: *conn.Conn, handler: ?NoticeHandler) void {
    c.notice_handler = handler;
}

// -----------------------------------------------------------------------------
// Connector wrapper (analogous to NoticeHandlerConnector)
// -----------------------------------------------------------------------------

/// A connector that wraps another connector and automatically sets a notice
/// handler on every connection it creates.
pub const NoticeHandlerConnector = struct {
    /// Underlying connector (a function that creates a connection).
    /// The error set is anyerror (allows any error).
    connect_fn: *const fn (allocator: std.mem.Allocator, conn_string: []const u8) anyerror!*conn.Conn,
    /// Allocator used for the connector (if needed).
    allocator: std.mem.Allocator,
    /// Notice handler to set on each connection.
    notice_handler: ?NoticeHandler,

    /// Creates a new connection by calling the underlying connect function,
    /// then sets the notice handler on it.
    pub fn connect(self: *const NoticeHandlerConnector, conn_string: []const u8) anyerror!*conn.Conn {
        const c = try self.connect_fn(self.allocator, conn_string);
        if (self.notice_handler) |handler| {
            setNoticeHandler(c, handler);
        }
        return c;
    }
};

/// Returns the notice handler associated with the given connector, if it is a
/// `NoticeHandlerConnector`. Otherwise returns null.
pub fn connectorNoticeHandler(connector: anytype) ?NoticeHandler {
    const T = @TypeOf(connector);
    if (T == NoticeHandlerConnector) {
        return connector.notice_handler;
    }
    return null;
}

/// Wraps a connect function with a notice handler.
pub fn connectorWithNoticeHandler(
    connect_fn: *const fn (allocator: std.mem.Allocator, conn_string: []const u8) anyerror!*conn.Conn,
    allocator: std.mem.Allocator,
    handler: ?NoticeHandler,
) NoticeHandlerConnector {
    return NoticeHandlerConnector{
        .connect_fn = connect_fn,
        .allocator = allocator,
        .notice_handler = handler,
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

// Mock connect function that returns a minimal connection.
fn mockConnect(allocator: std.mem.Allocator, _: []const u8) anyerror!*conn.Conn {
    const c = try allocator.create(conn.Conn);
    c.* = .{
        .allocator = allocator,
        .arena = undefined,
        .socket = undefined,
        .read_buffer = &[_]u8{},
        .write_buffer = &[_]u8{},
        .opts = undefined,
        .dialer = undefined,
        .processID = 0,
        .secretKey = 0,
        .txnStatus = .Idle,
        .parameterStatus = .{},
        .disablePreparedBinaryResult = false,
        .binaryParameters = false,
        .bad = false,
        .inCopy = false,
        .savedMsgType = 0,
        .savedMsgBuf = null,
        .nameCounter = 0,
        .socket_open = false,
        .notice_handler = null,
        .notification_handler = null,
    };
    return c;
}

fn dummyHandler(_: *conn.Conn, _: []const u8) void {}
fn testHandler(_: *conn.Conn, _: []const u8) void {}

test "notice handler get/set" {
    var dummy_conn = conn.Conn{
        .allocator = testing.allocator,
        .arena = undefined,
        .socket = undefined,
        .read_buffer = &[_]u8{},
        .write_buffer = &[_]u8{},
        .opts = undefined,
        .dialer = undefined,
        .processID = 0,
        .secretKey = 0,
        .txnStatus = .Idle,
        .parameterStatus = .{},
        .disablePreparedBinaryResult = false,
        .binaryParameters = false,
        .bad = false,
        .inCopy = false,
        .savedMsgType = 0,
        .savedMsgBuf = null,
        .nameCounter = 0,
        .socket_open = false,
        .notice_handler = null,
        .notification_handler = null,
    };
    defer {
        // Cleanup not needed for dummy
    }

    try testing.expect(noticeHandler(&dummy_conn) == null);

    setNoticeHandler(&dummy_conn, testHandler);
    try testing.expect(noticeHandler(&dummy_conn) == testHandler);

    setNoticeHandler(&dummy_conn, null);
    try testing.expect(noticeHandler(&dummy_conn) == null);
}

test "NoticeHandlerConnector" {
    var connector = NoticeHandlerConnector{
        .connect_fn = mockConnect,
        .allocator = testing.allocator,
        .notice_handler = null,
    };

    try testing.expect(connectorNoticeHandler(connector) == null);

    connector = connectorWithNoticeHandler(mockConnect, testing.allocator, dummyHandler);
    try testing.expect(connector.notice_handler == dummyHandler);

    const c = try connector.connect("");
    defer testing.allocator.destroy(c);
    try testing.expect(c.notice_handler == dummyHandler);
}
