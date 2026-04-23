//! PostgreSQL LISTEN/NOTIFY support (synchronous version).
//! Provides a simple, blocking listener for notifications without automatic reconnection.
//! For concurrent use, each connection must be used by a single thread.

const std = @import("std");
const conn = @import("conn.zig");
const buff = @import("buff.zig");
const errors = @import("error.zig");

// -----------------------------------------------------------------------------
// Notification
// -----------------------------------------------------------------------------

pub const Notification = struct {
    be_pid: i32,
    channel: []const u8,
    extra: []const u8,

    pub fn deinit(self: *Notification, allocator: std.mem.Allocator) void {
        allocator.free(self.channel);
        allocator.free(self.extra);
        allocator.destroy(self);
    }
};

// -----------------------------------------------------------------------------
// Connection-level notification handler
// -----------------------------------------------------------------------------

pub const NotificationHandler = *const fn (*conn.Conn, *Notification) void;

pub fn notificationHandler(c: *conn.Conn) ?NotificationHandler {
    return c.notification_handler;
}

pub fn setNotificationHandler(c: *conn.Conn, handler: ?NotificationHandler) void {
    c.notification_handler = handler;
}

pub const NotificationHandlerConnector = struct {
    connect_fn: *const fn (allocator: std.mem.Allocator, conn_string: []const u8) anyerror!*conn.Conn,
    allocator: std.mem.Allocator,
    notification_handler: ?NotificationHandler,

    pub fn connect(self: *const NotificationHandlerConnector, conn_string: []const u8) anyerror!*conn.Conn {
        const c = try self.connect_fn(self.allocator, conn_string);
        if (self.notification_handler) |handler| {
            setNotificationHandler(c, handler);
        }
        return c;
    }
};

pub fn connectorNotificationHandler(connector: anytype) ?NotificationHandler {
    const T = @TypeOf(connector);
    if (T == NotificationHandlerConnector) {
        return connector.notification_handler;
    }
    return null;
}

pub fn connectorWithNotificationHandler(
    connect_fn: *const fn (allocator: std.mem.Allocator, conn_string: []const u8) anyerror!*conn.Conn,
    allocator: std.mem.Allocator,
    handler: ?NotificationHandler,
) NotificationHandlerConnector {
    return NotificationHandlerConnector{
        .connect_fn = connect_fn,
        .allocator = allocator,
        .notification_handler = handler,
    };
}

// -----------------------------------------------------------------------------
// Synchronous Listener (no background thread)
// -----------------------------------------------------------------------------

pub const SyncListener = struct {
    allocator: std.mem.Allocator,
    cn: *conn.Conn,
    channels: std.StringHashMap(void),

    pub fn init(allocator: std.mem.Allocator, cn: *conn.Conn) !*SyncListener {
        const self = try allocator.create(SyncListener);
        self.* = .{
            .allocator = allocator,
            .cn = cn,
            .channels = std.StringHashMap(void).init(allocator),
        };
        return self;
    }

    pub fn deinit(self: *SyncListener) void {
        self.channels.deinit();
        self.allocator.destroy(self);
    }

    pub fn listen(self: *SyncListener, channel: []const u8) !void {
        const quoted = try quoteIdentifierAlloc(self.allocator, channel);
        defer self.allocator.free(quoted);
        const q = try std.fmt.allocPrint(self.allocator, "LISTEN {s}", .{quoted});
        defer self.allocator.free(q);
        try self.execSimpleQuery(q);
        try self.channels.put(channel, {});
    }

    pub fn unlisten(self: *SyncListener, channel: []const u8) !void {
        const quoted = try quoteIdentifierAlloc(self.allocator, channel);
        defer self.allocator.free(quoted);
        const q = try std.fmt.allocPrint(self.allocator, "UNLISTEN {s}", .{quoted});
        defer self.allocator.free(q);
        try self.execSimpleQuery(q);
        _ = self.channels.remove(channel);
    }

    pub fn unlistenAll(self: *SyncListener) !void {
        try self.execSimpleQuery("UNLISTEN *");
        self.channels.clearRetainingCapacity();
    }

    fn execSimpleQuery(self: *SyncListener, q: []const u8) !void {
        var w = buff.WriteBuf.init(self.allocator);
        defer w.deinit();
        try w.next('Q');
        try w.string(q);
        try self.cn.send(&w);

        while (true) {
            var msg = try self.cn.recv1();
            switch (msg.typ) {
                'Z' => {
                    try self.cn.processReadyForQuery(&msg.buf);
                    return;
                },
                'E' => {
                    _ = try errors.parseError(&msg.buf);
                    return error.PqError;
                },
                'N', 'S' => continue,
                else => return error.UnexpectedMessage,
            }
        }
    }

    /// Wait for a notification (blocks until one arrives).
    pub fn waitForNotification(self: *SyncListener) !*Notification {
        while (true) {
            var msg = try self.cn.recv1();
            switch (msg.typ) {
                'A' => {
                    return try recvNotification(self.allocator, &msg.buf);
                },
                'Z' => {
                    try self.cn.processReadyForQuery(&msg.buf);
                    continue;
                },
                'E' => {
                    _ = try errors.parseError(&msg.buf);
                    return error.PqError;
                },
                'N', 'S' => continue,
                else => return error.UnexpectedMessage,
            }
        }
    }
};

fn recvNotification(allocator: std.mem.Allocator, r: *buff.ReadBuf) !*Notification {
    const be_pid = try r.int32();
    const channel = try r.string();
    const extra = try r.string();
    const notif = try allocator.create(Notification);
    errdefer allocator.destroy(notif);
    notif.* = .{
        .be_pid = be_pid,
        .channel = try allocator.dupe(u8, channel),
        .extra = try allocator.dupe(u8, extra),
    };
    return notif;
}

fn quoteIdentifierAlloc(allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(allocator);
    try buf.append(allocator, '"');
    var it = std.mem.splitScalar(u8, name, '"');
    while (it.next()) |part| {
        try buf.appendSlice(allocator, part);
        if (it.index != null) try buf.append(allocator, '"');
    }
    try buf.append(allocator, '"');
    return try buf.toOwnedSlice(allocator);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

test "quoteIdentifier" {
    const alloc = testing.allocator;
    const quoted = try quoteIdentifierAlloc(alloc, "my_table");
    defer alloc.free(quoted);
    try testing.expectEqualStrings("\"my_table\"", quoted);
}
