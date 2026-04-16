//! PostgreSQL LISTEN/NOTIFY support.
//! Provides `ListenerConn` for low-level notification waiting and `Listener`
//! for automatic reconnection and channel management.

const std = @import("std");
const conn = @import("conn.zig");
const buff = @import("buff.zig");
const errors = @import("error.zig");

// -----------------------------------------------------------------------------
// Notification
// -----------------------------------------------------------------------------

/// A single notification from the database.
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
// ListenerConn (low-level)
// -----------------------------------------------------------------------------

const ConnState = enum(i32) {
    idle = 0,
    expect_response = 1,
    expect_ready_for_query = 2,
};

/// Internal message for communication between the main loop and query sender.
const Message = struct {
    typ: u8,
    err: ?anyerror = null,
};

pub const ListenerConn = struct {
    allocator: std.mem.Allocator,
    cn: *conn.Conn,
    error_state: ?anyerror = null,
    state: ConnState = .idle,
    notification_chan: std.Thread.Channel(*Notification),
    reply_chan: std.Thread.Channel(Message),
    // Mutex protecting cn and err
    mutex: std.Thread.Mutex = .{},
    // Sender lock (only one goroutine may send at a time)
    sender_mutex: std.Thread.Mutex = .{},
    // Background thread handle
    thread: ?std.Thread = null,
    closed: bool = false,

    pub fn init(allocator: std.mem.Allocator, cn: *conn.Conn, notification_chan: std.Thread.Channel(*Notification)) !*ListenerConn {
        const self = try allocator.create(ListenerConn);
        self.* = .{
            .allocator = allocator,
            .cn = cn,
            .notification_chan = notification_chan,
            .reply_chan = std.Thread.Channel(Message).init(allocator),
        };
        self.reply_chan.capacity = 2;
        // Start the background receiver loop
        self.thread = try std.Thread.spawn(.{}, listenerConnLoop, .{self});
        return self;
    }

    pub fn deinit(self: *ListenerConn) void {
        _ = self.close();
        if (self.thread) |t| t.join();
        self.reply_chan.deinit();
        self.cn.deinit();
        self.allocator.destroy(self);
    }

    // Acquire the sender lock; returns error if connection is already dead.
    fn acquireSenderLock(self: *ListenerConn) !void {
        self.sender_mutex.lock();
        defer self.sender_mutex.unlock();
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.error_state != null) return self.error_state.?;
    }

    // Helper to change state atomically.
    fn setState(self: *ListenerConn, new_state: ConnState) !void {
        const expected = switch (new_state) {
            .idle => .expect_ready_for_query,
            .expect_response => .idle,
            .expect_ready_for_query => .expect_response,
        };
        if (self.state != expected) return error.ProtocolOutOfSync;
        self.state = new_state;
    }

    // Send a simple query (no parameters). Caller must hold sender lock.
    fn sendSimpleQuery(self: *ListenerConn, q: []const u8) !void {
        try self.setState(.expect_response);
        var w = buff.WriteBuf.init(self.allocator);
        defer w.deinit();
        try w.byte('Q');
        try w.string(q);
        try self.cn.send(&w);
    }

    /// Execute a simple query and wait for the result.
    /// Returns `true` if the query was executed (even if it returned an error),
    /// and an optional error from the server.
    pub fn execSimpleQuery(self: *ListenerConn, q: []const u8) !struct { executed: bool, err: ?anyerror } {
        try self.acquireSenderLock();
        defer self.sender_mutex.unlock();

        self.sendSimpleQuery(q) catch |send_err| {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.error_state == null) self.error_state = send_err;
            self.cn.close() catch {};
            return .{ .executed = false, .err = send_err };
        };

        while (true) {
            const msg = self.reply_chan.receive();
            switch (msg.typ) {
                'Z' => {
                    std.debug.assert(msg.err == null);
                    return .{ .executed = true, .err = null };
                },
                'E' => {
                    std.debug.assert(msg.err != null);
                    return .{ .executed = true, .err = msg.err };
                },
                else => return .{ .executed = false, .err = error.UnexpectedMessage },
            }
        }
    }

    pub fn listen(self: *ListenerConn, channel: []const u8) !bool {
        const quoted = try quoteIdentifierAlloc(self.allocator, channel);
        defer self.allocator.free(quoted);
        const q = try std.fmt.allocPrint(self.allocator, "LISTEN {s}", .{quoted});
        defer self.allocator.free(q);
        const res = try self.execSimpleQuery(q);
        return res.executed;
    }

    pub fn unlisten(self: *ListenerConn, channel: []const u8) !bool {
        const quoted = try quoteIdentifierAlloc(self.allocator, channel);
        defer self.allocator.free(quoted);
        const q = try std.fmt.allocPrint(self.allocator, "UNLISTEN {s}", .{quoted});
        defer self.allocator.free(q);
        const res = try self.execSimpleQuery(q);
        return res.executed;
    }

    pub fn unlistenAll(self: *ListenerConn) !bool {
        const res = try self.execSimpleQuery("UNLISTEN *");
        return res.executed;
    }

    pub fn ping(self: *ListenerConn) !void {
        const res = try self.execSimpleQuery("");
        if (!res.executed) return res.err orelse error.PingFailed;
        if (res.err != null) return res.err;
    }

    pub fn close(self: *ListenerConn) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.closed) return error.AlreadyClosed;
        self.closed = true;
        if (self.error_state == null) self.error_state = error.ListenerConnClosed;
        self.cn.close() catch {};
    }

    pub fn getErr(self: *ListenerConn) ?anyerror {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.error_state;
    }
};

// Background loop that reads messages from the connection and forwards
// notifications and replies.
fn listenerConnLoop(lc: *ListenerConn) void {
    defer {
        // Cleanup: close the reply channel to unblock any waiting senders.
        lc.reply_chan.close();
        // Close the notification channel to signal the listener that we're done.
        lc.notification_chan.close();
    }

    while (true) {
        // Receive a message from the connection
        const msg = lc.cn.recvMessage() catch |err| {
            lc.mutex.lock();
            defer lc.mutex.unlock();
            if (lc.error_state == null) lc.error_state = err;
            return;
        };
        switch (msg.typ) {
            'A' => {
                const notif = recvNotification(lc.allocator, &msg.buf) catch continue;
                lc.notification_chan.send(notif) catch notif.deinit(lc.allocator);
            },
            'T', 'D' => continue,
            'E' => {
                // ErrorResponse
                if (lc.setState(.expect_ready_for_query)) {
                    const err = errors.parseError(&msg.buf) catch |e| e;
                    lc.reply_chan.send(.{ .typ = 'E', .err = err }) catch {};
                } else {
                    // protocol out of sync – abandon
                    lc.mutex.lock();
                    defer lc.mutex.unlock();
                    if (lc.error_state == null) lc.error_state = error.ProtocolOutOfSync;
                    return;
                }
            },
            'C', 'I' => {
                // CommandComplete / EmptyQueryResponse
                if (lc.setState(.expect_ready_for_query)) {
                    // Nothing to send; the ReadyForQuery will follow.
                } else {
                    lc.mutex.lock();
                    defer lc.mutex.unlock();
                    if (lc.error_state == null) lc.error_state = error.UnexpectedCommandComplete;
                    return;
                }
            },
            'Z' => {
                // ReadyForQuery
                if (lc.setState(.idle)) {
                    lc.reply_chan.send(.{ .typ = 'Z', .err = null }) catch {};
                } else {
                    lc.mutex.lock();
                    defer lc.mutex.unlock();
                    if (lc.error_state == null) lc.error_state = error.UnexpectedReadyForQuery;
                    return;
                }
            },
            'N', 'S' => continue,
            else => {
                lc.mutex.lock();
                defer lc.mutex.unlock();
                if (lc.error_state == null) lc.error_state = error.UnexpectedMessage;
                return;
            },
        }
    }
}

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

// -----------------------------------------------------------------------------
// Listener (high-level, with auto-reconnect)
// -----------------------------------------------------------------------------

pub const ListenerEvent = enum {
    connected,
    disconnected,
    reconnected,
    connection_attempt_failed,
};

pub const EventCallback = *const fn (event: ListenerEvent, err: ?anyerror) void;

pub const Listener = struct {
    allocator: std.mem.Allocator,
    name: []const u8,
    min_reconnect_interval_ms: u64,
    max_reconnect_interval_ms: u64,
    dialer: conn.Dialer,
    event_callback: ?EventCallback,

    // State
    mutex: std.Thread.Mutex = .{},
    is_closed: bool = false,
    reconnect_cond: std.Thread.Condition = .{},
    cn: ?*ListenerConn = null,
    notification_chan: std.Thread.Channel(*Notification),
    channels: std.StringHashMap(void),
    thread: ?std.Thread = null,

    pub fn init(allocator: std.mem.Allocator, name: []const u8, min_reconnect_interval_ms: u64, max_reconnect_interval_ms: u64, event_callback: ?EventCallback) !*Listener {
        const self = try allocator.create(Listener);
        self.* = .{
            .allocator = allocator,
            .name = try allocator.dupe(u8, name),
            .min_reconnect_interval_ms = min_reconnect_interval_ms,
            .max_reconnect_interval_ms = max_reconnect_interval_ms,
            .dialer = conn.Dialer.default,
            .event_callback = event_callback,
            .channels = std.StringHashMap(void).init(allocator),
            .notification_chan = std.Thread.Channel(*Notification).init(allocator),
        };
        self.notification_chan.capacity = 32;
        // Start the main listener goroutine
        self.thread = try std.Thread.spawn(.{}, listenerMain, .{self});
        return self;
    }

    pub fn deinit(self: *Listener) void {
        _ = self.close();
        if (self.thread) |t| t.join();
        self.notification_chan.deinit();
        self.channels.deinit();
        self.allocator.free(self.name);
        self.allocator.destroy(self);
    }

    pub fn notificationChannel(self: *Listener) std.Thread.Channel(*Notification) {
        return self.notification_chan;
    }

    pub fn listen(self: *Listener, channel: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.is_closed) return error.ListenerClosed;

        // Check if already listening
        if (self.channels.contains(channel)) return error.ChannelAlreadyOpen;

        // If we have a live connection, try to send LISTEN now
        if (self.cn) |lc| {
            _ = try lc.listen(channel);
        }

        // Add to our channel set regardless
        try self.channels.put(channel, {});

        // If we have no connection (e.g., we are disconnected), wait for reconnect
        while (self.cn == null and !self.is_closed) {
            self.reconnect_cond.wait(&self.mutex);
        }
    }

    pub fn unlisten(self: *Listener, channel: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.is_closed) return error.ListenerClosed;

        if (!self.channels.contains(channel)) return error.ChannelNotOpen;

        if (self.cn) |lc| {
            _ = try lc.unlisten(channel);
        }

        _ = self.channels.remove(channel);
    }

    pub fn unlistenAll(self: *Listener) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.is_closed) return error.ListenerClosed;

        if (self.cn) |lc| {
            _ = try lc.unlistenAll();
        }

        self.channels.clearRetainingCapacity();
    }

    pub fn ping(self: *Listener) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.is_closed) return error.ListenerClosed;
        if (self.cn) |lc| {
            try lc.ping();
        } else {
            return error.NoConnection;
        }
    }

    pub fn close(self: *Listener) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.is_closed) return error.ListenerClosed;
        self.is_closed = true;

        if (self.cn) |lc| {
            lc.close() catch {};
            self.cn = null;
        }
        self.reconnect_cond.signal();
    }

    // Internal functions (run in the background thread)

    fn emitEvent(self: *Listener, event: ListenerEvent, err: ?anyerror) void {
        if (self.event_callback) |cb| {
            cb(event, err);
        }
    }

    fn connect(self: *Listener) !void {
        // Create a new connection specifically for notifications
        var opts = conn.Options.init(self.allocator);
        defer {
            var it = opts.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            opts.deinit();
        }
        try conn.parseOpts(self.allocator, self.name, &opts);
        const raw_conn = try conn.dialOpen(self.allocator, self.dialer, self.name);
        errdefer raw_conn.deinit();

        // Create a notification channel for this connection
        const notif_chan = std.Thread.Channel(*Notification).init(self.allocator);
        notif_chan.capacity = 32;

        const lc = try ListenerConn.init(self.allocator, raw_conn, notif_chan);
        errdefer lc.deinit();

        // Resync: send LISTEN for all channels we think we're listening to
        var iter = self.channels.iterator();
        while (iter.next()) |entry| {
            const channel = entry.key_ptr.*;
            _ = try lc.listen(channel);
        }

        // Success: replace our current connection
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.cn) |old| old.deinit();
        self.cn = lc;
        self.notification_chan = notif_chan;
        self.reconnect_cond.signal();
    }

    fn disconnectCleanup(self: *Listener) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.cn) |lc| {
            const err = lc.getErr();
            lc.deinit();
            self.cn = null;
            if (err) |e| return e;
        }
        return error.ConnectionLost;
    }

    fn listenerMain(self: *Listener) void {
        var reconnect_interval_ms = self.min_reconnect_interval_ms;
        var next_reconnect: i64 = 0; // timestamp in milliseconds

        while (!self.is_closed) {
            // Attempt to connect
            self.connect() catch |err| {
                self.emitEvent(.connection_attempt_failed, err);
                // Wait before retrying
                std.time.sleep(reconnect_interval_ms * std.time.ns_per_ms);
                reconnect_interval_ms = @min(reconnect_interval_ms * 2, self.max_reconnect_interval_ms);
                continue;
            };

            // Connected successfully
            if (next_reconnect == 0) {
                self.emitEvent(.connected, null);
            } else {
                self.emitEvent(.reconnected, null);
            }
            reconnect_interval_ms = self.min_reconnect_interval_ms;
            next_reconnect = std.time.milliTimestamp() + @as(i64, @intCast(reconnect_interval_ms));

            // Now wait for notifications until the connection dies
            while (true) {
                self.mutex.lock();
                const cn_exists = self.cn != null;
                self.mutex.unlock();
                if (!cn_exists) break;
                std.time.sleep(100 * std.time.ns_per_ms);
            }

            // Connection lost
            const disconnect_err = self.disconnectCleanup();
            if (self.is_closed) return;
            self.emitEvent(.disconnected, disconnect_err);

            // Wait until next reconnect time
            const now = std.time.milliTimestamp();
            if (now < next_reconnect) {
                const wait_ns = (next_reconnect - now) * std.time.ns_per_ms;
                std.time.sleep(@intCast(wait_ns));
            }
        }

        // Cleanup: close the notification channel to signal the user
        self.notification_chan.close();
    }
};

fn quoteIdentifierAlloc(allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
    var buf = std.array_list.Managed(u8).init(allocator);
    defer buf.deinit();
    try buf.append('"');
    var it = std.mem.splitScalar(u8, name, '"');
    while (it.next()) |part| {
        try buf.appendSlice(part);
        if (it.index != null) try buf.append('"');
    }
    try buf.append('"');
    return buf.toOwnedSlice();
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
