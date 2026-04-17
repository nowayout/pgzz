//! PostgreSQL database connection driver.

const std = @import("std");
const oid = @import("oid.zig");
const buff = @import("buff.zig");
const url = @import("url.zig");
const userCurrent = @import("user.zig").userCurrent;
const FieldDesc = @import("rows.zig").FieldDesc;
const encode = @import("encode.zig");
const Format = encode.Format;
const scram = @import("scram/scram.zig");
const windows = std.os.windows;

// -----------------------------------------------------------------------------
// Constants and types
// -----------------------------------------------------------------------------

/// Authentication request codes
const AuthType = enum(i32) {
    Ok = 0,
    CleartextPassword = 3,
    MD5Password = 5,
    SASL = 10,
    SASLContinue = 11,
    SASLFinal = 12,
};

/// Transaction status as reported by ReadyForQuery
const TransactionStatus = enum(u8) {
    Idle = 'I',
    InTransaction = 'T',
    Failed = 'E',

    /// Returns true if the transaction is active (InTransaction or Failed)
    pub fn isInTransaction(self: TransactionStatus) bool {
        return self == .InTransaction or self == .Failed;
    }
};

/// Connection options (map of key-value strings)
pub const Options = std.StringHashMap([]const u8);

const ParseCompleteResult = struct {
    rowsAffected: i64,
    tag: []const u8,
};

const RecvResult = struct {
    typ: u8,
    buf: buff.ReadBuf,
};

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

pub const ConnError = error{
    InvalidConnectionString,
    MissingPassword,
    SSLNotSupported,
    UnexpectedMessage,
    AuthenticationFailed,
    ParseError,
    BindError,
    ExecuteError,
    TransactionFailed,
    CancelFailed,
    IoError,
    UnsupportedFeature,
    ColumnCountMismatch,
    NoMoreRows,
    UnexpectedNull,
    TypeMismatch,
    UnsupportedType,
    EndOfStream,
    InvalidParameterCount,
    InvalidColumnCount,
    UnexpectedDataRow,
    InvalidColumnLength,
    UnexpectedReady,
    StmtClosed,
    ConnectionBad,
    CopyInProgress,
};

// -----------------------------------------------------------------------------
// Dialer interface (for custom network dialing)
// -----------------------------------------------------------------------------

pub const Dialer = struct {
    dial: *const fn (allocator: std.mem.Allocator, host: []const u8, port: u16, timeout_ms: ?u32) ConnError!std.net.Stream,

    pub const default = Dialer{
        .dial = defaultDial,
    };

    fn defaultDial(allocator: std.mem.Allocator, host: []const u8, port: u16, timeout_ms: ?u32) ConnError!std.net.Stream {
        _ = timeout_ms; // TODO: implement timeout
        return std.net.tcpConnectToHost(allocator, host, port) catch |err| {
            std.debug.print("tcpConnectToHost error: {}\n", .{err});
            return error.IoError;
        };
    }
};

// -----------------------------------------------------------------------------
// Main connection structure
// -----------------------------------------------------------------------------

pub const Conn = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    socket: std.net.Stream,
    read_buffer: []u8,
    write_buffer: []u8,
    opts: Options,
    dialer: Dialer,
    processID: i32 = 0,
    secretKey: i32 = 0,
    txnStatus: TransactionStatus = .Idle,
    parameterStatus: encode.ParameterStatus = .{},
    disablePreparedBinaryResult: bool = false,
    binaryParameters: bool = false,
    bad: bool = false,
    inCopy: bool = false,
    // Saved message for workaround (see postExecuteWorkaround)
    savedMsgType: u8 = 0,
    savedMsgBuf: ?[]u8 = null,
    nameCounter: u32 = 0,
    socket_open: bool = false,
    notice_handler: ?*const fn (*Conn, []const u8) void = null,
    notification_handler: ?*const fn (*Conn, []const u8, i32, []const u8) void = null,

    /// Initializes a new connection structure without establishing network connection.
    pub fn init(allocator: std.mem.Allocator, opts: Options) !*Conn {
        return Conn{
            .allocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .socket = undefined,
            .read_buffer = &[_]u8{},
            .write_buffer = &[_]u8{},
            .opts = opts,
            .dialer = Dialer.default,
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
    }

    /// Releases all resources associated with the connection.
    pub fn deinit(self: *Conn) void {
        self.close();

        var it = self.opts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.opts.deinit();

        if (self.read_buffer.len > 0) {
            self.allocator.free(self.read_buffer);
            self.read_buffer = &[_]u8{};
        }

        if (self.write_buffer.len > 0) {
            self.allocator.free(self.write_buffer);
            self.write_buffer = &[_]u8{};
        }

        self.arena.deinit();
        self.allocator.destroy(self.arena);
        self.arena = undefined;
        self.allocator.destroy(self);
    }

    // -------------------------------------------------------------------------
    // Connection establishment
    // -------------------------------------------------------------------------

    /// Opens a connection using the default dialer.
    pub fn open(allocator: std.mem.Allocator, name: []const u8) !*Conn {
        return dialOpen(allocator, Dialer.default, name);
    }

    /// Opens a connection with a custom dialer.
    pub fn dialOpen(allocator: std.mem.Allocator, dialer: Dialer, name: []const u8) !*Conn {
        const arena_ptr = try allocator.create(std.heap.ArenaAllocator);
        arena_ptr.* = std.heap.ArenaAllocator.init(allocator);
        errdefer {
            arena_ptr.deinit();
            allocator.destroy(arena_ptr);
        }

        var opts = Options.init(allocator);
        var opts_initialized = false;
        defer if (!opts_initialized) {
            var it = opts.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                allocator.free(entry.value_ptr.*);
            }
            opts.deinit();
        };

        const arena_allocator = arena_ptr.allocator();

        // Parse URL or connection string
        var conn_str = name;
        if (std.mem.startsWith(u8, name, "postgres://") or std.mem.startsWith(u8, name, "postgresql://")) {
            const converted = try url.parseURL(arena_allocator, name);
            conn_str = converted;
        }
        try parseOptsWithDefaults(allocator, conn_str, &opts);

        // Apply environment variables (if not already set)
        try applyEnvironment(&opts);

        // Load password from .pgpass if not provided
        try loadPgPass(&opts);

        opts_initialized = true;

        // Allocate connection struct
        const cn = try allocator.create(Conn);
        cn.* = .{
            .allocator = allocator,
            .arena = arena_ptr,
            .socket = undefined,
            .read_buffer = &[_]u8{},
            .write_buffer = &[_]u8{},
            .opts = opts,
            .dialer = dialer,
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

        var success = false;
        defer if (!success) {
            if (cn.read_buffer.len > 0) allocator.free(cn.read_buffer);
            if (cn.write_buffer.len > 0) allocator.free(cn.write_buffer);
            if (cn.socket_open) cn.socket.close();
            allocator.destroy(cn);
        };

        const host = cn.opts.get("host").?;
        const port_str = cn.opts.get("port").?;
        const port = try std.fmt.parseInt(u16, port_str, 10);
        cn.socket = try dialer.dial(allocator, host, port, null);
        cn.socket_open = true;
        cn.read_buffer = try allocator.alloc(u8, 8192);
        cn.write_buffer = try allocator.alloc(u8, 8192);

        try cn.ssl();
        try cn.startup();

        success = true;
        return cn;
    }

    /// Performs SSL negotiation if required.
    fn ssl(self: *Conn) !void {
        const sslmode = self.opts.get("sslmode") orelse "disable";
        const host = self.opts.get("host") orelse "";
        if (std.mem.startsWith(u8, host, "/")) {
            return; // Unix socket, skip SSL
        }

        // Send SSLRequest message
        var request: [8]u8 = undefined;
        std.mem.writeInt(i32, request[0..4], 8, .big);
        std.mem.writeInt(i32, request[4..8], 80877103, .big);

        try self.socket.writeAll(&request);

        // Read server response (1 byte)
        var resp: [1]u8 = undefined;
        const n = try std.posix.recv(self.socket.handle, &resp, 0);
        if (n != 1) {
            std.debug.print("Failed to read SSL response, got {d} bytes\n", .{n});
            return error.SSLNotSupported;
        }

        if (resp[0] == 'S') {
            // Server supports SSL
            if (std.mem.eql(u8, sslmode, "require") or
                std.mem.eql(u8, sslmode, "verify-ca") or
                std.mem.eql(u8, sslmode, "verify-full"))
            {
                // TODO: Implement actual TLS upgrade
                // For now, we just log and continue without SSL
                std.debug.print("Server supports SSL, but TLS upgrade not implemented\n", .{});
                // In a real implementation, we would wrap the socket with TLS here
            } else {
                // Continue without SSL for disable/prefer modes
                std.debug.print("Server supports SSL, but we're not using it\n", .{});
            }
        } else if (resp[0] == 'N') {
            // Server does not support SSL
            if (std.mem.eql(u8, sslmode, "require")) {
                std.debug.print("SSL required but server doesn't support it\n", .{});
                return error.SSLNotSupported;
            }
            std.debug.print("Server does not support SSL, continuing without SSL\n", .{});
        } else {
            std.debug.print("Unexpected SSL response: 0x{x:0>2}\n", .{resp[0]});
            return error.SSLNotSupported;
        }
    }

    /// Sends startup packet and handles authentication.
    fn startup(self: *Conn) !void {
        // Build startup packet
        var packet = std.array_list.Managed(u8).init(self.allocator);
        defer packet.deinit();

        const writer = packet.writer();

        // Reserve space for length
        try writer.writeInt(i32, 0, .big);

        // Protocol version (3.0)
        try writer.writeInt(i32, 196608, .big);

        // Required parameters
        const user = self.opts.get("user") orelse "postgres";
        const dbname = self.opts.get("dbname") orelse "postgres";

        // Parameter key-value pairs
        try writer.writeAll("user");
        try writer.writeByte(0);
        try writer.writeAll(user);
        try writer.writeByte(0);

        try writer.writeAll("database");
        try writer.writeByte(0);
        try writer.writeAll(dbname);
        try writer.writeByte(0);

        // Optional parameters
        if (self.opts.get("client_encoding")) |client_encoding| {
            try writer.writeAll("client_encoding");
            try writer.writeByte(0);
            try writer.writeAll(client_encoding);
            try writer.writeByte(0);
        }

        if (self.opts.get("datestyle")) |datestyle| {
            try writer.writeAll("datestyle");
            try writer.writeByte(0);
            try writer.writeAll(datestyle);
            try writer.writeByte(0);
        }

        // Terminator
        try writer.writeByte(0);

        // Update total length
        const total_len = @as(i32, @intCast(packet.items.len));
        std.mem.writeInt(i32, packet.items[0..4], total_len, .big);

        // Send
        try self.socket.writeAll(packet.items);

        // Read response
        while (true) {
            var msg = try self.recv();
            switch (msg.typ) {
                'K' => { // BackendKeyData
                    self.processID = try msg.buf.int32();
                    self.secretKey = try msg.buf.int32();
                },
                'S' => { // ParameterStatus
                    try self.processParameterStatus(&msg.buf);
                },
                'R' => { // Authentication
                    try self.auth(&msg.buf);
                },
                'Z' => { // ReadyForQuery
                    try self.processReadyForQuery(&msg.buf);
                    return;
                },
                'E' => { // ErrorResponse
                    const err_msg = try parseErrorMessage(self.allocator, &msg.buf);
                    defer self.allocator.free(err_msg);
                    std.debug.print("Error during startup: {s}\n", .{err_msg});
                    return error.AuthenticationFailed;
                },
                else => {
                    std.debug.print("Unexpected message during startup: '{c}'\n", .{msg.typ});
                },
            }
        }
    }

    /// Handles authentication messages.
    fn auth(self: *Conn, r: *buff.ReadBuf) !void {
        const code: i32 = try r.int32();

        switch (code) {
            0 => {
                return; // OK
            },
            3 => { // Cleartext password
                const password = self.opts.get("password") orelse return error.MissingPassword;
                var msg_buf = std.array_list.Managed(u8).init(self.allocator);
                defer msg_buf.deinit();
                const writer = msg_buf.writer();
                try writer.writeByte('p');
                try writer.writeInt(i32, 0, .big);
                try writer.writeAll(password);
                try writer.writeByte(0);
                const total_len = @as(i32, @intCast(msg_buf.items.len));
                std.mem.writeInt(i32, msg_buf.items[1..5], total_len - 1, .big);
                try self.socket.writeAll(msg_buf.items);
                var resp = try self.recv();
                if (resp.typ != 'R') {
                    std.debug.print("Expected 'R' but got '{c}'\n", .{resp.typ});
                    return error.AuthenticationFailed;
                }
                const newcode = try (&resp.buf).int32();
                if (newcode != 0) {
                    std.debug.print("Authentication response code: {d}\n", .{newcode});
                    return error.AuthenticationFailed;
                }
                return;
            },
            5 => { // MD5 password
                const salt = try r.next(4);
                const password = self.opts.get("password") orelse return error.MissingPassword;
                const user = self.opts.get("user") orelse "";

                // Compute MD5
                const hash1_input = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ password, user });
                defer self.allocator.free(hash1_input);
                const hash1_hex = try md5s(self.allocator, hash1_input);
                defer self.allocator.free(hash1_hex);

                var buf = std.array_list.Managed(u8).init(self.allocator);
                defer buf.deinit();
                try buf.appendSlice(hash1_hex);
                try buf.appendSlice(salt);

                var hash2_raw: [16]u8 = undefined;
                std.crypto.hash.Md5.hash(buf.items, &hash2_raw, .{});
                const hash2_hex = std.fmt.bytesToHex(&hash2_raw, .lower);
                const response = try std.fmt.allocPrint(self.allocator, "md5{s}", .{hash2_hex});
                defer self.allocator.free(response);

                // Build password message
                var msg_buf = std.array_list.Managed(u8).init(self.allocator);
                defer msg_buf.deinit();
                const writer = msg_buf.writer();

                try writer.writeByte('p');
                try writer.writeInt(i32, 0, .big);
                try writer.writeAll(response);
                try writer.writeByte(0);

                const total_len = @as(i32, @intCast(msg_buf.items.len));
                std.mem.writeInt(i32, msg_buf.items[1..5], total_len - 1, .big);
                try self.socket.writeAll(msg_buf.items);

                // Handle authentication response
                var resp = try self.recv();

                if (resp.typ != 'R') {
                    std.debug.print("Expected 'R' but got '{c}'\n", .{resp.typ});
                    return error.AuthenticationFailed;
                }

                const newcode = try (&resp.buf).int32();
                if (newcode != 0) {
                    std.debug.print("Authentication failed with code: {d}\n", .{newcode});
                    return error.AuthenticationFailed;
                }
                return;
            },
            10 => { // SASL (SCRAM-SHA-256)
                // Parse mechanisms from the message
                const mechanisms = try r.string();
                _ = mechanisms; // We only support SCRAM-SHA-256
                const user = self.opts.get("user") orelse return error.MissingPassword;
                const password = self.opts.get("password") orelse return error.MissingPassword;

                // Create SCRAM client (SHA-256)
                var scram_client = scram.Client(scram.HashAlg).init(self.allocator, user, password) catch return error.AuthenticationFailed;
                defer scram_client.deinit();

                // Step 1: send client-first message
                var finished = try scram_client.step("");
                while (!finished) {
                    const out = scram_client.out();
                    // Send SASLInitialResponse
                    var msg_buf = std.array_list.Managed(u8).init(self.allocator);
                    defer msg_buf.deinit();
                    const writer = msg_buf.writer();
                    try writer.writeByte('p');
                    try writer.writeInt(i32, 0, .big);
                    try writer.writeAll("SCRAM-SHA-256");
                    try writer.writeByte(0);
                    try writer.writeInt(i32, @intCast(out.len), .big);
                    try writer.writeAll(out);
                    const total_len = @as(i32, @intCast(msg_buf.items.len));
                    std.mem.writeInt(i32, msg_buf.items[1..5], total_len - 1, .big);
                    try self.socket.writeAll(msg_buf.items);

                    // Receive server response
                    var resp = try self.recv();
                    if (resp.typ != 'R') {
                        std.debug.print("Expected 'R' during SCRAM, got '{c}'\n", .{resp.typ});
                        return error.AuthenticationFailed;
                    }
                    const auth_code = try (&resp.buf).int32();
                    if (auth_code == 11) { // SASLContinue
                        const server_data = try (&resp.buf).string();
                        finished = try scram_client.step(server_data);
                        if (scram_client.err() != null) {
                            std.debug.print("SCRAM error: {any}\n", .{scram_client.err()});
                            return error.AuthenticationFailed;
                        }
                    } else if (auth_code == 12) { // SASLFinal
                        const server_data = try (&resp.buf).string();
                        _ = try scram_client.step(server_data);
                        if (scram_client.err() != null) {
                            std.debug.print("SCRAM final error: {any}\n", .{scram_client.err()});
                            return error.AuthenticationFailed;
                        }
                        break;
                    } else {
                        std.debug.print("Unexpected SASL response code: {d}\n", .{auth_code});
                        return error.AuthenticationFailed;
                    }
                }
                // After SASLFinal, we should receive AuthenticationOk
                var final_resp = try self.recv();
                if (final_resp.typ != 'R') {
                    std.debug.print("Expected final AuthenticationOk, got '{c}'\n", .{final_resp.typ});
                    return error.AuthenticationFailed;
                }
                const final_code = try (&final_resp.buf).int32();
                if (final_code != 0) {
                    std.debug.print("Final authentication code: {d}\n", .{final_code});
                    return error.AuthenticationFailed;
                }
                return;
            },
            else => {
                std.debug.print("Unsupported authentication method: {d}\n", .{code});
                return error.AuthenticationFailed;
            },
        }
    }

    fn processBackendKeyData(self: *Conn, r: *buff.ReadBuf) !void {
        self.processID = try r.int32();
        self.secretKey = try r.int32();
    }

    fn processParameterStatus(self: *Conn, r: *buff.ReadBuf) !void {
        const remaining = r.data.len;
        if (remaining < 2) {
            std.debug.print("Error: Not enough data for param/value, remaining={d}\n", .{remaining});
            return error.UnexpectedMessage;
        }

        const param = try r.string();
        const value = try r.string();

        const param_dup = try self.allocator.dupe(u8, param);
        defer self.allocator.free(param_dup);
        const value_dup = try self.allocator.dupe(u8, value);
        defer self.allocator.free(value_dup);

        if (std.mem.eql(u8, param_dup, "server_version")) {
            // Parse version into integer
            var parts = std.mem.splitScalar(u8, value_dup, '.');
            var major1: i32 = 0;
            var major2: i32 = 0;
            var minor: i32 = 0;
            if (parts.next()) |p| major1 = std.fmt.parseInt(i32, p, 10) catch 0;
            if (parts.next()) |p| major2 = std.fmt.parseInt(i32, p, 10) catch 0;
            if (parts.next()) |p| minor = std.fmt.parseInt(i32, p, 10) catch 0;
            self.parameterStatus.serverVersion = major1 * 10000 + major2 * 100 + minor;
        } else if (std.mem.eql(u8, param_dup, "TimeZone")) {
            // Load location (simplified, skip)
        }
    }

    fn processReadyForQuery(self: *Conn, r: *buff.ReadBuf) !void {
        const status = try r.byte();
        self.txnStatus = @enumFromInt(status);
    }

    // -------------------------------------------------------------------------
    // Message sending/receiving
    // -------------------------------------------------------------------------

    fn send(self: *Conn, w: *buff.WriteBuf) !void {
        const data = try w.wrap();
        var total_written: usize = 0;
        while (total_written < data.len) {
            const n = try self.socket.write(data[total_written..]);
            total_written += n;
        }
    }

    fn readFull(self: *Conn, buf: []u8) !void {
        var total: usize = 0;

        while (total < buf.len) {
            const n = try std.posix.recv(self.socket.handle, buf[total..], 0);

            if (n == 0) {
                self.bad = true;
                return error.EndOfStream;
            }
            total += n;
        }
    }

    fn recv(self: *Conn) !RecvResult {
        if (self.savedMsgType != 0) {
            const typ = self.savedMsgType;
            const data = self.savedMsgBuf orelse &[_]u8{};
            self.savedMsgType = 0;
            self.savedMsgBuf = null;
            return .{ .typ = typ, .buf = buff.ReadBuf.init(data) };
        }

        // Read message header
        var header align(4) = [_]u8{0} ** 5;
        try self.readFull(&header);

        const typ = header[0];
        const len = std.mem.readInt(i32, header[1..5], .big) - 4;

        if (len < 0) return error.UnexpectedMessage;

        if (len > 0) {
            const payload = try self.arena.allocator().alloc(u8, @intCast(len));

            try self.readFull(payload);
            return .{ .typ = typ, .buf = buff.ReadBuf.init(payload) };
        } else {
            return .{ .typ = typ, .buf = buff.ReadBuf.init(&[_]u8{}) };
        }
    }

    fn recvUntilReady(self: *Conn) !void {
        while (true) {
            var msg = try self.recv();
            switch (msg.typ) {
                'Z' => {
                    try self.processReadyForQuery(&msg.buf);
                    return;
                },
                'E' => return error.ParseError,
                else => continue,
            }
        }
    }

    // -------------------------------------------------------------------------
    // Simple query execution
    // -------------------------------------------------------------------------

    /// Executes a simple query (no parameters) and returns command completion info.
    pub fn exec(self: *Conn, _query: []const u8) !ParseCompleteResult {
        if (self.bad) return error.ConnectionBad;
        if (self.inCopy) return error.CopyInProgress;

        var w = buff.WriteBuf.init(self.allocator);
        defer w.deinit();
        try w.next('Q');
        try w.string(_query);
        try self.send(&w);

        var res: ?ParseCompleteResult = null;
        var err: ?ConnError = null;
        errdefer if (res) |r| self.allocator.free(r.tag);

        while (true) {
            var msg = try self.recv();
            switch (msg.typ) {
                'C' => {
                    const tag = try msg.buf.string();
                    const parsed = try self.parseComplete(tag);
                    res = .{ .rowsAffected = parsed.rowsAffected, .tag = parsed.tag };
                },
                'Z' => {
                    try self.processReadyForQuery(&msg.buf);
                    if (err) |e| return e;
                    if (res == null) return error.UnexpectedReady;
                    return res.?;
                },
                'E' => {
                    const err_msg = try parseErrorMessage(self.allocator, &msg.buf);
                    defer self.allocator.free(err_msg);
                    std.debug.print("Query error: {s}\n", .{err_msg});
                    err = error.ParseError;
                    return error.ParseError;
                },
                'I' => {
                    res = .{ .rowsAffected = 0, .tag = "" };
                },
                'T', 'D' => {
                    // Ignore result rows for simple query
                },
                'S' => {
                    try self.processParameterStatus(&msg.buf);
                },
                'A' => {
                    if (self.notification_handler) |handler| {
                        const pid = try msg.buf.int32();
                        const channel = try msg.buf.string();
                        const payload = try msg.buf.string();
                        handler(self, channel, pid, payload);
                    }
                },
                'N' => {
                    if (self.notice_handler) |handler| {
                        const err_msg = try parseErrorMessage(self.allocator, &msg.buf);
                        defer self.allocator.free(err_msg);
                        handler(self, err_msg);
                    }
                },
                else => {
                    std.debug.print("Unexpected message type: '{c}' (0x{x:0>2})\n", .{ msg.typ, msg.typ });
                    return error.UnexpectedMessage;
                },
            }
        }
    }

    /// Executes a query and returns a Rows iterator for fetching results.
    pub fn query(self: *Conn, _query: []const u8) !*Rows {
        if (self.bad) return error.ConnectionBad;
        if (self.inCopy) return error.CopyInProgress;

        var w = buff.WriteBuf.init(self.allocator);
        defer w.deinit();
        try w.next('Q');
        try w.string(_query);
        try self.send(&w);

        var rows = try Rows.init(self);
        errdefer rows.deinit();

        while (true) {
            var msg = try self.recv();
            switch (msg.typ) {
                'T' => {
                    try rows.parseRowDescription(&msg.buf);
                },
                'D' => {
                    if (rows.colNames.len == 0) return error.UnexpectedDataRow;
                    self.saveMessage(msg.typ, msg.buf);
                    return rows;
                },
                'C', 'I' => {
                    if (msg.typ == 'C') {
                        const tag = try msg.buf.string();
                        const tag_dup = try self.allocator.dupe(u8, tag);
                        defer self.allocator.free(tag_dup);
                        const parsed = try self.parseComplete(tag_dup);
                        rows.result = parsed;
                    }
                    rows.done = true;
                },
                'Z' => {
                    try self.processReadyForQuery(&msg.buf);
                    if (rows.colNames.len == 0) {
                        rows.done = true;
                        return rows;
                    }
                },
                'E' => {
                    const err_msg = try parseErrorMessage(self.allocator, &msg.buf);
                    defer self.allocator.free(err_msg);
                    return error.ParseError;
                },
                else => return error.UnexpectedMessage,
            }
        }
    }

    // -------------------------------------------------------------------------
    // Prepared statements
    // -------------------------------------------------------------------------

    /// Prepares a statement for later execution.
    pub fn prepare(self: *Conn, _query: []const u8) !*Stmt {
        if (self.bad) return error.ConnectionBad;
        const name = try self.nextName();
        defer self.allocator.free(name);
        var stmt = try Stmt.init(self, name, _query);
        errdefer stmt.deinit();
        try stmt.prepare();
        return stmt;
    }

    fn nextName(self: *Conn) ![]const u8 {
        self.nameCounter += 1;
        return try std.fmt.allocPrint(self.allocator, "stmt_{d}", .{self.nameCounter});
    }

    // -------------------------------------------------------------------------
    // Transaction handling
    // -------------------------------------------------------------------------

    /// Begins a new transaction.
    pub fn begin(self: *Conn) !void {
        const res = try self.exec("BEGIN");
        defer self.allocator.free(res.tag);
        if (!std.mem.eql(u8, res.tag, "BEGIN")) return error.UnexpectedMessage;
        if (self.txnStatus != .InTransaction) return error.UnexpectedTransactionStatus;
    }

    /// Commits the current transaction.
    pub fn commit(self: *Conn) !void {
        if (self.txnStatus == .Failed) {
            const res = try self.exec("ROLLBACK");
            defer self.allocator.free(res.tag);
            return error.TransactionFailed;
        }
        const res = try self.exec("COMMIT");
        defer self.allocator.free(res.tag);
        if (!std.mem.eql(u8, res.tag, "COMMIT")) return error.UnexpectedMessage;
        if (self.txnStatus != .Idle) return error.UnexpectedTransactionStatus;
    }

    /// Rolls back the current transaction.
    pub fn rollback(self: *Conn) !void {
        const res = try self.exec("ROLLBACK");
        defer self.allocator.free(res.tag);
        if (!std.mem.eql(u8, res.tag, "ROLLBACK")) return error.UnexpectedMessage;
        if (self.txnStatus != .Idle) return error.UnexpectedTransactionStatus;
    }

    // -------------------------------------------------------------------------
    // Cancel request (context cancellation)
    // -------------------------------------------------------------------------

    /// Sends a cancel request to the server for the currently executing command.
    pub fn cancel(self: *Conn) !void {
        // Create a new connection just for cancel
        var cancel_conn = try Conn.dialOpen(self.allocator, self.dialer, "");
        defer cancel_conn.deinit();
        var w = buff.WriteBuf.init(self.allocator);
        defer w.deinit();
        try w.int32(80877102); // cancel request code
        try w.int32(self.processID);
        try w.int32(self.secretKey);
        const packet = try w.wrap();
        // Cancel request does not have a message type byte
        try cancel_conn.socket.writeAll(packet[1..]);
        // Read until EOF
        var buf2: [1024]u8 = undefined;
        while (true) {
            cancel_conn.socket.read(&buf2) catch break;
        }
    }

    // -----------------------------------------------------------------------------
    // Additional methods referenced in the code
    // -----------------------------------------------------------------------------

    /// Reads the parse response (ParseComplete or Error).
    pub fn readParseResponse(self: *Conn) !void {
        var msg = try self.recv();
        switch (msg.typ) {
            '1' => return,
            'E' => {
                const err_msg = try parseErrorMessage(self.allocator, &msg.buf);
                defer self.allocator.free(err_msg);
                try self.readReadyForQuery();
                return error.ParseError;
            },
            else => return error.UnexpectedMessage,
        }
    }

    /// Reads a ReadyForQuery message.
    pub fn readReadyForQuery(self: *Conn) !void {
        var msg = try self.recv();
        if (msg.typ != 'Z') return error.UnexpectedMessage;
        try self.processReadyForQuery(&msg.buf);
    }

    /// Reads the describe response for a prepared statement.
    pub fn readStatementDescribeResponse(self: *Conn, stmt: *Stmt) !void {
        while (true) {
            var msg = try self.recv();
            switch (msg.typ) {
                't' => {
                    const nparams = try msg.buf.int16();
                    if (nparams < 0) return error.InvalidParameterCount;
                    stmt.paramTyps = try self.allocator.alloc(oid.Oid, @intCast(nparams));
                    for (0..@intCast(nparams)) |i| {
                        stmt.paramTyps[i] = try msg.buf.oid();
                    }
                },
                'n' => {
                    stmt.colNames = &[_][]const u8{};
                    stmt.colTyps = &[_]FieldDesc{};
                    return;
                },
                'T' => {
                    const ncols = try msg.buf.int16();
                    if (ncols < 0) return error.InvalidColumnCount;
                    stmt.colNames = try self.allocator.alloc([]const u8, @intCast(ncols));
                    stmt.colTyps = try self.allocator.alloc(FieldDesc, @intCast(ncols));
                    for (0..@intCast(ncols)) |i| {
                        stmt.colNames[i] = try msg.buf.string();
                        _ = try msg.buf.next(6);
                        stmt.colTyps[i].oid = try msg.buf.oid();
                        stmt.colTyps[i].len = try msg.buf.int16();
                        stmt.colTyps[i].mod = try msg.buf.int32();
                        _ = try msg.buf.int16();
                    }
                    stmt.colFmts = try self.allocator.alloc(Format, @intCast(ncols));
                    stmt.colFmtData = try decideColumnFormats(self.allocator, stmt.colTyps, self.disablePreparedBinaryResult);
                    return;
                },
                'E' => {
                    const err_msg = try parseErrorMessage(self.allocator, &msg.buf);
                    defer self.allocator.free(err_msg);
                    try self.readReadyForQuery();
                    return error.ParseError;
                },
                else => return error.UnexpectedMessage,
            }
        }
    }

    /// Reads the bind response (BindComplete or Error).
    pub fn readBindResponse(self: *Conn) !void {
        var msg = try self.recv();
        switch (msg.typ) {
            '2' => return,
            'E' => {
                const err_msg = try parseErrorMessage(self.allocator, &msg.buf);
                defer self.allocator.free(err_msg);
                try self.readReadyForQuery();
                return error.BindError;
            },
            else => return error.UnexpectedMessage,
        }
    }

    /// Reads the execute response (CommandComplete, Error, etc.).
    pub fn readExecuteResponse(self: *Conn) !ParseCompleteResult {
        while (true) {
            var msg = try self.recv();
            switch (msg.typ) {
                'C' => {
                    const tag = try msg.buf.string();
                    const parsed = try self.parseComplete(tag);
                    const tag_dup = try self.allocator.dupe(u8, parsed.tag);
                    return .{ .rowsAffected = parsed.rowsAffected, .tag = tag_dup };
                },
                'Z' => {
                    try self.processReadyForQuery(&msg.buf);
                    return error.UnexpectedReady;
                },
                'E' => {
                    const err_msg = try parseErrorMessage(self.allocator, &msg.buf);
                    defer self.allocator.free(err_msg);
                    return error.ExecuteError;
                },
                'T', 'D', 'I' => {
                    // ignore
                },
                else => return error.UnexpectedMessage,
            }
        }
    }

    /// Receives one message, ignoring notices and parameter status updates.
    pub fn recv1(self: *Conn) !RecvResult {
        while (true) {
            var msg = try self.recv();
            switch (msg.typ) {
                'A', 'N' => continue,
                'S' => {
                    try self.processParameterStatus(&msg.buf);
                    continue;
                },
                else => return msg,
            }
        }
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    fn parseComplete(self: *Conn, tag: []const u8) !ParseCompleteResult {
        const commands = [_][]const u8{ "SELECT ", "UPDATE ", "DELETE ", "FETCH ", "MOVE ", "COPY ", "INSERT " };
        for (commands) |cmd| {
            if (std.mem.startsWith(u8, tag, cmd)) {
                const num_part = tag[cmd.len..];
                const n = std.fmt.parseInt(i64, num_part, 10) catch 0;
                const tag_dup = try self.allocator.dupe(u8, cmd[0 .. cmd.len - 1]);
                return .{ .rowsAffected = n, .tag = tag_dup };
            }
        }
        if (std.mem.startsWith(u8, tag, "INSERT ")) {
            var parts = std.mem.splitScalar(u8, tag, ' ');
            _ = parts.next(); // "INSERT"
            _ = parts.next(); // oid
            const rows = parts.next() orelse "0";
            const n = std.fmt.parseInt(i64, rows, 10) catch 0;
            const tag_dup = try self.allocator.dupe(u8, "INSERT");
            return .{ .rowsAffected = n, .tag = tag_dup };
        }
        const tag_dup = try self.allocator.dupe(u8, tag);
        return .{ .rowsAffected = 0, .tag = tag_dup };
    }

    fn saveMessage(self: *Conn, typ: u8, r: buff.ReadBuf) void {
        if (self.savedMsgType != 0) @panic("saveMessage called twice");
        self.savedMsgType = typ;
        self.savedMsgBuf = self.arena.allocator().dupe(u8, r.data) catch @panic("OOM");
    }

    /// Closes the connection gracefully.
    pub fn close(self: *Conn) void {
        if (self.bad) {
            return;
        }

        self.bad = true;

        const stream_handle = self.socket.handle;

        var msg_buf: [5]u8 = undefined;
        msg_buf[0] = 'X';
        std.mem.writeInt(i32, msg_buf[1..5], 4, .big);

        _ = std.posix.send(stream_handle, &msg_buf, 0) catch {};
        self.socket.close();
    }
};

// -----------------------------------------------------------------------------
// Rows result set
// -----------------------------------------------------------------------------

/// Iterator over query result rows.
pub const Rows = struct {
    conn: *Conn,
    colNames: [][]const u8 = &[_][]const u8{},
    colFmts: []Format = &[_]Format{},
    colTyps: []FieldDesc = &[_]FieldDesc{},
    done: bool = false,
    result: ?ParseCompleteResult = null,
    allocated: std.ArrayListUnmanaged([]const u8) = .{},
    nextRows: ?*Rows = null, // For multiple result sets

    pub fn init(conn: *Conn) !*Rows {
        const rows = try conn.allocator.create(Rows);
        rows.* = .{
            .conn = conn,
            .colNames = &[_][]const u8{},
            .colFmts = &[_]Format{},
            .colTyps = &[_]FieldDesc{},
            .allocated = .{},
            .result = null,
            .nextRows = null,
        };
        return rows;
    }

    pub fn deinit(self: *Rows) void {
        if (self.result) |res| {
            self.conn.allocator.free(res.tag);
        }
        for (self.allocated.items) |item| {
            self.conn.allocator.free(item);
        }
        self.allocated.deinit(self.conn.allocator);

        if (self.colNames.len > 0) {
            for (self.colNames) |name| {
                self.conn.allocator.free(name);
            }
            self.conn.allocator.free(self.colNames);
        }
        if (self.colFmts.len > 0) {
            self.conn.allocator.free(self.colFmts);
        }
        if (self.colTyps.len > 0) {
            self.conn.allocator.free(self.colTyps);
        }
        if (self.nextRows) |_next| _next.deinit();
        self.conn.allocator.destroy(self);
    }

    fn parseRowDescription(self: *Rows, r: *buff.ReadBuf) !void {
        const n_raw = try r.int16();
        if (n_raw < 0) return error.InvalidColumnCount;
        const n = @as(usize, @intCast(n_raw));
        self.colNames = try self.conn.allocator.alloc([]const u8, n);
        self.colFmts = try self.conn.allocator.alloc(Format, n);
        self.colTyps = try self.conn.allocator.alloc(FieldDesc, n);
        for (0..n) |i| {
            const name = try r.string();
            self.colNames[i] = try self.conn.allocator.dupe(u8, name);
            _ = try r.next(6); // table OID, column number
            self.colTyps[i].oid = try r.oid();
            self.colTyps[i].len = try r.int16();
            self.colTyps[i].mod = try r.int32();
            const format_code = try r.int16();
            self.colFmts[i] = if (format_code == 1) .binary else .text;
        }
    }

    /// Fetches the next row into a slice of nullable byte slices.
    /// Returns false when no more rows.
    pub fn next(self: *Rows, dest: []?[]const u8) !bool {
        if (self.done) return false;
        if (self.conn.bad) return error.ConnectionBad;

        while (true) {
            var msg = try self.conn.recv();
            switch (msg.typ) {
                'D' => {
                    const ncols = try msg.buf.int16();
                    if (ncols < 0) return error.InvalidColumnCount;
                    if (ncols != self.colNames.len) return error.ColumnCountMismatch;
                    for (0..@intCast(ncols)) |i| {
                        const len = try msg.buf.int32();
                        if (len < -1) return error.InvalidColumnLength;
                        if (len == -1) {
                            dest[i] = null;
                        } else {
                            const data = try msg.buf.next(@intCast(len));
                            if (self.colFmts[i] == .binary) {
                                const typ = self.colTyps[i].oid;
                                const text = switch (typ) {
                                    oid.T_int2, oid.T_int4, oid.T_int8 => blk: {
                                        const value = switch (typ) {
                                            oid.T_int2 => std.mem.readInt(i16, data[0..2], .big),
                                            oid.T_int4 => std.mem.readInt(i32, data[0..4], .big),
                                            oid.T_int8 => std.mem.readInt(i64, data[0..8], .big),
                                            else => unreachable,
                                        };
                                        break :blk try std.fmt.allocPrint(self.conn.allocator, "{d}", .{value});
                                    },
                                    else => try self.conn.allocator.dupe(u8, data),
                                };
                                dest[i] = text;
                                try self.allocated.append(self.conn.allocator, text);
                            } else {
                                const duped = try self.conn.allocator.dupe(u8, data);
                                dest[i] = duped;
                                try self.allocated.append(self.conn.allocator, duped);
                            }
                        }
                    }
                    return true;
                },
                'C' => {
                    if (msg.buf.data.len == 0) return error.UnexpectedEmptyMessage;
                    const tag = try msg.buf.string();
                    const parsed = try self.conn.parseComplete(tag);
                    if (self.result) |old| self.conn.allocator.free(old.tag);
                    self.result = parsed;
                    self.done = true;
                },
                'Z' => {
                    try self.conn.processReadyForQuery(&msg.buf);
                    self.done = true;
                    return false;
                },
                'E' => {
                    const err_msg = try parseErrorMessage(self.conn.allocator, &msg.buf);
                    defer self.conn.allocator.free(err_msg);
                    return error.ParseError;
                },
                'T' => {
                    // Next result set description
                    var nextRows = try Rows.init(self.conn);
                    try nextRows.parseRowDescription(&msg.buf);
                    self.nextRows = nextRows;
                    self.done = true;
                    return false;
                },
                else => return error.UnexpectedMessage,
            }
        }
    }

    /// Returns the column names.
    pub fn columns(self: *Rows) [][]const u8 {
        return self.colNames;
    }

    /// Checks if there is another result set.
    pub fn hasNextResultSet(self: *Rows) bool {
        return self.nextRows != null and !self.done;
    }

    /// Moves to the next result set.
    pub fn nextResultSet(self: *Rows) !void {
        if (self.nextRows == null) return error.NoMoreRows;
        const _next = self.nextRows.?;
        self.colNames = _next.colNames;
        self.colFmts = _next.colFmts;
        self.colTyps = _next.colTyps;
        self.result = _next.result;
        self.done = false;
        self.nextRows = _next.nextRows;
        // Transfer ownership of allocations
        _next.colNames = &[_][]const u8{};
        _next.colFmts = &[_]Format{};
        _next.colTyps = &[_]FieldDesc{};
        _next.result = null;
        _next.nextRows = null;
        _next.deinit();
    }

    /// Scans the next row into a struct.
    pub fn scan(self: *Rows, comptime T: type, dest: *T, allocator: std.mem.Allocator) !void {
        const fields = std.meta.fields(T);
        if (fields.len != self.colNames.len) return error.ColumnCountMismatch;

        var raw_vals: [fields.len]?[]const u8 = undefined;
        if (!try self.next(&raw_vals)) return error.NoMoreRows;

        var temp_allocations = std.array_list.Managed([]const u8).init(allocator);
        errdefer {
            for (temp_allocations.items) |item| allocator.free(item);
            temp_allocations.deinit();
        }

        inline for (fields, 0..) |field, i| {
            const raw = raw_vals[i];
            const col_typ = self.colTyps[i];
            const col_fmt = self.colFmts[i];
            const target_type = field.type;

            if (raw == null) {
                if (@typeInfo(target_type) == .optional) {
                    @field(dest, field.name) = null;
                } else {
                    return error.UnexpectedNull;
                }
            } else {
                const decoded = try encode.decode(allocator, &self.conn.parameterStatus, raw.?, col_typ.oid, col_fmt);
                defer decoded.deinit(allocator);

                switch (decoded) {
                    .int => |val| {
                        if (@typeInfo(target_type) == .int or @typeInfo(target_type) == .comptime_int) {
                            @field(dest, field.name) = @as(target_type, @intCast(val));
                        } else if (@typeInfo(target_type) == .optional) {
                            const child = @typeInfo(target_type).optional.child;
                            if (@typeInfo(child) == .int or @typeInfo(child) == .comptime_int) {
                                @field(dest, field.name) = @as(child, @intCast(val));
                            } else {
                                return error.TypeMismatch;
                            }
                        } else {
                            return error.TypeMismatch;
                        }
                    },
                    .float => |val| {
                        if (target_type == f64 or target_type == f32) {
                            @field(dest, field.name) = @as(target_type, val);
                        } else if (@typeInfo(target_type) == .optional) {
                            const child = @typeInfo(target_type).optional.child;
                            if (child == f64 or child == f32) {
                                @field(dest, field.name) = @as(child, val);
                            } else {
                                return error.TypeMismatch;
                            }
                        } else {
                            return error.TypeMismatch;
                        }
                    },
                    .bool => |val| {
                        if (target_type == bool) {
                            @field(dest, field.name) = val;
                        } else if (@typeInfo(target_type) == .optional and @typeInfo(target_type).optional.child == bool) {
                            @field(dest, field.name) = val;
                        } else {
                            return error.TypeMismatch;
                        }
                    },
                    .string => |val| {
                        const duped = try allocator.dupe(u8, val);
                        try temp_allocations.append(duped);
                        if (target_type == []const u8) {
                            @field(dest, field.name) = duped;
                        } else if (@typeInfo(target_type) == .optional and @typeInfo(target_type).optional.child == []const u8) {
                            @field(dest, field.name) = duped;
                        } else {
                            return error.TypeMismatch;
                        }
                    },
                    .bytes => |val| {
                        const duped = try allocator.dupe(u8, val);
                        try temp_allocations.append(duped);
                        if (target_type == []u8) {
                            @field(dest, field.name) = duped;
                        } else if (@typeInfo(target_type) == .optional and @typeInfo(target_type).optional.child == []u8) {
                            @field(dest, field.name) = duped;
                        } else {
                            return error.TypeMismatch;
                        }
                    },
                    .timestamp => |val| {
                        if (target_type == i128) {
                            @field(dest, field.name) = val;
                        } else if (@typeInfo(target_type) == .optional and @typeInfo(target_type).optional.child == i128) {
                            @field(dest, field.name) = val;
                        } else {
                            return error.TypeMismatch;
                        }
                    },
                    else => return error.UnsupportedType,
                }
            }
        }
        temp_allocations.clearAndFree();
    }
};

// -----------------------------------------------------------------------------
// Prepared statement
// -----------------------------------------------------------------------------

/// Represents a prepared statement.
pub const Stmt = struct {
    conn: *Conn,
    name: []const u8,
    _query: []const u8,
    paramTyps: []oid.Oid = &[_]oid.Oid{},
    colNames: [][]const u8 = &[_][]const u8{},
    colTyps: []FieldDesc = &[_]FieldDesc{},
    colFmts: []Format = &[_]Format{},
    colFmtData: []u8 = &[_]u8{},
    closed: bool = false,

    pub fn init(conn: *Conn, name: []const u8, _query: []const u8) !*Stmt {
        const stmt = try conn.allocator.create(Stmt);
        stmt.* = .{
            .conn = conn,
            .name = try conn.allocator.dupe(u8, name),
            ._query = try conn.allocator.dupe(u8, _query),
        };
        return stmt;
    }

    pub fn deinit(self: *Stmt) void {
        self.conn.allocator.free(self.name);
        self.conn.allocator.free(self._query);

        if (self.paramTyps.len > 0) {
            self.conn.allocator.free(self.paramTyps);
        }

        if (self.colNames.len > 0) {
            for (self.colNames) |name| {
                self.conn.allocator.free(name);
            }
            self.conn.allocator.free(self.colNames);
        }

        if (self.colTyps.len > 0) {
            self.conn.allocator.free(self.colTyps);
        }

        if (self.colFmts.len > 0) {
            self.conn.allocator.free(self.colFmts);
        }

        if (self.colFmtData.len > 0) {
            self.conn.allocator.free(self.colFmtData);
        }

        self.conn.allocator.destroy(self);
    }

    fn prepare(self: *Stmt) !void {
        // Send Parse
        {
            var w = buff.WriteBuf.init(self.conn.allocator);
            defer w.deinit();
            try w.next('P');
            try w.string(self.name);
            try w.string(self._query);
            try w.int16(0);
            try self.conn.send(&w);
        }

        // Send Describe (statement)
        {
            var w = buff.WriteBuf.init(self.conn.allocator);
            defer w.deinit();
            try w.next('D');
            try w.byte('S');
            try w.string(self.name);
            try self.conn.send(&w);
        }

        // Send Sync
        {
            var w = buff.WriteBuf.init(self.conn.allocator);
            defer w.deinit();
            try w.next('S');
            try self.conn.send(&w);
        }

        var parse_done = false;
        while (true) {
            var msg = try self.conn.recv();

            switch (msg.typ) {
                '1' => {
                    parse_done = true;
                },
                't' => {
                    const nparams = try msg.buf.int16();
                    if (nparams < 0) return error.InvalidParameterCount;
                    self.paramTyps = try self.conn.allocator.alloc(oid.Oid, @intCast(nparams));
                    for (0..@intCast(nparams)) |i| {
                        self.paramTyps[i] = try msg.buf.oid();
                    }
                },
                'n' => {
                    // No result columns
                    self.colNames = &[_][]const u8{};
                    self.colTyps = &[_]FieldDesc{};
                    self.colFmts = &[_]Format{};
                    self.colFmtData = try self.conn.allocator.alloc(u8, 2);
                    self.colFmtData[0] = 0;
                    self.colFmtData[1] = 0;
                },
                'T' => {
                    const ncols = try msg.buf.int16();
                    if (ncols < 0) return error.InvalidColumnCount;
                    const n = @as(usize, @intCast(ncols));
                    self.colNames = try self.conn.allocator.alloc([]const u8, n);
                    self.colTyps = try self.conn.allocator.alloc(FieldDesc, n);
                    for (0..n) |i| {
                        const name = try msg.buf.string();
                        self.colNames[i] = try self.conn.allocator.dupe(u8, name);
                        _ = try msg.buf.next(6);
                        self.colTyps[i].oid = try msg.buf.oid();
                        self.colTyps[i].len = try msg.buf.int16();
                        self.colTyps[i].mod = try msg.buf.int32();
                        _ = try msg.buf.int16();
                    }
                    self.colFmts = try self.conn.allocator.alloc(Format, n);
                    self.colFmtData = try decideColumnFormats(self.conn.allocator, self.colTyps, self.conn.disablePreparedBinaryResult);
                },
                'Z' => {
                    try self.conn.processReadyForQuery(&msg.buf);
                    if (!parse_done) return error.UnexpectedReady;
                    return;
                },
                'E' => {
                    const err_msg = try parseErrorMessage(self.conn.allocator, &msg.buf);
                    defer self.conn.allocator.free(err_msg);
                    std.debug.print("Prepare error: {s}\n", .{err_msg});
                    return error.ParseError;
                },
                'S', 'N', 'A' => {
                    if (msg.typ == 'S') try self.conn.processParameterStatus(&msg.buf);
                },
                else => {
                    std.debug.print("Unexpected message in prepare: '{c}'\n", .{msg.typ});
                    return error.UnexpectedMessage;
                },
            }
        }
    }

    /// Executes the prepared statement with the given parameters.
    pub fn exec(self: *Stmt, args: []const []const u8) !ParseCompleteResult {
        if (self.closed) return error.StmtClosed;
        if (self.conn.bad) return error.ConnectionBad;

        // Bind
        {
            var w = buff.WriteBuf.init(self.conn.allocator);
            defer w.deinit();
            try w.next('B');
            try w.byte(0); // unnamed portal
            try w.string(self.name);
            try w.int16(0); // parameter formats: all text
            try w.int16(@intCast(args.len));
            for (args) |arg| {
                try w.int32(@intCast(arg.len));
                try w.bytes(arg);
            }
            try w.bytes(self.colFmtData);
            try self.conn.send(&w);
        }

        // Execute
        {
            var w = buff.WriteBuf.init(self.conn.allocator);
            defer w.deinit();
            try w.next('E');
            try w.byte(0); // unnamed portal
            try w.int32(0); // max rows (0 = all)
            try self.conn.send(&w);
        }

        // Sync
        {
            var w = buff.WriteBuf.init(self.conn.allocator);
            defer w.deinit();
            try w.next('S');
            try self.conn.send(&w);
        }

        var bind_done = false;
        var result: ?ParseCompleteResult = null;
        errdefer if (result) |r| self.conn.allocator.free(r.tag);

        while (true) {
            var msg = try self.conn.recv();

            switch (msg.typ) {
                '2' => bind_done = true,
                'C' => {
                    if (msg.buf.data.len == 0) return error.UnexpectedEmptyMessage;
                    const tag = try msg.buf.string();
                    const parsed = try self.conn.parseComplete(tag);
                    result = .{ .rowsAffected = parsed.rowsAffected, .tag = parsed.tag };
                },
                'Z' => {
                    try self.conn.processReadyForQuery(&msg.buf);
                    if (!bind_done) return error.UnexpectedReady;
                    if (result == null) return error.UnexpectedReady;
                    return result.?;
                },
                'E' => {
                    const err_msg = try parseErrorMessage(self.conn.allocator, &msg.buf);
                    defer self.conn.allocator.free(err_msg);
                    std.debug.print("Execute error: {s}\n", .{err_msg});
                    return error.ExecuteError;
                },
                'S', 'N', 'A' => {
                    if (msg.typ == 'S') try self.conn.processParameterStatus(&msg.buf);
                },
                else => {
                    std.debug.print("Unexpected message in exec: '{c}'\n", .{msg.typ});
                    return error.UnexpectedMessage;
                },
            }
        }
    }

    /// Executes a query that returns rows, returning a Rows iterator.
    pub fn query(self: *Stmt, args: []const []const u8) !*Rows {
        const exec_res = try self.exec(args);
        defer self.conn.allocator.free(exec_res.tag);

        var rows = try Rows.init(self.conn);

        // Deep copy colNames
        rows.colNames = try self.conn.allocator.alloc([]const u8, self.colNames.len);
        for (self.colNames, 0..) |name, i| {
            rows.colNames[i] = try self.conn.allocator.dupe(u8, name);
        }

        rows.colFmts = try self.conn.allocator.dupe(Format, self.colFmts);
        rows.colTyps = try self.conn.allocator.dupe(FieldDesc, self.colTyps);

        rows.done = false;
        return rows;
    }

    /// Closes the prepared statement on the server.
    pub fn close(self: *Stmt) void {
        if (self.closed) return;
        if (self.conn.bad) return;

        self.closed = true;

        var w = buff.WriteBuf.init(self.conn.allocator);
        defer w.deinit();

        w.byte('C') catch return;
        w.byte('S') catch return;
        w.string(self.name) catch return;

        var w2 = buff.WriteBuf.init(self.conn.allocator);
        defer w2.deinit();
        w2.byte('S') catch return;

        _ = w.wrap() catch return;
        self.conn.send(&w) catch return;

        _ = w2.wrap() catch return;
        self.conn.send(&w2) catch return;

        _ = self.conn.recv1() catch {};
        _ = self.conn.readReadyForQuery() catch null;
    }
};

// -----------------------------------------------------------------------------
// Helper functions for the Conn methods that were deferred
// -----------------------------------------------------------------------------

fn isDriverSetting(key: []const u8) bool {
    const settings = [_][]const u8{
        "host",                      "port",            "password",                       "sslmode",           "sslcert", "sslkey", "sslrootcert",
        "fallback_application_name", "connect_timeout", "disable_prepared_binary_result", "binary_parameters",
    };
    for (settings) |s| {
        if (std.mem.eql(u8, key, s)) return true;
    }
    return false;
}

fn parseOptsWithDefaults(allocator: std.mem.Allocator, name: []const u8, opts: *Options) !void {
    var it = std.mem.splitScalar(u8, name, ' ');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq_pos = std.mem.indexOfScalar(u8, pair, '=') orelse {
            std.debug.print("Invalid key-value pair: '{s}'\n", .{pair});
            return error.InvalidConnString;
        };
        const key = pair[0..eq_pos];
        const value = pair[eq_pos + 1 ..];
        try opts.put(try allocator.dupe(u8, key), try allocator.dupe(u8, value));
    }
    if (!opts.contains("host")) {
        try opts.put(try allocator.dupe(u8, "host"), try allocator.dupe(u8, "localhost"));
    }
    if (!opts.contains("port")) {
        try opts.put(try allocator.dupe(u8, "port"), try allocator.dupe(u8, "5432"));
    }
    if (!opts.contains("extra_float_digits")) {
        try opts.put(try allocator.dupe(u8, "extra_float_digits"), try allocator.dupe(u8, "2"));
    }
    if (!opts.contains("client_encoding")) {
        try opts.put(try allocator.dupe(u8, "client_encoding"), try allocator.dupe(u8, "UTF8"));
    }
    if (!opts.contains("datestyle")) {
        try opts.put(try allocator.dupe(u8, "datestyle"), try allocator.dupe(u8, "ISO, MDY"));
    }
    if (!opts.contains("user")) {
        const user = try userCurrent(allocator);
        try opts.put(try allocator.dupe(u8, "user"), user);
    }
}

fn unquoteValue(quoted: []const u8) []const u8 {
    if (quoted.len < 2 or quoted[0] != '\'' or quoted[quoted.len - 1] != '\'') return quoted;
    var result = std.ArrayList(u8).init(std.heap.page_allocator);
    defer result.deinit();
    var i: usize = 1;
    while (i < quoted.len - 1) {
        if (quoted[i] == '\\' and i + 1 < quoted.len - 1) {
            result.append(quoted[i + 1]) catch break;
            i += 2;
        } else {
            result.append(quoted[i]) catch break;
            i += 1;
        }
    }
    return result.items;
}

fn applyEnvironment(opts: *Options) !void {
    // Map of environment variable to option key
    const env_map = [_]struct { env: []const u8, key: []const u8 }{
        .{ .env = "PGHOST", .key = "host" },
        .{ .env = "PGPORT", .key = "port" },
        .{ .env = "PGDATABASE", .key = "dbname" },
        .{ .env = "PGUSER", .key = "user" },
        .{ .env = "PGPASSWORD", .key = "password" },
        .{ .env = "PGSSLMODE", .key = "sslmode" },
        .{ .env = "PGSSLCERT", .key = "sslcert" },
        .{ .env = "PGSSLKEY", .key = "sslkey" },
        .{ .env = "PGSSLROOTCERT", .key = "sslrootcert" },
        .{ .env = "PGCONNECT_TIMEOUT", .key = "connect_timeout" },
        .{ .env = "PGCLIENTENCODING", .key = "client_encoding" },
        .{ .env = "PGDATESTYLE", .key = "datestyle" },
        .{ .env = "PGTZ", .key = "timezone" },
    };
    for (env_map) |item| {
        if (std.process.getEnvVarOwned(std.heap.page_allocator, item.env)) |val| {
            defer std.heap.page_allocator.free(val);
            if (!opts.contains(item.key)) {
                try opts.put(try std.heap.page_allocator.dupe(u8, item.key), try std.heap.page_allocator.dupe(u8, val));
            }
        } else |_| {}
    }
}

fn loadPgPass(opts: *Options) !void {
    if (opts.contains("password")) return;
    const filename = blk: {
        if (std.process.getEnvVarOwned(std.heap.page_allocator, "PGPASSFILE")) |path| {
            defer std.heap.page_allocator.free(path);
            break :blk path;
        } else |_| {
            const home = std.process.getEnvVarOwned(std.heap.page_allocator, "HOME") catch {
                // Fallback to user.Current
                const user = userCurrent(std.heap.page_allocator) catch return;
                defer std.heap.page_allocator.free(user);
                break :blk try std.fmt.allocPrint(std.heap.page_allocator, "{s}/.pgpass", .{user});
            };
            defer std.heap.page_allocator.free(home);
            break :blk try std.fmt.allocPrint(std.heap.page_allocator, "{s}/.pgpass", .{home});
        }
    };
    defer std.heap.page_allocator.free(filename);

    const file = std.fs.cwd().openFile(filename, .{}) catch return;
    defer file.close();

    const stat = file.stat() catch return;
    // Check permissions: only owner read/write (0600)
    if (stat.mode & 0o077 != 0) return;

    const content = try file.readToEndAlloc(std.heap.page_allocator, 4096);
    defer std.heap.page_allocator.free(content);

    const host = opts.get("host") orelse "";
    const port = opts.get("port") orelse "";
    const dbname = opts.get("dbname") orelse "";
    const user = opts.get("user") orelse "";

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.splitScalar(u8, line, ':');
        const file_host = fields.next() orelse continue;
        const file_port = fields.next() orelse continue;
        const file_db = fields.next() orelse continue;
        const file_user = fields.next() orelse continue;
        const file_pass = fields.next() orelse continue;

        const host_match = std.mem.eql(u8, file_host, "*") or std.mem.eql(u8, file_host, host);
        const port_match = std.mem.eql(u8, file_port, "*") or std.mem.eql(u8, file_port, port);
        const db_match = std.mem.eql(u8, file_db, "*") or std.mem.eql(u8, file_db, dbname);
        const user_match = std.mem.eql(u8, file_user, "*") or std.mem.eql(u8, file_user, user);
        if (host_match and port_match and db_match and user_match) {
            try opts.put(try std.heap.page_allocator.dupe(u8, "password"), try std.heap.page_allocator.dupe(u8, file_pass));
            return;
        }
    }
}

fn md5s(allocator: std.mem.Allocator, s: []const u8) ![]const u8 {
    var hash: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(s, &hash, .{});
    const hex = std.fmt.bytesToHex(&hash, .lower);
    return try allocator.dupe(u8, &hex);
}

fn parseErrorMessage(allocator: std.mem.Allocator, r: *buff.ReadBuf) ![]const u8 {
    var fields = std.array_list.Managed(u8).init(allocator);
    defer fields.deinit();

    var severity: []const u8 = "";
    var code: []const u8 = "";
    var message: []const u8 = "";
    var detail: []const u8 = "";
    var hint: []const u8 = "";

    while (true) {
        const field = try r.byte();
        if (field == 0) break;
        const value = try r.string();

        switch (field) {
            'S' => severity = value,
            'C' => code = value,
            'M' => message = value,
            'D' => detail = value,
            'H' => hint = value,
            else => {},
        }
    }

    var result = std.array_list.Managed(u8).init(allocator);
    defer result.deinit();

    if (severity.len > 0) {
        try result.writer().print("[{s}] ", .{severity});
    }
    if (code.len > 0) {
        try result.writer().print("({s}) ", .{code});
    }
    if (message.len > 0) {
        try result.writer().print("{s}", .{message});
    }
    if (detail.len > 0) {
        try result.writer().print(" Detail: {s}", .{detail});
    }
    if (hint.len > 0) {
        try result.writer().print(" Hint: {s}", .{hint});
    }

    return try result.toOwnedSlice();
}

fn decideColumnFormats(allocator: std.mem.Allocator, colTyps: []FieldDesc, forceText: bool) ![]u8 {
    if (colTyps.len == 0) return allocator.dupe(u8, &[_]u8{ 0, 0 });
    if (forceText) return allocator.dupe(u8, &[_]u8{ 0, 0 });

    var allBinary = true;
    var allText = true;
    var fmts = try allocator.alloc(Format, colTyps.len);
    for (colTyps, 0..) |typ, i| {
        switch (typ.oid) {
            oid.T_bytea, oid.T_int8, oid.T_int4, oid.T_int2, oid.T_uuid => {
                fmts[i] = .binary;
                allText = false;
            },
            else => {
                fmts[i] = .text;
                allBinary = false;
            },
        }
    }
    if (allBinary) {
        return allocator.dupe(u8, &[_]u8{ 0, 1, 0, 1 });
    } else if (allText) {
        return allocator.dupe(u8, &[_]u8{ 0, 0 });
    } else {
        var buf2 = std.array_list.Managed(u8).init(allocator);
        try buf2.appendSlice(&[_]u8{ 0, @intCast(fmts.len) });
        for (fmts) |f| {
            const val: i16 = @intFromEnum(f);
            var bytes: [2]u8 = undefined;
            std.mem.writeInt(i16, &bytes, val, .big);
            try buf2.appendSlice(&bytes);
        }
        return buf2.toOwnedSlice();
    }
}

// -----------------------------------------------------------------------------
// Top-level open function
// -----------------------------------------------------------------------------

/// Opens a connection using the default dialer.
pub fn open(allocator: std.mem.Allocator, connString: []const u8) !*Conn {
    return Conn.dialOpen(allocator, Dialer.default, connString);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

test "parseOptsWithDefaults" {
    const alloc = testing.allocator;
    var opts = Options.init(alloc);
    defer {
        var it = opts.iterator();
        while (it.next()) |entry| {
            alloc.free(entry.key_ptr.*);
            alloc.free(entry.value_ptr.*);
        }
        opts.deinit();
    }
    try parseOptsWithDefaults(alloc, "host=localhost port=5432 user=test", &opts);
    try testing.expectEqualStrings("localhost", opts.get("host").?);
    try testing.expectEqualStrings("5432", opts.get("port").?);
    try testing.expectEqualStrings("test", opts.get("user").?);
}
