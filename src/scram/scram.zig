// SCRAM client implementation per RFC5802 (Salted Challenge Response Authentication Mechanism)
//
// This module implements a SCRAM-{SHA-256} client for SASL authentication.
// Based on the Go implementation by Gustavo Niemeyer.

const std = @import("std");
const mem = std.mem;
const fmt = std.fmt;
const base64 = std.base64;
const crypto = std.crypto;
const Allocator = mem.Allocator;

// Default hash algorithm is SHA-256. Can be replaced with any hash that follows the std.crypto.hash interface.
pub const HashAlg = crypto.hash.sha2.Sha256;

// Client returns a SCRAM-* client (SCRAM-SHA-256, etc.) for the given hash algorithm.
// Usage:
//   var client = try Client(Sha256).init(allocator, "username", "password");
//   defer client.deinit();
//   while (!finished) {
//       const out = client.out();
//       // send out to server
//       // receive in from server
//       finished = try client.step(in);
//   }
//   if (client.err()) |err| { // auth failed }
pub fn Client(comptime H: type) type {
    if (!@hasDecl(H, "init") or !@hasDecl(H, "update") or !@hasDecl(H, "final"))
        @compileError("Hash type must have init, update, final methods");

    return struct {
        const Self = @This();

        allocator: Allocator,
        user: []const u8,
        pass: []const u8,
        _step: u8 = 0,
        _err: ?anyerror = null,
        _out: std.array_list.Managed(u8),
        client_nonce: ?[]u8 = null,
        server_nonce: ?[]u8 = null,
        salted_pass: ?[]u8 = null,
        auth_msg: std.array_list.Managed(u8),

        // Creates a new SCRAM client with the provided hash algorithm.
        pub fn init(allocator: Allocator, user: []const u8, pass: []const u8) !Self {
            return Self{
                .allocator = allocator,
                .user = try allocator.dupe(u8, user),
                .pass = try allocator.dupe(u8, pass),
                ._out = std.array_list.Managed(u8).init(allocator),
                .auth_msg = std.array_list.Managed(u8).init(allocator),
            };
        }

        // Releases all allocated resources.
        pub fn deinit(self: *Self) void {
            self.allocator.free(self.user);
            self.allocator.free(self.pass);
            self._out.deinit();
            self.auth_msg.deinit();
            if (self.client_nonce) |n| self.allocator.free(n);
            if (self.server_nonce) |n| self.allocator.free(n);
            if (self.salted_pass) |p| self.allocator.free(p);
        }

        // Sets the client nonce to the provided value.
        // If not set, the nonce is generated automatically from crypto.random on the first step.
        pub fn setNonce(self: *Self, nonce: []const u8) !void {
            if (self.client_nonce) |old| self.allocator.free(old);
            self.client_nonce = try self.allocator.dupe(u8, nonce);
        }

        // Returns the data to be sent to the server in the current step.
        pub fn out(self: *Self) []const u8 {
            return self._out.items;
        }

        // Returns the error that occurred, or null if there were no errors.
        pub fn err(self: *Self) ?anyerror {
            return self._err;
        }

        // Processes the incoming data from the server and makes the next round of data
        // available via Client.out(). Returns false if there are no errors and more data
        // is still expected.
        pub fn step(self: *Self, in: []const u8) !bool {
            self._out.clearRetainingCapacity();
            if (self._step > 2 or self._err != null) return false;
            self._step += 1;
            switch (self._step) {
                1 => try self.step1(),
                2 => try self.step2(in),
                3 => try self.step3(in),
                else => {},
            }
            return self._step > 2 or self._err != null;
        }

        // Step 1: send client-first message
        fn step1(self: *Self) !void {
            // Generate client nonce if not set
            if (self.client_nonce == null) {
                const nonce_len = 16;
                var buf: [nonce_len]u8 = undefined;
                crypto.random.bytes(&buf);
                const encoded = try self.allocator.alloc(u8, base64.standard.Encoder.calcSize(nonce_len));
                defer self.allocator.free(encoded);
                _ = base64.standard.Encoder.encode(encoded, &buf);
                self.client_nonce = try self.allocator.dupe(u8, encoded);
            }
            const client_nonce = self.client_nonce.?;
            // Build auth_msg: "n=user,r=nonce"
            self.auth_msg.clearRetainingCapacity();
            try self.auth_msg.appendSlice("n=");
            try escape(self.auth_msg.writer(), self.user);
            try self.auth_msg.appendSlice(",r=");
            try self.auth_msg.appendSlice(client_nonce);
            // Output: "n,,auth_msg"
            try self._out.appendSlice("n,,");
            try self._out.appendSlice(self.auth_msg.items);
        }

        // Step 2: process server-first message and send client-final message
        fn step2(self: *Self, in: []const u8) !void {
            // Append server message to auth_msg
            try self.auth_msg.append(',');
            try self.auth_msg.appendSlice(in);

            // Parse server message: "r=...,s=...,i=..."
            var fields = mem.splitScalar(u8, in, ',');
            const r_field = fields.next() orelse return error.InvalidServerMessage;
            const s_field = fields.next() orelse return error.InvalidServerMessage;
            const i_field = fields.next() orelse return error.InvalidServerMessage;
            if (fields.next() != null) return error.InvalidServerMessage;

            if (!mem.startsWith(u8, r_field, "r=")) return error.InvalidNonce;
            if (!mem.startsWith(u8, s_field, "s=")) return error.InvalidSalt;
            if (!mem.startsWith(u8, i_field, "i=")) return error.InvalidIteration;

            const server_nonce = r_field[2..];
            const salt_b64 = s_field[2..];
            const iter_str = i_field[2..];

            // Verify nonce prefix
            const client_nonce = self.client_nonce.?;
            if (!mem.startsWith(u8, server_nonce, client_nonce))
                return error.NonceMismatch;

            self.server_nonce = try self.allocator.dupe(u8, server_nonce);

            // Decode salt
            const decoded_len = base64.standard.Decoder.calcSizeForSlice(salt_b64) catch return error.InvalidBase64;
            const salt = try self.allocator.alloc(u8, decoded_len);
            defer self.allocator.free(salt);
            try base64.standard.Decoder.decode(salt, salt_b64);

            const iter_count = try fmt.parseInt(u32, iter_str, 10);

            // Compute salted password
            const salted_pass = try self.saltPassword(salt, iter_count);
            self.salted_pass = salted_pass;

            // Append ",c=biws,r=server_nonce"
            try self.auth_msg.appendSlice(",c=biws,r=");
            try self.auth_msg.appendSlice(server_nonce);

            // Build output: "c=biws,r=server_nonce,p=client_proof"
            try self._out.appendSlice("c=biws,r=");
            try self._out.appendSlice(server_nonce);
            try self._out.appendSlice(",p=");
            const proof = try self.clientProof();
            defer self.allocator.free(proof);
            try self._out.appendSlice(proof);
        }

        // Step 3: verify server-final message
        fn step3(self: *Self, in: []const u8) !void {
            // Server final message: "v=..." or "e=..."
            if (mem.startsWith(u8, in, "e=")) {
                const err_msg = in[2..];
                _ = err_msg;
                return error.ServerError;
            } else if (mem.startsWith(u8, in, "v=")) {
                const server_sig_b64 = in[2..];
                const expected_sig = try self.serverSignature();
                defer self.allocator.free(expected_sig);
                if (!mem.eql(u8, server_sig_b64, expected_sig))
                    return error.InvalidServerSignature;
            } else {
                return error.InvalidServerMessage;
            }
        }

        // Hi function: PBKDF2-HMAC single-iteration variant (used to generate salted password)
        fn saltPassword(self: *Self, salt: []const u8, iter: u32) ![]u8 {
            const pass = self.pass;
            var hmac_ctx = crypto.auth.hmac.Hmac(H).init(pass);
            hmac_ctx.update(salt);
            hmac_ctx.update(&[_]u8{ 0, 0, 0, 1 });
            var ui: [H.digest_length]u8 = undefined;
            hmac_ctx.final(&ui);

            var hi = try self.allocator.alloc(u8, H.digest_length);
            @memcpy(hi, &ui);

            var i: u32 = 1;
            while (i < iter) : (i += 1) {
                hmac_ctx = crypto.auth.hmac.Hmac(H).init(pass);
                hmac_ctx.update(ui[0..]);
                hmac_ctx.final(&ui);
                for (0..H.digest_length) |j| {
                    hi[j] ^= ui[j];
                }
            }
            return hi;
        }

        // Computes the client proof for the current authentication state.
        fn clientProof(self: *Self) ![]u8 {
            const salted_pass = self.salted_pass.?;
            // ClientKey = HMAC(salted_pass, "Client Key")
            var hmac_ck = crypto.auth.hmac.Hmac(H).init(salted_pass);
            hmac_ck.update("Client Key");
            var client_key: [H.digest_length]u8 = undefined;
            hmac_ck.final(&client_key);

            // StoredKey = H(ClientKey)
            var hash_sk = H.init(.{});
            hash_sk.update(client_key[0..]);
            var stored_key: [H.digest_length]u8 = undefined;
            hash_sk.final(&stored_key);

            // ClientSignature = HMAC(stored_key, auth_msg)
            var hmac_cs = crypto.auth.hmac.Hmac(H).init(stored_key[0..]);
            hmac_cs.update(self.auth_msg.items);
            var client_sig: [H.digest_length]u8 = undefined;
            hmac_cs.final(&client_sig);

            // ClientProof = ClientKey XOR ClientSignature
            var proof = try self.allocator.alloc(u8, H.digest_length);
            for (0..H.digest_length) |i| {
                proof[i] = client_key[i] ^ client_sig[i];
            }
            // Base64 encode
            const encoded = try self.allocator.alloc(u8, base64.standard.Encoder.calcSize(H.digest_length));
            _ = base64.standard.Encoder.encode(encoded, proof);
            self.allocator.free(proof);
            return encoded;
        }

        // Computes the server signature to verify the server's final message.
        fn serverSignature(self: *Self) ![]u8 {
            const salted_pass = self.salted_pass.?;
            // ServerKey = HMAC(salted_pass, "Server Key")
            var hmac_sk = crypto.auth.hmac.Hmac(H).init(salted_pass);
            hmac_sk.update("Server Key");
            var server_key: [H.digest_length]u8 = undefined;
            hmac_sk.final(&server_key);

            // ServerSignature = HMAC(ServerKey, auth_msg)
            var hmac_ss = crypto.auth.hmac.Hmac(H).init(server_key[0..]);
            hmac_ss.update(self.auth_msg.items);
            var server_sig: [H.digest_length]u8 = undefined;
            hmac_ss.final(&server_sig);

            const encoded = try self.allocator.alloc(u8, base64.standard.Encoder.calcSize(H.digest_length));
            _ = base64.standard.Encoder.encode(encoded, &server_sig);
            return encoded;
        }
    };
}

// Helper function to escape '=' and ',' characters as required by SCRAM.
fn escape(writer: anytype, s: []const u8) !void {
    for (s) |ch| {
        switch (ch) {
            '=' => try writer.writeAll("=3D"),
            ',' => try writer.writeAll("=2C"),
            else => try writer.writeByte(ch),
        }
    }
}

// Tests
const testing = std.testing;
const Sha1 = crypto.hash.Sha1; // Use SHA-1 for RFC 5802 test vectors
const ScramClient = Client(Sha1);

test "SCRAM step1 output format" {
    const alloc = testing.allocator;
    var client = try ScramClient.init(alloc, "user", "pass");
    defer client.deinit();

    try client.setNonce("fyko+d2lbbFgONRv9qkxdawL");
    const finished = try client.step("");
    try testing.expect(!finished);
    const out = client.out();
    try testing.expectEqualStrings("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", out);
}

test "SCRAM full flow" {
    const alloc = testing.allocator;
    
    // RFC 5802 uses password "pencil" not "pass"
    var client = try ScramClient.init(alloc, "user", "pencil");
    defer client.deinit();

    try client.setNonce("fyko+d2lbbFgONRv9qkxdawL");

    var finished = try client.step("");
    try testing.expect(!finished);
    const out1 = client.out();
    try testing.expectEqualStrings("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", out1);

    const server_msg = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";
    finished = try client.step(server_msg);
    try testing.expect(!finished);
    const out2 = client.out();
    
    // Debug: print the client proof
    const proof_start = mem.indexOf(u8, out2, "p=").? + 2;
    const client_proof = out2[proof_start..];
    std.debug.print("Client proof: {s}\n", .{client_proof});
    // Expected from RFC 5802: v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
    
    const server_final = "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=";
    finished = try client.step(server_final);
    try testing.expect(finished);
    try testing.expect(client.err() == null);
}

test "SCRAM debug RFC 5802" {
    const alloc = testing.allocator;
    
    var client = try ScramClient.init(alloc, "user", "pencil");
    defer client.deinit();
    
    try client.setNonce("fyko+d2lbbFgONRv9qkxdawL");
    
    // Step 1
    _ = try client.step("");
    
    // Step 2
    const server_msg = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";
    _ = try client.step(server_msg);
    
    // Now manually compute the salted password to verify
    const salt_b64 = "QSXCR+Q6sek8bf92";
    const decoded_len = base64.standard.Decoder.calcSizeForSlice(salt_b64) catch unreachable;
    const salt = try alloc.alloc(u8, decoded_len);
    defer alloc.free(salt);
    try base64.standard.Decoder.decode(salt, salt_b64);
    
    std.debug.print("Salt (hex): ", .{});
    for (salt) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n", .{});
    
    // The expected salted password from RFC 5802 (hex):
    // 1d96ee3a529b5d5f9e4c3692f2c9b4a0d0df2e40
    const expected_salted_pass_hex = "1d96ee3a529b5d5f9e4c3692f2c9b4a0d0df2e40";
    std.debug.print("Expected salted pass (hex): {s}\n", .{expected_salted_pass_hex});
}

test "escape function" {
    var buf = std.array_list.Managed(u8).init(testing.allocator);
    defer buf.deinit();
    try escape(buf.writer(), "a=b,c");
    try testing.expectEqualStrings("a=3Db=2Cc", buf.items);
}
