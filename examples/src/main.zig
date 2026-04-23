const std = @import("std");
const pgzz = @import("pgzz");
const Conn = pgzz.conn.Conn;

const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    conn_string: []const u8,
    max_conn: usize,
    available: std.ArrayList(*Conn),
    in_use: std.ArrayList(*Conn),
    total_created: usize,

    pub fn init(allocator: std.mem.Allocator, conn_string: []const u8, max_conn: usize) !ConnectionPool {
        return ConnectionPool{
            .allocator = allocator,
            .conn_string = try allocator.dupe(u8, conn_string),
            .max_conn = max_conn,
            .available = std.ArrayList(*Conn).empty,
            .in_use = std.ArrayList(*Conn).empty,
            .total_created = 0,
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        for (self.available.items) |conn| {
            conn.close();
            conn.deinit();
        }
        self.available.deinit(self.allocator);
        for (self.in_use.items) |conn| {
            conn.close();
            conn.deinit();
        }
        self.in_use.deinit(self.allocator);
        self.allocator.free(self.conn_string);
    }

    pub fn get(self: *ConnectionPool) !*Conn {
        if (self.available.items.len > 0) {
            const conn = self.available.pop().?;
            try self.in_use.append(self.allocator, conn);
            return conn;
        }
        if (self.total_created < self.max_conn) {
            const conn = try pgzz.conn.open(self.allocator, self.conn_string);
            self.total_created += 1;
            try self.in_use.append(self.allocator, conn);
            return conn;
        }
        return error.NoAvailableConnection;
    }

    pub fn put(self: *ConnectionPool, conn: *Conn) void {
        for (self.in_use.items, 0..) |c, i| {
            if (c == conn) {
                _ = self.in_use.swapRemove(i);
                self.available.append(self.allocator, conn) catch {
                    conn.close();
                    conn.deinit();
                };
                return;
            }
        }
        conn.close();
        conn.deinit();
    }
};

pub fn main() !void {
    // const allocator = std.heap.c_allocator;
    const DebugAllocator = std.heap.DebugAllocator(.{});
    var gpa = DebugAllocator{};
    defer {
        const check = gpa.deinit();
        if (check != .ok) @panic("memory leak detected");
    }

    const allocator = gpa.allocator();

    const conn_string = "host=127.0.0.1 port=5432 user=postgres dbname=postgres password=secret sslmode=disable";
    //const conn_string = "postgres://postgres:secret@127.0.0.1:5432/postgres?sslmode=disable";

    // 1. Initial connection pool
    var pool = try ConnectionPool.init(allocator, conn_string, 10);
    defer pool.deinit();

    // 2. get a connection from pool
    var _conn = try pool.get();
    defer pool.put(_conn);

    // 3. Drop existing table (if any)
    const drop_res = try _conn.exec("DROP TABLE IF EXISTS subhana_allah_t");
    defer _conn.allocator.free(drop_res.tag);

    // 4. Create new table
    const create_res = try _conn.exec(
        \\CREATE TABLE IF NOT EXISTS subhana_allah_t (
        \\    id INT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
        \\    v_str TEXT NOT NULL,
        \\    v_varchar VARCHAR(24) NOT NULL,
        \\    v_bool BOOLEAN NOT NULL,
        \\    ts TIMESTAMPTZ NOT NULL
        \\)
    );
    defer _conn.allocator.free(create_res.tag);

    // 5. Prepare INSERT statement with parameters
    var stmt = try _conn.prepare(
        \\INSERT INTO subhana_allah_t(v_str, v_varchar, v_bool, ts)
        \\VALUES ($1, $2, $3, $4)
    );
    defer {
        stmt.close(); // Send protocol close message to server
        stmt.deinit(); // Free client-side memory
    }

    // 6. Insert 20 rows with different values
    for (0..20) |i| {
        const bool_val = (i % 4 == 0);
        const hour = i % 24;
        const day = i / 24 + 1;
        const ts_str = try std.fmt.allocPrint(allocator, "2024-01-{d:0>2} {d:0>2}:30:45+08", .{ day, hour });
        defer allocator.free(ts_str);
        const params = [_][]const u8{
            "subhana_allah",
            "alhamdo li Allah",
            if (bool_val) "t" else "f",
            ts_str,
        };
        const insert_res = try stmt.exec(&params);
        defer _conn.allocator.free(insert_res.tag);
    }

    // 7. Query all rows using manual field extraction
    var rows = try _conn.query("SELECT id, v_str, v_varchar, v_bool, ts FROM subhana_allah_t");
    errdefer rows.deinit();
    defer rows.deinit();

    var dest: [5]?[]const u8 = undefined;
    std.debug.print("\n--- Manual extraction (text format) ---\n", .{});
    while (try rows.next(&dest)) {
        const id_str = dest[0].?;
        const id = try std.fmt.parseInt(i16, id_str, 10);
        const v_str = dest[1].?;
        const v_varchar = dest[2].?;
        const bool_str = dest[3].?;
        const b = std.mem.eql(u8, bool_str, "t");
        const ts_str = dest[4].?;

        const ts_ns = try pgzz.encode.parseTimestamp(allocator, null, ts_str);
        const formatted = try pgzz.encode.formatTimestamp(allocator, ts_ns);
        defer allocator.free(formatted);

        std.debug.print("   {d}\t| '{s}' | '{s}' | {any} | ts={s} (parsed={s})\n", .{ id, v_str, v_varchar, b, ts_str, formatted });
    }

    // 8. Structure representing a database row
    const MyRow = struct {
        id: i32,
        v_str: []const u8, // TEXT field
        v_varchar: []const u8, // VARCHAR field
        v_bool: bool,
        ts_ns: i128,
    };

    // 9. Query all rows using automatic scanning into struct
    var rows2 = try _conn.query("SELECT id, v_str, v_varchar, v_bool, ts FROM subhana_allah_t");
    errdefer rows2.deinit();
    defer rows2.deinit();

    std.debug.print("\n--- Automatic scanning (decoded to i128) ---\n", .{});
    var row_count: usize = 0;
    while (true) {
        var row: MyRow = undefined;
        rows2.scan(MyRow, &row, allocator) catch |err| switch (err) {
            error.NoMoreRows => break,
            else => return err,
        };
        defer {
            allocator.free(row.v_str);
            allocator.free(row.v_varchar);
        }
        const formatted = try pgzz.encode.formatTimestamp(allocator, row.ts_ns);
        defer allocator.free(formatted);
        std.debug.print("   {d}\t| '{s}' | '{s}' | {any} | ts={s}\n", .{ row.id, row.v_str, row.v_varchar, row.v_bool, formatted });
        row_count += 1;
    }

    std.debug.print("Done, {} rows fetched\n", .{row_count});
}
