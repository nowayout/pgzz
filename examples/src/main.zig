const std = @import("std");
const pgzz = @import("pgzz");
const Connection = pgzz.conn;

pub fn main() !void {
    // Initialize General Purpose Allocator with enhanced debugging features
    var gpa = std.heap.GeneralPurposeAllocator(.{
        .stack_trace_frames = 10, // Enable stack traces
        .enable_memory_limit = true,
        .never_unmap = true,
        .retain_metadata = true,
        .safety = true,
    }){};
    defer {
        const check = gpa.deinit();
        if (check != .ok) @panic("memory leak detected");
    }

    const allocator = gpa.allocator();

    // 1. Connect to PostgreSQL database
    var _conn = try Connection.open(allocator, "host=127.0.0.1 port=5432 user=postgres dbname=postgres password=secret sslmode=disable");
    // var _conn = try Connection.open(allocator, "postgres://postgres:secret@127.0.0.1:5432/postgres?sslmode=disable");
    defer {
        _conn.close();
        _conn.deinit();
    }

    // 2. Drop existing table (if any)
    const drop_res = try _conn.exec("DROP TABLE IF EXISTS subhana_allah_t");
    defer _conn.allocator.free(drop_res.tag);

    // 3. Create new table
    const create_res = try _conn.exec(
        \\CREATE TABLE IF NOT EXISTS subhana_allah_t (
        \\    id INT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
        \\    v_str TEXT NOT NULL,
        \\    v_varchar VARCHAR(24) NOT NULL,
        \\    v_bool BOOLEAN NOT NULL
        \\)
    );
    defer _conn.allocator.free(create_res.tag);

    // 4. Prepare INSERT statement with parameters
    var stmt = try _conn.prepare(
        \\INSERT INTO subhana_allah_t(v_str, v_varchar, v_bool)
        \\VALUES ($1, $2, $3)
    );
    defer {
        stmt.close(); // Send protocol close message to server
        stmt.deinit(); // Free client-side memory
    }

    // 5. Insert 20 rows with different values
    for (0..20) |i| {
        const bool_val = (i % 4 == 0);
        // Parameters must be encoded as text format
        const params = [_][]const u8{
            "subhana_allah",
            "alhamdo li Allah",
            if (bool_val) "t" else "f", // PostgreSQL boolean literal
        };
        const insert_res = try stmt.exec(&params);
        defer _conn.allocator.free(insert_res.tag);
    }

    // 6. Query all rows using manual field extraction
    var rows = try _conn.query("SELECT id, v_str, v_varchar, v_bool FROM subhana_allah_t");
    errdefer rows.deinit();
    defer rows.deinit();

    var dest: [4]?[]const u8 = undefined;
    while (try rows.next(&dest)) {
        const id_str = dest[0].?;
        const id = try std.fmt.parseInt(i16, id_str, 10);
        const v_str = dest[1].?;
        const v_varchar = dest[2].?;
        const bool_str = dest[3].?;
        const b = std.mem.eql(u8, bool_str, "t");
        std.debug.print("   {d}\t| '{s}' | '{s}' | {any}\n", .{ id, v_str, v_varchar, b });
    }

    // Structure representing a database row
    const MyRow = struct {
        id: i32,
        v_str: []const u8, // TEXT field
        v_varchar: []const u8, // VARCHAR field
        v_bool: bool,
    };

    // 7. Query all rows using automatic scanning into struct
    var rows2 = try _conn.query("SELECT id, v_str, v_varchar, v_bool FROM subhana_allah_t");
    errdefer rows2.deinit();
    defer rows2.deinit();

    var row_count: usize = 0;
    while (true) {
        var row: MyRow = undefined;
        // Scan next row into struct, break when no more rows
        rows2.scan(MyRow, &row, allocator) catch |err| switch (err) {
            error.NoMoreRows => break,
            else => return err,
        };
        // row.v_str and row.v_varchar are newly allocated memory, must be freed
        defer allocator.free(row.v_str);
        defer allocator.free(row.v_varchar);

        std.debug.print("   {d}\t| '{s}' | '{s}' | {any}\n", .{ row.id, row.v_str, row.v_varchar, row.v_bool });
        row_count += 1;
    }

    std.debug.print("Done, {} rows fetched\n", .{row_count});
}
