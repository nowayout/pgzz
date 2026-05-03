# pgzz – Native PostgreSQL driver for Zig

    pgzz​ is a lightweight, asynchronous PostgreSQL driver written in pure Zig. It speaks the PostgreSQL wire protocol (v3) directly, without depending on libpqor any C libraries. Built for simplicity, performance, and safety.

* Features
    * Pure Zig, no external dependencies
    * Asynchronous I/O (uses std.netand std.posix.poll)
    * Supports text and binary wire formats
    * Parameterized queries (prepared statements)
    * Connection pooling (optional)

## Installation

    Add pgzto your build.zig.zondependencies:
    ```zig
    // build.zig.zon
    .{
        .name = "myapp",
        .version = "0.1.0",
        .dependencies = .{
            .pgzz = .{
                .url = "https://github.com/yourusername/pgzz/archive/refs/tags/v0.1.0.tar.gz",
                .hash = "1220...", // replace with actual hash
            },
        },
    }
    ```

    Then in build.zig:
    ```zig
    const pgzz = b.dependency("pgzz", .{});
    exe.root_module.addImport("pgzz", pgzz.module("pgzz"));
    ```

## Build example
    zig build -Dcpu=haswell

## Usage

### Basic connection

```zig
const pgzz = @import("pgzz");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var conn = try pgzz.Connection.init(allocator, .{
        .host = "localhost",
        .port = 5432,
        .user = "postgres",
        .password = "secret",
        .database = "mydb",
    });
    defer conn.deinit();

    try conn.connect();
    defer conn.close();

    // Simple query
    var result = try conn.query("SELECT version()", .{});
    defer result.deinit();

    if (try result.next()) |row| {
        const version = row.get([]const u8, 0);
        std.debug.print("PG version: {s}\n", .{version});
    }
}
```

### Parameterized queries

```zig
const rows = try conn.query("SELECT name, age FROM users WHERE age > $1", .{30});
defer rows.deinit();

while (try rows.next()) |row| {
    const name = row.get([]const u8, 0);
    const age = row.get(i32, 1);
    std.debug.print("{s} is {} years old\n", .{ name, age });
}
```

### Prepared statements (manual)

```zig
const stmt = try conn.prepare("SELECT name FROM users WHERE id = $1");
defer stmt.deinit();

var rows = try stmt.execute(&.{42});
defer rows.deinit();

if (try rows.next()) |row| {
    const name = row.get([]const u8, 0);
    // ...
}
```

## API Overview

    Connection.init(allocator, ConnectionSettings) -> Connection
    Connection.connect() !void
    Connection.query(comptime sql: []const u8, args: anytype) !Result
    Connection.prepare(comptime sql: []const u8) !Statement
    Connection.begin() !Transaction
    Result.next() !?Row
    Row.get(comptime T: type, idx: usize) T
    
## Error handling

    All functions return pgzz.Erroror any standard Zig error. Typical errors include:
    ConnectionFailed
    AuthenticationFailed
    QueryError(SQL-level errors, e.g. syntax, constraint violation)
    UnexpectedMessage
    OutOfMemory

## Limitations

    No LISTEN/NOTIFY
    SCRAM-SHA-256 authentication is not implemented (only MD5 and cleartext for now)
    TLS is experimental
    Big integers (int8) are returned as i64; overflow is not checked

## Contributing

    Contributions are very welcome! Please:
    Open an issue to discuss your change.
    Follow Zig's style guide (use zig fmt).
    Add tests for new functionality.
    Update this README if needed.

## License

    This project is licensed under the Apache License 2.0.
