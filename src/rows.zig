//! PostgreSQL row descriptor and column type information.
//! Provides methods to inspect result column types, similar to database/sql/Rows.
//! Dependencies: oid.zig

const std = @import("std");
const oid = @import("oid.zig");

/// Size of the header for type modifier calculations.
const headerSize = 4;

/// Field descriptor for a result column, as returned in RowDescription messages.
pub const FieldDesc = struct {
    oid: oid.Oid,
    len: i16,
    mod: i32,

    /// Returns the Zig type tag that can hold values of this column.
    /// The returned value is a `std.builtin.TypeId` or a custom enum.
    pub fn scanType(self: FieldDesc) TypeTag {
        return switch (self.oid) {
            oid.T_int8, oid.T_int4, oid.T_int2 => .Int,
            oid.T_varchar, oid.T_text => .String,
            oid.T_bool => .Bool,
            oid.T_date, oid.T_time, oid.T_timetz, oid.T_timestamp, oid.T_timestamptz => .Timestamp,
            oid.T_bytea => .Bytes,
            else => .Unknown,
        };
    }

    /// Returns the PostgreSQL type name for this column.
    pub fn databaseTypeName(self: FieldDesc) []const u8 {
        return oid.typeName(self.oid) orelse "unknown";
    }

    /// Returns the length of the column if it is a variable-length type.
    /// For fixed-length types, returns (0, false).
    pub fn length(self: FieldDesc) struct { len: i64, ok: bool } {
        switch (self.oid) {
            oid.T_text, oid.T_bytea => return .{ .len = std.math.maxInt(i64), .ok = true },
            oid.T_varchar, oid.T_bpchar => return .{ .len = self.mod - headerSize, .ok = true },
            else => return .{ .len = 0, .ok = false },
        }
    }

    /// Returns precision and scale for numeric/decimal columns.
    pub fn precisionScale(self: FieldDesc) struct { precision: i64, scale: i64, ok: bool } {
        switch (self.oid) {
            oid.T_numeric, oid.T__numeric => {
                const mod = self.mod - headerSize;
                const precision = @as(i64, @intCast((mod >> 16) & 0xffff));
                const scale = @as(i64, @intCast(mod & 0xffff));
                return .{ .precision = precision, .scale = scale, .ok = true };
            },
            else => return .{ .precision = 0, .scale = 0, .ok = false },
        }
    }
};

/// Type tag for scanning values.
pub const TypeTag = enum {
    Int,
    String,
    Bool,
    Timestamp,
    Bytes,
    Unknown,
};

// -----------------------------------------------------------------------------
// Extend the Rows type (defined in conn.zig) with column introspection methods.
// These functions assume a `rows` variable of type *Rows is available.
// In a real implementation, you would add these methods directly to the Rows
// struct in conn.zig. Here we show the method signatures and implementations
// as free functions for clarity.
// -----------------------------------------------------------------------------

/// Returns the scan type for the column at `index`.
pub fn columnTypeScanType(rows: anytype, index: usize) TypeTag {
    return rows.colTyps[index].scanType();
}

/// Returns the database system type name for the column at `index`.
pub fn columnTypeDatabaseTypeName(rows: anytype, index: usize) []const u8 {
    return rows.colTyps[index].databaseTypeName();
}

/// Returns the length of the column at `index` if variable-length.
pub fn columnTypeLength(rows: anytype, index: usize) struct { len: i64, ok: bool } {
    return rows.colTyps[index].length();
}

/// Returns precision and scale for decimal columns at `index`.
pub fn columnTypePrecisionScale(rows: anytype, index: usize) struct { precision: i64, scale: i64, ok: bool } {
    return rows.colTyps[index].precisionScale();
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

test "FieldDesc length for text" {
    const fd = FieldDesc{
        .oid = oid.T_text,
        .len = -1,
        .mod = 0,
    };
    const res = fd.length();
    try testing.expect(res.ok);
    try testing.expect(res.len == std.math.maxInt(i64));
}

test "FieldDesc length for varchar" {
    const fd = FieldDesc{
        .oid = oid.T_varchar,
        .len = -1,
        .mod = headerSize + 255, // typical varchar(255) modifier
    };
    const res = fd.length();
    try testing.expect(res.ok);
    try testing.expect(res.len == 255);
}

test "FieldDesc precisionScale for numeric" {
    const fd = FieldDesc{
        .oid = oid.T_numeric,
        .len = -1,
        .mod = headerSize + (10 << 16) | 2, // precision=10, scale=2
    };
    const res = fd.precisionScale();
    try testing.expect(res.ok);
    try testing.expect(res.precision == 10);
    try testing.expect(res.scale == 2);
}

test "FieldDesc databaseTypeName" {
    const fd = FieldDesc{
        .oid = oid.T_int4,
        .len = 4,
        .mod = 0,
    };
    try testing.expectEqualStrings("INT4", fd.databaseTypeName());
}
