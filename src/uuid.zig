//! UUID support for PostgreSQL.
//! Converts a binary UUID (16 bytes) to the standard text format with hyphens.

const std = @import("std");

/// Decodes a binary UUID into its text representation (e.g., "123e4567-e89b-12d3-a456-426614174000").
/// The returned slice must be freed by the caller using `allocator.free`.
pub fn decodeUUIDBinary(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
    if (src.len != 16) {
        return error.InvalidUUIDLength;
    }

    var dst = try allocator.alloc(u8, 36);
    errdefer allocator.free(dst);

    // Set hyphen positions
    dst[8] = '-';
    dst[13] = '-';
    dst[18] = '-';
    dst[23] = '-';

    // Encode each segment as hex
    const hex = std.fmt.bytesToHex;

    // Segment 1: bytes 0-3 (8 hex chars)
    const seg1 = hex(src[0..4], .lower);
    @memcpy(dst[0..8], seg1[0..8]);

    // Segment 2: bytes 4-5 (4 hex chars)
    const seg2 = hex(src[4..6], .lower);
    @memcpy(dst[9..13], seg2[0..4]);

    // Segment 3: bytes 6-7 (4 hex chars)
    const seg3 = hex(src[6..8], .lower);
    @memcpy(dst[14..18], seg3[0..4]);

    // Segment 4: bytes 8-9 (4 hex chars)
    const seg4 = hex(src[8..10], .lower);
    @memcpy(dst[19..23], seg4[0..4]);

    // Segment 5: bytes 10-15 (12 hex chars)
    const seg5 = hex(src[10..16], .lower);
    @memcpy(dst[24..36], seg5[0..12]);

    return dst;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

test "decodeUUIDBinary" {
    const alloc = testing.allocator;
    // Sample UUID bytes: 123e4567-e89b-12d3-a456-426614174000
    // In binary: 0x12,0x3e,0x45,0x67,0xe8,0x9b,0x12,0xd3,0xa4,0x56,0x42,0x66,0x14,0x17,0x40,0x00
    const bytes = [_]u8{
        0x12, 0x3e, 0x45, 0x67,
        0xe8, 0x9b, 0x12, 0xd3,
        0xa4, 0x56, 0x42, 0x66,
        0x14, 0x17, 0x40, 0x00,
    };
    const expected = "123e4567-e89b-12d3-a456-426614174000";

    const result = try decodeUUIDBinary(alloc, &bytes);
    defer alloc.free(result);

    try testing.expectEqualStrings(expected, result);
}

test "decodeUUIDBinary invalid length" {
    const alloc = testing.allocator;
    const bytes = [_]u8{0} ** 15;
    const result = decodeUUIDBinary(alloc, &bytes);
    try testing.expectError(error.InvalidUUIDLength, result);
}
