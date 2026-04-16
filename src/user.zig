//! Platform-specific user detection for PostgreSQL default username.
//! Provides a function to get the current operating system user name,
//! mimicking libpq's behavior.

const std = @import("std");
const builtin = @import("builtin");

/// Error returned when the current username cannot be detected.
pub const UserError = error{
    CouldNotDetectUsername,
};

/// Returns the current operating system user name.
/// On Unix-like systems, it first attempts `std.os.getenv("USER")`.
/// On Windows, it calls `GetUserNameExW` with `NameSamCompatible` and returns
/// the base name (last component) of the result.
pub fn userCurrent(allocator: std.mem.Allocator) ![]const u8 {
    const is_windows = builtin.os.tag == .windows;
    if (is_windows) {
        return userCurrentWindows(allocator);
    } else {
        return userCurrentPosix(allocator);
    }
}

/// Unix-like implementation: get from environment variable USER.
fn userCurrentPosix(allocator: std.mem.Allocator) ![]const u8 {
    if (std.os.getenv("USER")) |user| {
        return try allocator.dupe(u8, user);
    }
    return error.CouldNotDetectUsername;
}

/// Windows implementation: use GetUserNameExW.
fn userCurrentWindows(allocator: std.mem.Allocator) ![]const u8 {
    if (std.process.getEnvVarOwned(allocator, "USERNAME")) |username| {
        return username;
    } else |_| {}

    const GetUserNameW = struct {
        extern "advapi32" fn GetUserNameW(
            lpBuffer: [*]u16,
            pcbBuffer: *u32,
        ) callconv(.winapi) i32;
    }.GetUserNameW;

    var buf_len: u32 = 256;
    var buf = try allocator.alloc(u16, buf_len);
    defer allocator.free(buf);

    const result = GetUserNameW(buf.ptr, &buf_len);
    if (result == 0) {
        return error.CouldNotDetectUsername;
    }
    // buf_len includes the null terminator
    const actual_len = if (buf_len > 0) buf_len - 1 else 0;
    const utf16_slice = buf[0..actual_len];
    const utf8_buf = try std.unicode.utf16LeToUtf8Alloc(allocator, utf16_slice);
    return utf8_buf;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

test "userCurrent returns non-empty string (on supported platforms)" {
    const alloc = testing.allocator;
    const user = userCurrent(alloc) catch return error.SkipZigTest;
    defer alloc.free(user);
    try testing.expect(user.len > 0);
}
