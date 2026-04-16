//! PostgreSQL wire protocol error handling.
//! Provides `Error` struct, error code mapping, and parsing of ErrorResponse messages.

const std = @import("std");
const buff = @import("buff.zig");

// -----------------------------------------------------------------------------
// Error severity constants
// -----------------------------------------------------------------------------

pub const Severity = struct {
    pub const fatal = "FATAL";
    pub const panic = "PANIC";
    pub const warning = "WARNING";
    pub const notice = "NOTICE";
    pub const debug = "DEBUG";
    pub const info = "INFO";
    pub const log = "LOG";
};

// -----------------------------------------------------------------------------
// ErrorCode type
// -----------------------------------------------------------------------------

/// A five-character PostgreSQL error code.
pub const ErrorCode = [5]u8;

/// Returns the human-readable condition name for an error code.
pub fn errorCodeName(ec: ErrorCode) []const u8 {
    return errorCodeNames.get(ec[0..]) orelse "unknown_error";
}

/// Returns the error class (first two characters).
pub fn errorCodeClass(ec: ErrorCode) [2]u8 {
    return ec[0..2].*;
}

/// Returns the condition name for an error class (e.g., "28" -> "invalid_authorization_specification").
pub fn errorClassName(ec_class: [2]u8) []const u8 {
    var full: [5]u8 = undefined;
    @memcpy(full[0..2], &ec_class);
    full[2..5].* = "000".*;
    return errorCodeNames.get(full[0..]) orelse "unknown_class";
}

// Build a compile-time map from error code to condition name.
// This is derived from the PostgreSQL documentation (errcodes-appendix.html).
const errorCodeNames = std.StaticStringMap([]const u8).initComptime(.{
    // Class 00 - Successful Completion
    .{ "00000", "successful_completion" },
    // Class 01 - Warning
    .{ "01000", "warning" },
    .{ "0100C", "dynamic_result_sets_returned" },
    .{ "01008", "implicit_zero_bit_padding" },
    .{ "01003", "null_value_eliminated_in_set_function" },
    .{ "01007", "privilege_not_granted" },
    .{ "01006", "privilege_not_revoked" },
    .{ "01004", "string_data_right_truncation" },
    .{ "01P01", "deprecated_feature" },
    // Class 02 - No Data
    .{ "02000", "no_data" },
    .{ "02001", "no_additional_dynamic_result_sets_returned" },
    // Class 03 - SQL Statement Not Yet Complete
    .{ "03000", "sql_statement_not_yet_complete" },
    // Class 08 - Connection Exception
    .{ "08000", "connection_exception" },
    .{ "08003", "connection_does_not_exist" },
    .{ "08006", "connection_failure" },
    .{ "08001", "sqlclient_unable_to_establish_sqlconnection" },
    .{ "08004", "sqlserver_rejected_establishment_of_sqlconnection" },
    .{ "08007", "transaction_resolution_unknown" },
    .{ "08P01", "protocol_violation" },
    // Class 09 - Triggered Action Exception
    .{ "09000", "triggered_action_exception" },
    // Class 0A - Feature Not Supported
    .{ "0A000", "feature_not_supported" },
    // Class 0B - Invalid Transaction Initiation
    .{ "0B000", "invalid_transaction_initiation" },
    // Class 0F - Locator Exception
    .{ "0F000", "locator_exception" },
    .{ "0F001", "invalid_locator_specification" },
    // Class 0L - Invalid Grantor
    .{ "0L000", "invalid_grantor" },
    .{ "0LP01", "invalid_grant_operation" },
    // Class 0P - Invalid Role Specification
    .{ "0P000", "invalid_role_specification" },
    // Class 0Z - Diagnostics Exception
    .{ "0Z000", "diagnostics_exception" },
    .{ "0Z002", "stacked_diagnostics_accessed_without_active_handler" },
    // Class 20 - Case Not Found
    .{ "20000", "case_not_found" },
    // Class 21 - Cardinality Violation
    .{ "21000", "cardinality_violation" },
    // Class 22 - Data Exception
    .{ "22000", "data_exception" },
    .{ "2202E", "array_subscript_error" },
    .{ "22021", "character_not_in_repertoire" },
    .{ "22008", "datetime_field_overflow" },
    .{ "22012", "division_by_zero" },
    .{ "22005", "error_in_assignment" },
    .{ "2200B", "escape_character_conflict" },
    .{ "22022", "indicator_overflow" },
    .{ "22015", "interval_field_overflow" },
    .{ "2201E", "invalid_argument_for_logarithm" },
    .{ "22014", "invalid_argument_for_ntile_function" },
    .{ "22016", "invalid_argument_for_nth_value_function" },
    .{ "2201F", "invalid_argument_for_power_function" },
    .{ "2201G", "invalid_argument_for_width_bucket_function" },
    .{ "22018", "invalid_character_value_for_cast" },
    .{ "22007", "invalid_datetime_format" },
    .{ "22019", "invalid_escape_character" },
    .{ "2200D", "invalid_escape_octet" },
    .{ "22025", "invalid_escape_sequence" },
    .{ "22P06", "nonstandard_use_of_escape_character" },
    .{ "22010", "invalid_indicator_parameter_value" },
    .{ "22023", "invalid_parameter_value" },
    .{ "2201B", "invalid_regular_expression" },
    .{ "2201W", "invalid_row_count_in_limit_clause" },
    .{ "2201X", "invalid_row_count_in_result_offset_clause" },
    .{ "22009", "invalid_time_zone_displacement_value" },
    .{ "2200C", "invalid_use_of_escape_character" },
    .{ "2200G", "most_specific_type_mismatch" },
    .{ "22004", "null_value_not_allowed" },
    .{ "22002", "null_value_no_indicator_parameter" },
    .{ "22003", "numeric_value_out_of_range" },
    .{ "22026", "string_data_length_mismatch" },
    .{ "22001", "string_data_right_truncation" },
    .{ "22011", "substring_error" },
    .{ "22027", "trim_error" },
    .{ "22024", "unterminated_c_string" },
    .{ "2200F", "zero_length_character_string" },
    .{ "22P01", "floating_point_exception" },
    .{ "22P02", "invalid_text_representation" },
    .{ "22P03", "invalid_binary_representation" },
    .{ "22P04", "bad_copy_file_format" },
    .{ "22P05", "untranslatable_character" },
    .{ "2200L", "not_an_xml_document" },
    .{ "2200M", "invalid_xml_document" },
    .{ "2200N", "invalid_xml_content" },
    .{ "2200S", "invalid_xml_comment" },
    .{ "2200T", "invalid_xml_processing_instruction" },
    // Class 23 - Integrity Constraint Violation
    .{ "23000", "integrity_constraint_violation" },
    .{ "23001", "restrict_violation" },
    .{ "23502", "not_null_violation" },
    .{ "23503", "foreign_key_violation" },
    .{ "23505", "unique_violation" },
    .{ "23514", "check_violation" },
    .{ "23P01", "exclusion_violation" },
    // Class 24 - Invalid Cursor State
    .{ "24000", "invalid_cursor_state" },
    // Class 25 - Invalid Transaction State
    .{ "25000", "invalid_transaction_state" },
    .{ "25001", "active_sql_transaction" },
    .{ "25002", "branch_transaction_already_active" },
    .{ "25008", "held_cursor_requires_same_isolation_level" },
    .{ "25003", "inappropriate_access_mode_for_branch_transaction" },
    .{ "25004", "inappropriate_isolation_level_for_branch_transaction" },
    .{ "25005", "no_active_sql_transaction_for_branch_transaction" },
    .{ "25006", "read_only_sql_transaction" },
    .{ "25007", "schema_and_data_statement_mixing_not_supported" },
    .{ "25P01", "no_active_sql_transaction" },
    .{ "25P02", "in_failed_sql_transaction" },
    // Class 26 - Invalid SQL Statement Name
    .{ "26000", "invalid_sql_statement_name" },
    // Class 27 - Triggered Data Change Violation
    .{ "27000", "triggered_data_change_violation" },
    // Class 28 - Invalid Authorization Specification
    .{ "28000", "invalid_authorization_specification" },
    .{ "28P01", "invalid_password" },
    // Class 2B - Dependent Privilege Descriptors Still Exist
    .{ "2B000", "dependent_privilege_descriptors_still_exist" },
    .{ "2BP01", "dependent_objects_still_exist" },
    // Class 2D - Invalid Transaction Termination
    .{ "2D000", "invalid_transaction_termination" },
    // Class 2F - SQL Routine Exception
    .{ "2F000", "sql_routine_exception" },
    .{ "2F005", "function_executed_no_return_statement" },
    .{ "2F002", "modifying_sql_data_not_permitted" },
    .{ "2F003", "prohibited_sql_statement_attempted" },
    .{ "2F004", "reading_sql_data_not_permitted" },
    // Class 34 - Invalid Cursor Name
    .{ "34000", "invalid_cursor_name" },
    // Class 38 - External Routine Exception
    .{ "38000", "external_routine_exception" },
    .{ "38001", "containing_sql_not_permitted" },
    .{ "38002", "modifying_sql_data_not_permitted" },
    .{ "38003", "prohibited_sql_statement_attempted" },
    .{ "38004", "reading_sql_data_not_permitted" },
    // Class 39 - External Routine Invocation Exception
    .{ "39000", "external_routine_invocation_exception" },
    .{ "39001", "invalid_sqlstate_returned" },
    .{ "39004", "null_value_not_allowed" },
    .{ "39P01", "trigger_protocol_violated" },
    .{ "39P02", "srf_protocol_violated" },
    // Class 3B - Savepoint Exception
    .{ "3B000", "savepoint_exception" },
    .{ "3B001", "invalid_savepoint_specification" },
    // Class 3D - Invalid Catalog Name
    .{ "3D000", "invalid_catalog_name" },
    // Class 3F - Invalid Schema Name
    .{ "3F000", "invalid_schema_name" },
    // Class 40 - Transaction Rollback
    .{ "40000", "transaction_rollback" },
    .{ "40002", "transaction_integrity_constraint_violation" },
    .{ "40001", "serialization_failure" },
    .{ "40003", "statement_completion_unknown" },
    .{ "40P01", "deadlock_detected" },
    // Class 42 - Syntax Error or Access Rule Violation
    .{ "42000", "syntax_error_or_access_rule_violation" },
    .{ "42601", "syntax_error" },
    .{ "42501", "insufficient_privilege" },
    .{ "42846", "cannot_coerce" },
    .{ "42803", "grouping_error" },
    .{ "42P20", "windowing_error" },
    .{ "42P19", "invalid_recursion" },
    .{ "42830", "invalid_foreign_key" },
    .{ "42602", "invalid_name" },
    .{ "42622", "name_too_long" },
    .{ "42939", "reserved_name" },
    .{ "42804", "datatype_mismatch" },
    .{ "42P18", "indeterminate_datatype" },
    .{ "42P21", "collation_mismatch" },
    .{ "42P22", "indeterminate_collation" },
    .{ "42809", "wrong_object_type" },
    .{ "42703", "undefined_column" },
    .{ "42883", "undefined_function" },
    .{ "42P01", "undefined_table" },
    .{ "42P02", "undefined_parameter" },
    .{ "42704", "undefined_object" },
    .{ "42701", "duplicate_column" },
    .{ "42P03", "duplicate_cursor" },
    .{ "42P04", "duplicate_database" },
    .{ "42723", "duplicate_function" },
    .{ "42P05", "duplicate_prepared_statement" },
    .{ "42P06", "duplicate_schema" },
    .{ "42P07", "duplicate_table" },
    .{ "42712", "duplicate_alias" },
    .{ "42710", "duplicate_object" },
    .{ "42702", "ambiguous_column" },
    .{ "42725", "ambiguous_function" },
    .{ "42P08", "ambiguous_parameter" },
    .{ "42P09", "ambiguous_alias" },
    .{ "42P10", "invalid_column_reference" },
    .{ "42611", "invalid_column_definition" },
    .{ "42P11", "invalid_cursor_definition" },
    .{ "42P12", "invalid_database_definition" },
    .{ "42P13", "invalid_function_definition" },
    .{ "42P14", "invalid_prepared_statement_definition" },
    .{ "42P15", "invalid_schema_definition" },
    .{ "42P16", "invalid_table_definition" },
    .{ "42P17", "invalid_object_definition" },
    // Class 44 - WITH CHECK OPTION Violation
    .{ "44000", "with_check_option_violation" },
    // Class 53 - Insufficient Resources
    .{ "53000", "insufficient_resources" },
    .{ "53100", "disk_full" },
    .{ "53200", "out_of_memory" },
    .{ "53300", "too_many_connections" },
    .{ "53400", "configuration_limit_exceeded" },
    // Class 54 - Program Limit Exceeded
    .{ "54000", "program_limit_exceeded" },
    .{ "54001", "statement_too_complex" },
    .{ "54011", "too_many_columns" },
    .{ "54023", "too_many_arguments" },
    // Class 55 - Object Not In Prerequisite State
    .{ "55000", "object_not_in_prerequisite_state" },
    .{ "55006", "object_in_use" },
    .{ "55P02", "cant_change_runtime_param" },
    .{ "55P03", "lock_not_available" },
    // Class 57 - Operator Intervention
    .{ "57000", "operator_intervention" },
    .{ "57014", "query_canceled" },
    .{ "57P01", "admin_shutdown" },
    .{ "57P02", "crash_shutdown" },
    .{ "57P03", "cannot_connect_now" },
    .{ "57P04", "database_dropped" },
    // Class 58 - System Error
    .{ "58000", "system_error" },
    .{ "58030", "io_error" },
    .{ "58P01", "undefined_file" },
    .{ "58P02", "duplicate_file" },
    // Class F0 - Configuration File Error
    .{ "F0000", "config_file_error" },
    .{ "F0001", "lock_file_exists" },
    // Class HV - Foreign Data Wrapper Error
    .{ "HV000", "fdw_error" },
    .{ "HV005", "fdw_column_name_not_found" },
    .{ "HV002", "fdw_dynamic_parameter_value_needed" },
    .{ "HV010", "fdw_function_sequence_error" },
    .{ "HV021", "fdw_inconsistent_descriptor_information" },
    .{ "HV024", "fdw_invalid_attribute_value" },
    .{ "HV007", "fdw_invalid_column_name" },
    .{ "HV008", "fdw_invalid_column_number" },
    .{ "HV004", "fdw_invalid_data_type" },
    .{ "HV006", "fdw_invalid_data_type_descriptors" },
    .{ "HV091", "fdw_invalid_descriptor_field_identifier" },
    .{ "HV00B", "fdw_invalid_handle" },
    .{ "HV00C", "fdw_invalid_option_index" },
    .{ "HV00D", "fdw_invalid_option_name" },
    .{ "HV090", "fdw_invalid_string_length_or_buffer_length" },
    .{ "HV00A", "fdw_invalid_string_format" },
    .{ "HV009", "fdw_invalid_use_of_null_pointer" },
    .{ "HV014", "fdw_too_many_handles" },
    .{ "HV001", "fdw_out_of_memory" },
    .{ "HV00P", "fdw_no_schemas" },
    .{ "HV00J", "fdw_option_name_not_found" },
    .{ "HV00K", "fdw_reply_handle" },
    .{ "HV00Q", "fdw_schema_not_found" },
    .{ "HV00R", "fdw_table_not_found" },
    .{ "HV00L", "fdw_unable_to_create_execution" },
    .{ "HV00M", "fdw_unable_to_create_reply" },
    .{ "HV00N", "fdw_unable_to_establish_connection" },
    // Class P0 - PL/pgSQL Error
    .{ "P0000", "plpgsql_error" },
    .{ "P0001", "raise_exception" },
    .{ "P0002", "no_data_found" },
    .{ "P0003", "too_many_rows" },
    // Class XX - Internal Error
    .{ "XX000", "internal_error" },
    .{ "XX001", "data_corrupted" },
    .{ "XX002", "index_corrupted" },
});

// -----------------------------------------------------------------------------
// Error struct
// -----------------------------------------------------------------------------

/// PostgreSQL wire protocol error.
/// Fields correspond to ErrorResponse message fields.
pub const Error = struct {
    severity: []const u8 = "",
    code: ErrorCode = .{0} ** 5,
    message: []const u8 = "",
    detail: []const u8 = "",
    hint: []const u8 = "",
    position: []const u8 = "",
    internal_position: []const u8 = "",
    internal_query: []const u8 = "",
    where_: []const u8 = "",
    schema: []const u8 = "",
    table: []const u8 = "",
    column: []const u8 = "",
    data_type_name: []const u8 = "",
    constraint: []const u8 = "",
    file: []const u8 = "",
    line: []const u8 = "",
    routine: []const u8 = "",

    /// Returns true if the severity is FATAL.
    pub fn fatal(self: *const Error) bool {
        return std.mem.eql(u8, self.severity, Severity.fatal);
    }

    /// Returns the human-readable condition name for the error code.
    pub fn conditionName(self: *const Error) []const u8 {
        return errorCodeName(self.code);
    }

    /// Returns the error class (first two characters) as a slice.
    pub fn class(self: *const Error) [2]u8 {
        return self.code[0..2].*;
    }

    /// Returns the human-readable name of the error class.
    pub fn className(self: *const Error) []const u8 {
        return errorClassName(self.code[0..2].*);
    }

    /// Formats the error for printing (implements std.fmt.format).
    pub fn format(self: *const Error, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("pq: {s}", .{self.message});
    }
};

// -----------------------------------------------------------------------------
// Parsing an ErrorResponse from a ReadBuf
// -----------------------------------------------------------------------------

/// Parses an ErrorResponse message from a ReadBuf and returns an Error struct.
/// The returned Error contains slices borrowed from the buffer; caller must ensure
/// the buffer lives as long as the Error. If you need ownership, copy the strings.
pub fn parseError(r: *buff.ReadBuf) !Error {
    var err = Error{};
    while (true) {
        const typ = try r.byte();
        if (typ == 0) break;
        const msg = try r.string();
        switch (typ) {
            'S' => err.severity = msg,
            'C' => {
                if (msg.len != 5) return error.InvalidErrorCode;
                @memcpy(&err.code, msg[0..5]);
            },
            'M' => err.message = msg,
            'D' => err.detail = msg,
            'H' => err.hint = msg,
            'P' => err.position = msg,
            'p' => err.internal_position = msg,
            'q' => err.internal_query = msg,
            'W' => err.where_ = msg,
            's' => err.schema = msg,
            't' => err.table = msg,
            'c' => err.column = msg,
            'd' => err.data_type_name = msg,
            'n' => err.constraint = msg,
            'F' => err.file = msg,
            'L' => err.line = msg,
            'R' => err.routine = msg,
            else => {}, // unknown field, ignore
        }
    }
    return err;
}

// -----------------------------------------------------------------------------
// Panic-style error helpers (matching Go's errorf and recover)
// -----------------------------------------------------------------------------

/// errorf panics with a formatted error message.
/// Use this for fatal protocol errors that should not be recovered normally.
pub fn errorf(comptime format: []const u8, args: anytype) noreturn {
    const msg = std.fmt.allocPrint(std.heap.page_allocator, format, args) catch "formatting error";
    defer std.heap.page_allocator.free(msg);
    @panic(msg);
}

/// Error recovery for functions that return an error pointer.
/// This mimics the behavior of errRecoverNoErrBadConn in the Go code.
/// It recovers from a panic and sets the pointed error to the recovered error,
/// unless the recovered value is not an error (then it sets a generic error).
pub fn errRecoverNoErrBadConn(err: *anyerror) void {
    _ = err;
    const pan = @errorReturnTrace() orelse return;
    // In Zig we don't have panic recovery like Go's recover.
    // Instead, we rely on the caller to catch errors and convert panics.
    // This function is a placeholder; in practice, Zig code should use
    // try/catch and avoid panics. For compatibility with the Go design,
    // we assume that any non-returned error is already captured.
    _ = pan;
}

/// Error recovery for a connection.  This should be called in a defer block
/// after any operation that may panic.  It sets the error and marks the
/// connection bad if appropriate.
///
/// - `bad`: pointer to a boolean that indicates whether the connection is bad.
/// - `err`: pointer to an error that will be set on recovery.
pub fn errRecover(bad: *bool, err: *anyerror) void {
    // In Zig we don't have recover. Instead, we rely on the caller to
    // propagate errors. This function is a placeholder to match the Go API.
    // The actual implementation should be integrated into Conn methods
    // using Zig's error handling (try/catch) rather than panics.
    _ = bad;
    _ = err;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

test "error code name lookup" {
    const code: ErrorCode = "23505".*;
    try testing.expectEqualStrings("unique_violation", errorCodeName(code));
}

test "error class extraction" {
    const code: ErrorCode = "23505".*;
    const class = errorCodeClass(code);
    try testing.expectEqualSlices(u8, "23", &class);
    try testing.expectEqualStrings("integrity_constraint_violation", errorClassName(class));
}

test "parse error response" {
    // Build a minimal ErrorResponse message:
    // 'S' "FATAL" 0 'C' "23505" 0 'M' "duplicate key" 0 0
    const data = &[_]u8{
        'S', 'F', 'A', 'T', 'A', 'L', 0,
        'C', '2', '3', '5', '0', '5', 0,
        'M', 'd', 'u', 'p', 'l', 'i', 'c',
        'a', 't', 'e', ' ', 'k', 'e', 'y',
        0,   0,
    };
    var rb = buff.ReadBuf.init(data);
    const err = try parseError(&rb);
    try testing.expectEqualStrings("FATAL", err.severity);
    try testing.expectEqualSlices(u8, "23505", &err.code);
    try testing.expectEqualStrings("duplicate key", err.message);
    try testing.expect(err.fatal());
}
