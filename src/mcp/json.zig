// Minimal JSON writer and parser for MCP protocol.
// No allocations for writing (writes to a fixed buffer).
// Parsing uses std.json.

const std = @import("std");

pub const JsonWriter = struct {
    buf: []u8,
    pos: usize = 0,
    overflow: bool = false,

    pub fn init(buf: []u8) JsonWriter {
        return .{ .buf = buf, .pos = 0, .overflow = false };
    }

    pub fn raw(self: *JsonWriter, s: []const u8) void {
        if (self.pos + s.len > self.buf.len) {
            self.overflow = true;
            return;
        }
        @memcpy(self.buf[self.pos..][0..s.len], s);
        self.pos += s.len;
    }

    pub fn beginObject(self: *JsonWriter) void {
        self.raw("{");
    }
    pub fn endObject(self: *JsonWriter) void {
        // overwrite trailing comma if present
        if (self.pos > 0 and self.buf[self.pos - 1] == ',') self.pos -= 1;
        self.raw("}");
    }

    pub fn beginArray(self: *JsonWriter) void {
        self.raw("[");
    }
    pub fn endArray(self: *JsonWriter) void {
        if (self.pos > 0 and self.buf[self.pos - 1] == ',') self.pos -= 1;
        self.raw("]");
    }

    pub fn key(self: *JsonWriter, name: []const u8) void {
        self.writeString(name);
        self.raw(":");
    }

    pub fn fieldStr(self: *JsonWriter, name: []const u8, value: []const u8) void {
        self.key(name);
        self.writeString(value);
        self.raw(",");
    }

    pub fn fieldInt(self: *JsonWriter, name: []const u8, value: anytype) void {
        self.key(name);
        self.writeInt(value);
        self.raw(",");
    }

    pub fn fieldBool(self: *JsonWriter, name: []const u8, value: bool) void {
        self.key(name);
        self.raw(if (value) "true" else "false");
        self.raw(",");
    }

    pub fn fieldNull(self: *JsonWriter, name: []const u8) void {
        self.key(name);
        self.raw("null,");
    }

    pub fn fieldRaw(self: *JsonWriter, name: []const u8, value: []const u8) void {
        self.key(name);
        self.raw(value);
        self.raw(",");
    }

    pub fn writeString(self: *JsonWriter, s: []const u8) void {
        self.raw("\"");
        for (s) |c| {
            switch (c) {
                '"' => self.raw("\\\""),
                '\\' => self.raw("\\\\"),
                '\n' => self.raw("\\n"),
                '\r' => self.raw("\\r"),
                '\t' => self.raw("\\t"),
                // RFC 8259 requires U+0000..U+001F to be escaped. Tool output
                // (Echo, symbol/comment text, debugger strings) can carry them
                // verbatim; emitting the raw byte produces JSON that strict
                // parsers reject with "Bad control character".
                0x00...0x08, 0x0B, 0x0C, 0x0E...0x1F => {
                    var esc: [6]u8 = undefined;
                    const hex = std.fmt.bufPrint(&esc, "\\u{x:0>4}", .{c}) catch return;
                    self.raw(hex);
                },
                else => {
                    if (self.pos < self.buf.len) {
                        self.buf[self.pos] = c;
                        self.pos += 1;
                    }
                },
            }
        }
        self.raw("\"");
    }

    pub fn writeInt(self: *JsonWriter, value: anytype) void {
        var tmp: [24]u8 = undefined;
        const T = @TypeOf(value);
        const s = switch (@typeInfo(T)) {
            .int => std.fmt.bufPrint(&tmp, "{d}", .{value}) catch return,
            .comptime_int => std.fmt.bufPrint(&tmp, "{d}", .{value}) catch return,
            else => std.fmt.bufPrint(&tmp, "{d}", .{value}) catch return,
        };
        self.raw(s);
    }

    pub fn writeHex(self: *JsonWriter, value: usize) void {
        self.raw("\"0x");
        var tmp: [20]u8 = undefined;
        const s = std.fmt.bufPrint(&tmp, "{X}", .{value}) catch return;
        self.raw(s);
        self.raw("\"");
    }

    pub fn slice(self: *const JsonWriter) []const u8 {
        return self.buf[0..self.pos];
    }
};

// ── Minimal JSON value lookup (for parsing incoming requests) ───────

pub fn getStringField(parsed: std.json.Value, field: []const u8) ?[]const u8 {
    if (parsed != .object) return null;
    const obj = parsed.object;
    const val = obj.get(field) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

pub fn getIntField(parsed: std.json.Value, field: []const u8) ?i64 {
    if (parsed != .object) return null;
    const obj = parsed.object;
    const val = obj.get(field) orelse return null;
    return switch (val) {
        .integer => |i| i,
        else => null,
    };
}

pub fn getObjectField(parsed: std.json.Value, field: []const u8) ?std.json.Value {
    if (parsed != .object) return null;
    const obj = parsed.object;
    return obj.get(field);
}

/// Address-style lookup: accepts a JSON string ("0x...", symbol, or
/// expression) or a JSON integer, formatted as "0x{X}" into buf so the
/// result can be handed to the debugger's expression parser.
/// Returns null for negative integers and non-string/non-integer values.
pub fn getAddrField(parsed: std.json.Value, field: []const u8, buf: []u8) ?[]const u8 {
    if (parsed != .object) return null;
    const obj = parsed.object;
    const val = obj.get(field) orelse return null;
    return switch (val) {
        .string => |s| s,
        .integer => |i| if (i < 0) null else std.fmt.bufPrint(buf, "0x{X}", .{i}) catch null,
        else => null,
    };
}

// ── Tests ───────────────────────────────────────────────────────────

test "JsonWriter writes a simple object" {
    var buf: [256]u8 = undefined;
    var w = JsonWriter.init(&buf);
    w.beginObject();
    w.fieldStr("name", "alice");
    w.fieldInt("age", 30);
    w.fieldBool("active", true);
    w.endObject();
    try std.testing.expectEqualStrings("{\"name\":\"alice\",\"age\":30,\"active\":true}", w.slice());
}

test "JsonWriter escapes special characters in strings" {
    var buf: [256]u8 = undefined;
    var w = JsonWriter.init(&buf);
    w.writeString("a\"b\\c\nd\re\tf");
    try std.testing.expectEqualStrings("\"a\\\"b\\\\c\\nd\\re\\tf\"", w.slice());
}

test "JsonWriter escapes remaining control characters as \\u00XX" {
    var buf: [256]u8 = undefined;
    var w = JsonWriter.init(&buf);
    // SOH, backspace, form feed, unit separator — each illegal unescaped.
    w.writeString("a\x01b\x08c\x0cd\x1fe");
    try std.testing.expectEqualStrings(
        "\"a\\u0001b\\u0008c\\u000cd\\u001fe\"",
        w.slice(),
    );
}

test "JsonWriter control-character output parses as JSON" {
    var buf: [256]u8 = undefined;
    var w = JsonWriter.init(&buf);
    w.beginObject();
    w.fieldStr("text", "x\x01y\x08z");
    w.endObject();

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, w.slice(), .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("x\x01y\x08z", parsed.value.object.get("text").?.string);
}

test "JsonWriter writes null and raw fields" {
    var buf: [256]u8 = undefined;
    var w = JsonWriter.init(&buf);
    w.beginObject();
    w.fieldNull("nothing");
    w.fieldRaw("raw", "[1,2,3]");
    w.endObject();
    try std.testing.expectEqualStrings("{\"nothing\":null,\"raw\":[1,2,3]}", w.slice());
}

test "JsonWriter writes nested arrays" {
    var buf: [256]u8 = undefined;
    var w = JsonWriter.init(&buf);
    w.beginArray();
    w.writeInt(1);
    w.raw(",");
    w.writeInt(2);
    w.raw(",");
    w.writeInt(3);
    w.endArray();
    try std.testing.expectEqualStrings("[1,2,3]", w.slice());
}

test "JsonWriter writes hex value" {
    var buf: [64]u8 = undefined;
    var w = JsonWriter.init(&buf);
    w.writeHex(0xDEADBEEF);
    try std.testing.expectEqualStrings("\"0xDEADBEEF\"", w.slice());
}

test "JsonWriter handles buffer overflow gracefully" {
    // 7 bytes exactly fits "hello" (quotes + 5 chars)
    var buf: [7]u8 = undefined;
    var w = JsonWriter.init(&buf);
    w.writeString("hello");
    try std.testing.expectEqualStrings("\"hello\"", w.slice());
    // buffer is full; further writes are ignored (no panic, no corruption)
    w.writeString("this-is-way-too-long-for-the-buffer");
    try std.testing.expectEqualStrings("\"hello\"", w.slice());
}

test "JsonWriter strips trailing comma on endObject" {
    var buf: [64]u8 = undefined;
    var w = JsonWriter.init(&buf);
    w.beginObject();
    w.fieldStr("k", "v");
    w.endObject();
    try std.testing.expectEqualStrings("{\"k\":\"v\"}", w.slice());
}

test "getStringField returns value for string field" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"name":"alice","age":30}
    , .{});
    defer parsed.deinit();
    const val = getStringField(parsed.value, "name");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("alice", val.?);
}

test "getStringField returns null for non-string field" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"age":30}
    , .{});
    defer parsed.deinit();
    try std.testing.expect(getStringField(parsed.value, "age") == null);
}

test "getStringField returns null for missing field" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"name":"alice"}
    , .{});
    defer parsed.deinit();
    try std.testing.expect(getStringField(parsed.value, "missing") == null);
}

test "getIntField returns value for integer field" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"count":42}
    , .{});
    defer parsed.deinit();
    const val = getIntField(parsed.value, "count");
    try std.testing.expect(val != null);
    try std.testing.expectEqual(@as(i64, 42), val.?);
}

test "getIntField returns null for non-integer field" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"name":"alice"}
    , .{});
    defer parsed.deinit();
    try std.testing.expect(getIntField(parsed.value, "name") == null);
}

test "getObjectField returns nested object" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"meta":{"key":"value"}}
    , .{});
    defer parsed.deinit();
    const obj = getObjectField(parsed.value, "meta");
    try std.testing.expect(obj != null);
    try std.testing.expect(obj.? == .object);
}

test "getObjectField returns null for non-object root" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\[1,2,3]
    , .{});
    defer parsed.deinit();
    try std.testing.expect(getObjectField(parsed.value, "0") == null);
}

test "getAddrField passes string addresses through unchanged" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"address":"0x1400016B0"}
    , .{});
    defer parsed.deinit();
    var buf: [32]u8 = undefined;
    const val = getAddrField(parsed.value, "address", &buf);
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("0x1400016B0", val.?);
}

test "getAddrField formats integer addresses as hex" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"address":5368714928}
    , .{});
    defer parsed.deinit();
    var buf: [32]u8 = undefined;
    const val = getAddrField(parsed.value, "address", &buf);
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("0x1400016B0", val.?);
}

test "getAddrField formats zero as 0x0" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"address":0}
    , .{});
    defer parsed.deinit();
    var buf: [32]u8 = undefined;
    const val = getAddrField(parsed.value, "address", &buf);
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("0x0", val.?);
}

test "getAddrField rejects negative integers and floats" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"neg":-1,"f":1.5}
    , .{});
    defer parsed.deinit();
    var buf: [32]u8 = undefined;
    try std.testing.expect(getAddrField(parsed.value, "neg", &buf) == null);
    try std.testing.expect(getAddrField(parsed.value, "f", &buf) == null);
}

test "getAddrField rejects non-address types and missing fields" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"b":true,"arr":[1]}
    , .{});
    defer parsed.deinit();
    var buf: [32]u8 = undefined;
    try std.testing.expect(getAddrField(parsed.value, "b", &buf) == null);
    try std.testing.expect(getAddrField(parsed.value, "arr", &buf) == null);
    try std.testing.expect(getAddrField(parsed.value, "missing", &buf) == null);
}

test "getAddrField returns null when the buffer is too small" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"address":5368714928}
    , .{});
    defer parsed.deinit();
    var buf: [4]u8 = undefined;
    try std.testing.expect(getAddrField(parsed.value, "address", &buf) == null);
}
