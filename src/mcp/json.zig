// Minimal JSON writer and parser for MCP protocol.
// The writer can either fill a fixed buffer or grow a ByteBuffer, so a
// response that grows with the content (the tool list) cannot be
// truncated.  Parsing uses std.json.

const std = @import("std");

/// A growable byte buffer.
///
/// std.ArrayList changed shape between Zig 0.14 and 0.17 (managed vs.
/// unmanaged, different method signatures), so this buffer keeps its own
/// small implementation and builds under both.
pub const ByteBuffer = struct {
    allocator: std.mem.Allocator,
    buf: []u8 = &.{},
    len: usize = 0,
    cap: usize = 0,
    /// Set when an allocation failed and bytes had to be dropped.
    failed: bool = false,

    pub fn init(allocator: std.mem.Allocator) ByteBuffer {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ByteBuffer) void {
        if (self.cap > 0) self.allocator.free(self.buf[0..self.cap]);
        self.* = undefined;
    }

    fn reserve(self: *ByteBuffer, extra: usize) bool {
        const needed = self.len + extra;
        if (needed <= self.cap) return true;
        var new_cap: usize = if (self.cap == 0) 256 else self.cap;
        while (new_cap < needed) new_cap *= 2;
        const new_buf = self.allocator.alloc(u8, new_cap) catch {
            self.failed = true;
            return false;
        };
        if (self.cap > 0) {
            @memcpy(new_buf[0..self.len], self.buf[0..self.len]);
            self.allocator.free(self.buf[0..self.cap]);
        }
        self.buf = new_buf;
        self.cap = new_cap;
        return true;
    }

    pub fn append(self: *ByteBuffer, bytes: []const u8) void {
        if (bytes.len == 0) return;
        if (!self.reserve(bytes.len)) return;
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    pub fn appendByte(self: *ByteBuffer, byte: u8) void {
        if (!self.reserve(1)) return;
        self.buf[self.len] = byte;
        self.len += 1;
    }

    pub fn popLast(self: *ByteBuffer) void {
        if (self.len > 0) self.len -= 1;
    }

    pub fn lastByte(self: *const ByteBuffer) ?u8 {
        if (self.len == 0) return null;
        return self.buf[self.len - 1];
    }

    pub fn slice(self: *const ByteBuffer) []const u8 {
        return self.buf[0..self.len];
    }
};

pub const JsonWriter = struct {
    /// Fixed output buffer.  Unused when `grow` is set.
    buf: []u8,
    pos: usize = 0,
    /// When set, the writer appends to this buffer instead of `buf`, so
    /// the output grows with the content.
    grow: ?*ByteBuffer = null,
    /// Set when a write had to be dropped.  A truncated document is not
    /// valid JSON, so callers check this before sending it.
    truncated: bool = false,

    pub fn init(buf: []u8) JsonWriter {
        return .{ .buf = buf, .pos = 0 };
    }

    /// A writer whose output grows with the content.
    pub fn initGrowable(buffer: *ByteBuffer) JsonWriter {
        return .{ .buf = buffer.buf[0..0], .pos = 0, .grow = buffer };
    }
    /// Whether bytes had to be dropped, which means the output is not
    /// valid JSON.
    pub fn isTruncated(self: *const JsonWriter) bool {
        return self.truncated;
    }

    fn append(self: *JsonWriter, s: []const u8) void {
        if (self.grow) |buffer| {
            buffer.append(s);
            if (buffer.failed) self.truncated = true;
            return;
        }
        if (self.pos + s.len > self.buf.len) {
            self.truncated = true;
            return;
        }
        @memcpy(self.buf[self.pos..][0..s.len], s);
        self.pos += s.len;
    }

    fn appendByte(self: *JsonWriter, c: u8) void {
        if (self.grow) |buffer| {
            buffer.appendByte(c);
            if (buffer.failed) self.truncated = true;
            return;
        }
        if (self.pos < self.buf.len) {
            self.buf[self.pos] = c;
            self.pos += 1;
        } else {
            self.truncated = true;
        }
    }

    pub fn raw(self: *JsonWriter, s: []const u8) void {
        self.append(s);
    }

    pub fn beginObject(self: *JsonWriter) void {
        self.raw("{");
    }
    pub fn endObject(self: *JsonWriter) void {
        // overwrite trailing comma if present
        if (self.lastByte() == ',') self.popLast();
        self.raw("}");
    }

    pub fn beginArray(self: *JsonWriter) void {
        self.raw("[");
    }
    pub fn endArray(self: *JsonWriter) void {
        if (self.lastByte() == ',') self.popLast();
        self.raw("]");
    }

    fn lastByte(self: *const JsonWriter) ?u8 {
        if (self.grow) |buffer| return buffer.lastByte();
        if (self.pos == 0) return null;
        return self.buf[self.pos - 1];
    }

    fn popLast(self: *JsonWriter) void {
        if (self.grow) |buffer| {
            buffer.popLast();
            return;
        }
        if (self.pos > 0) self.pos -= 1;
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
                else => self.appendByte(c),
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
        if (self.grow) |buffer| return buffer.slice();
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

test "JsonWriter reports truncation instead of dropping bytes silently" {
    var buf: [16]u8 = undefined;
    var w = JsonWriter.init(&buf);
    w.raw("0123456789abcdef"); // exactly fits
    try std.testing.expect(!w.isTruncated());
    w.raw("g"); // one byte too many
    try std.testing.expect(w.isTruncated());
}

test "ByteBuffer grows with the content" {
    var buffer = ByteBuffer.init(std.testing.allocator);
    defer buffer.deinit();

    buffer.append("hello");
    buffer.appendByte('!');
    try std.testing.expectEqualStrings("hello!", buffer.slice());

    buffer.popLast();
    try std.testing.expectEqualStrings("hello", buffer.slice());
    try std.testing.expectEqual(@as(?u8, 'o'), buffer.lastByte());
}

test "a tool list larger than the old fixed buffer stays complete and parseable" {
    // tools/list used to be written into a 64 KB buffer, and the writer
    // dropped whatever did not fit — the client then received truncated,
    // invalid JSON instead of an error.  The response now grows with the
    // content, so a tool list of any size comes out whole.
    var buffer = ByteBuffer.init(std.testing.allocator);
    defer buffer.deinit();

    var w = JsonWriter.initGrowable(&buffer);
    w.beginObject();
    w.key("tools");
    w.beginArray();
    var i: usize = 0;
    while (i < 400) : (i += 1) {
        w.beginObject();
        w.fieldStr("name", "ToolWithALongEnoughNameToFillTheOldBuffer");
        w.fieldStr("description", "A description long enough to push the tool list past the size of the buffer that used to hold it, so the response has to grow with the content.");
        w.key("inputSchema");
        w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\"}}}");
        w.raw(",");
        w.endObject();
        w.raw(",");
    }
    w.endArray();
    w.endObject();

    try std.testing.expect(!w.isTruncated());
    try std.testing.expect(buffer.slice().len > 65536);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, buffer.slice(), .{});
    defer parsed.deinit();

    const tools = parsed.value.object.get("tools").?.array;
    try std.testing.expectEqual(@as(usize, 400), tools.items.len);
    for (tools.items) |item| {
        try std.testing.expect(item.object.get("name") != null);
        try std.testing.expect(item.object.get("description") != null);
        try std.testing.expect(item.object.get("inputSchema") != null);
    }
}

test "a growable writer produces the same document as a fixed one" {
    var fixed_buf: [4096]u8 = undefined;
    var w_fixed = JsonWriter.init(&fixed_buf);
    var grow_buf = ByteBuffer.init(std.testing.allocator);
    defer grow_buf.deinit();
    var w_grow = JsonWriter.initGrowable(&grow_buf);

    w_fixed.beginObject();
    w_grow.beginObject();
    w_fixed.fieldStr("name", "alice");
    w_grow.fieldStr("name", "alice");
    w_fixed.fieldInt("age", 30);
    w_grow.fieldInt("age", 30);
    w_fixed.beginArray();
    w_grow.beginArray();
    w_fixed.writeString("x\"y");
    w_grow.writeString("x\"y");
    w_fixed.endArray();
    w_grow.endArray();
    w_fixed.endObject();
    w_grow.endObject();

    try std.testing.expectEqualStrings(w_fixed.slice(), w_grow.slice());
    try std.testing.expect(!w_grow.isTruncated());
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
