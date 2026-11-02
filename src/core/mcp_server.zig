// MCP server — supports both Streamable HTTP and SSE transports.

const std = @import("std");
const bridge = @import("bridge.zig");
const sync = @import("sync.zig");
const tools_mod = @import("../mcp/tools.zig");
const json_mod = @import("../mcp/json.zig");
const JsonWriter = json_mod.JsonWriter;

const ws2 = @import("winsock.zig");
const SOCKET = ws2.SOCKET;
const INVALID_SOCKET = ws2.INVALID_SOCKET;

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_NAME = "x64dbg-MCP Server";
pub const SERVER_VERSION = "1.6";

// Win32 threading
const HANDLE = ?*anyopaque;
extern "kernel32" fn Sleep(ms: u32) callconv(.winapi) void;
extern "kernel32" fn CreateThread(
    lpThreadAttributes: ?*anyopaque,
    dwStackSize: usize,
    lpStartAddress: *const fn (?*anyopaque) callconv(.winapi) u32,
    lpParameter: ?*anyopaque,
    dwCreationFlags: u32,
    lpThreadId: ?*u32,
) callconv(.winapi) HANDLE;
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.winapi) i32;
extern "kernel32" fn WaitForSingleObject(hHandle: ?*anyopaque, dwMilliseconds: u32) callconv(.winapi) u32;

var server_handle: HANDLE = null;
var running_flag: bool = false;
var state_lock: sync.Mutex = .{};
var listen_sock: SOCKET = INVALID_SOCKET;

/// Prepare the locks that guard the state shared between x64dbg's
/// debugger callbacks and the HTTP worker threads.
pub fn initLocks() void {
    state_lock.init();
    pending_lock.init();
    sse_lock.init();
}

/// Whether the MCP server is currently serving.
pub fn isRunning() bool {
    state_lock.lock();
    defer state_lock.unlock();
    return running_flag;
}

fn setRunning(value: bool) void {
    state_lock.lock();
    defer state_lock.unlock();
    running_flag = value;
}

var server_port: u16 = 9094;
/// The port the server actually bound.  It differs from the configured
/// port when that one was already taken.
var bound_port: u16 = 0;
// "127.0.0.1" followed by zero padding, so the default bind address is
// already correct before setConfig() runs.
const ip_default_padding: [55]u8 = @splat(0);
var server_ip: [64]u8 = .{ '1', '2', '7', '.', '0', '.', '0', '.', '1' } ++ ip_default_padding;
var server_ip_len: usize = 9;
var auth_token: [64]u8 = @splat(0);
var auth_token_len: usize = 0;

/// The bind address, the port and the auth token are written by the
/// config dialog on x64dbg's GUI thread and read by the server thread
/// and the HTTP worker threads, so they are guarded by the state lock.
pub fn setConfig(ip: []const u8, port: u16, token: []const u8) void {
    state_lock.lock();
    defer state_lock.unlock();
    server_port = port;
    if (ip.len > 0 and ip.len < 64) {
        @memcpy(server_ip[0..ip.len], ip);
        server_ip_len = ip.len;
    } else {
        const default = "127.0.0.1";
        @memcpy(server_ip[0..default.len], default);
        server_ip_len = default.len;
    }
    if (token.len > 0 and token.len <= 64) {
        @memcpy(auth_token[0..token.len], token);
        auth_token_len = token.len;
    } else {
        auth_token_len = 0;
    }
}

/// Copy the configured bind address and port out of the shared state.
fn bindTarget(ip_buf: []u8, port: *u16) usize {
    state_lock.lock();
    defer state_lock.unlock();
    const n = @min(server_ip_len, ip_buf.len);
    @memcpy(ip_buf[0..n], server_ip[0..n]);
    port.* = server_port;
    return n;
}

/// The port the server is listening on.
fn currentPort() u16 {
    state_lock.lock();
    defer state_lock.unlock();
    return server_port;
}

/// The port the server actually bound, or 0 when it is not serving.
fn currentBoundPort() u16 {
    state_lock.lock();
    defer state_lock.unlock();
    return bound_port;
}

/// Check a bearer token against the configured one.
fn authTokenMatches(bearer: []const u8) bool {
    state_lock.lock();
    defer state_lock.unlock();
    if (auth_token_len == 0 or bearer.len != auth_token_len) return false;
    return std.mem.eql(u8, bearer, auth_token[0..auth_token_len]);
}

fn parseIpAddr(ip: []const u8) u32 {
    if (ip.len == 0) return 0; // INADDR_ANY
    // "0.0.0.0" -> INADDR_ANY
    if (std.mem.eql(u8, ip, "0.0.0.0")) return 0;

    var octets: [4]u8 = .{ 0, 0, 0, 0 };
    var octet_idx: usize = 0;
    var val: u32 = 0;
    for (ip) |c| {
        if (c == '.') {
            if (octet_idx >= 3 or val > 255) return 0;
            octets[octet_idx] = @intCast(val);
            octet_idx += 1;
            val = 0;
        } else if (c >= '0' and c <= '9') {
            val = val * 10 + (c - '0');
        } else {
            return 0;
        }
    }
    if (octet_idx != 3 or val > 255) return 0;
    octets[3] = @intCast(val);
    return @bitCast(octets);
}

// ── Pending events queue (for HTTP clients that can't receive SSE) ──
//
// The queue is filled by x64dbg's debugger callbacks and drained by the
// HTTP worker threads, so it is guarded by its own lock.
const MAX_PENDING_EVENTS = 16;
const MAX_EVENT_LEN = 128;
var pending_events: [MAX_PENDING_EVENTS][MAX_EVENT_LEN]u8 = undefined;
var pending_event_lens: [MAX_PENDING_EVENTS]usize = @splat(0);
var pending_head: usize = 0;
var pending_count: usize = 0;
var pending_lock: sync.Mutex = .{};

/// A copy of the pending queue, taken while holding the lock.
const PendingSnapshot = struct {
    count: usize = 0,
    lens: [MAX_PENDING_EVENTS]usize = @splat(0),
    texts: [MAX_PENDING_EVENTS][MAX_EVENT_LEN]u8 = undefined,
};

/// Take everything that is queued and empty the queue.
fn pendingTake() PendingSnapshot {
    var snap: PendingSnapshot = .{};
    pending_lock.lock();
    defer pending_lock.unlock();
    snap.count = pending_count;
    var i: usize = 0;
    while (i < pending_count) : (i += 1) {
        const slot = (pending_head + i) % MAX_PENDING_EVENTS;
        snap.lens[i] = pending_event_lens[slot];
        @memcpy(snap.texts[i][0..snap.lens[i]], pending_events[slot][0..snap.lens[i]]);
    }
    pending_head = 0;
    pending_count = 0;
    return snap;
}

pub fn pendingHasEvents() bool {
    pending_lock.lock();
    defer pending_lock.unlock();
    return pending_count > 0;
}

pub fn pendingDrainToBuffer(out: []u8) usize {
    const snap = pendingTake();
    var pos: usize = 0;
    var i: usize = 0;
    while (i < snap.count) : (i += 1) {
        const event_text = snap.texts[i][0..snap.lens[i]];
        if (pos > 0 and pos < out.len) {
            out[pos] = '\n';
            pos += 1;
        }
        const copy_len = @min(event_text.len, out.len - pos);
        if (copy_len == 0) break;
        @memcpy(out[pos .. pos + copy_len], event_text[0..copy_len]);
        pos += copy_len;
    }
    return pos;
}

fn pendingPush(msg: []const u8) void {
    const copy_len = @min(msg.len, MAX_EVENT_LEN);
    pending_lock.lock();
    defer pending_lock.unlock();
    const slot = (pending_head + pending_count) % MAX_PENDING_EVENTS;
    @memcpy(pending_events[slot][0..copy_len], msg[0..copy_len]);
    pending_event_lens[slot] = copy_len;
    if (pending_count < MAX_PENDING_EVENTS) {
        pending_count += 1;
    } else {
        pending_head = (pending_head + 1) % MAX_PENDING_EVENTS;
    }
}

fn pendingDrain(w: *JsonWriter) void {
    const snap = pendingTake();
    var i: usize = 0;
    while (i < snap.count) : (i += 1) {
        w.raw(",");
        w.beginObject();
        w.fieldStr("type", "text");
        w.key("text");
        w.writeString(snap.texts[i][0..snap.lens[i]]);
        w.endObject();
    }
}

// ── SSE client tracking ────────────────────────────────────────────
//
// The client table is written by the HTTP worker threads and read by the
// debugger callback thread that pushes notifications.
/// How many ports the server tries before it gives up: the configured
/// one plus the next MAX_PORT_ATTEMPTS - 1.
const MAX_PORT_ATTEMPTS = 32;

const MAX_SSE_CLIENTS = 8;var sse_clients: [MAX_SSE_CLIENTS]SOCKET = @splat(INVALID_SOCKET);
var sse_session_ids: [MAX_SSE_CLIENTS][32]u8 = undefined;
var sse_session_lens: [MAX_SSE_CLIENTS]usize = @splat(0);
var sse_next_id: u32 = 1;
var sse_lock: sync.Mutex = .{};

/// A slot of the SSE client table.
const SseSlot = struct {
    index: usize,
    session_id: [32]u8 = undefined,
    session_len: usize = 0,
};

/// Register an SSE client.  Returns null when no slot is free.
fn sseAddClient(sock: SOCKET) ?SseSlot {
    sse_lock.lock();
    defer sse_lock.unlock();
    for (0..MAX_SSE_CLIENTS) |i| {
        if (sse_clients[i] == INVALID_SOCKET) {
            sse_clients[i] = sock;
            const id = sse_next_id;
            sse_next_id +%= 1;
            const len = fmtU32(id, &sse_session_ids[i]);
            sse_session_lens[i] = len;
            var slot: SseSlot = .{ .index = i };
            @memcpy(slot.session_id[0..len], sse_session_ids[i][0..len]);
            slot.session_len = len;
            return slot;
        }
    }
    return null;
}

/// Release a slot.  The socket is checked so a late disconnect cannot
/// clear a slot that has meanwhile been handed to another client.
fn sseRemoveClient(idx: usize, sock: SOCKET) void {
    if (idx >= MAX_SSE_CLIENTS) return;
    sse_lock.lock();
    defer sse_lock.unlock();
    if (sse_clients[idx] != sock) return;
    sse_clients[idx] = INVALID_SOCKET;
    sse_session_lens[idx] = 0;
}

/// Find the socket of the SSE client with the given session id.
fn sseFindBySessionId(session_id: []const u8) ?SOCKET {
    sse_lock.lock();
    defer sse_lock.unlock();
    for (0..MAX_SSE_CLIENTS) |i| {
        if (sse_clients[i] != INVALID_SOCKET and sse_session_lens[i] > 0) {
            if (std.mem.eql(u8, sse_session_ids[i][0..sse_session_lens[i]], session_id)) {
                return sse_clients[i];
            }
        }
    }
    return null;
}

/// Copy the sockets of all connected SSE clients, so notifications can
/// be pushed without holding the lock across a blocking send.
fn sseSnapshot(socks: *[MAX_SSE_CLIENTS]SOCKET) usize {
    sse_lock.lock();
    defer sse_lock.unlock();
    var n: usize = 0;
    for (0..MAX_SSE_CLIENTS) |i| {
        if (sse_clients[i] != INVALID_SOCKET) {
            socks[n] = sse_clients[i];
            n += 1;
        }
    }
    return n;
}

/// Close every SSE client socket and empty the table.
fn sseCloseAll() void {
    sse_lock.lock();
    defer sse_lock.unlock();
    for (0..MAX_SSE_CLIENTS) |i| {
        if (sse_clients[i] != INVALID_SOCKET) {
            _ = ws2.closesocket(sse_clients[i]);
            sse_clients[i] = INVALID_SOCKET;
        }
        sse_session_lens[i] = 0;
    }
}

fn sseSendEvent(sock: SOCKET, event: []const u8, data: []const u8) void {
    wsSend(sock, "event: ");
    wsSend(sock, event);
    wsSend(sock, "\ndata: ");
    wsSend(sock, data);
    wsSend(sock, "\n\n");
}

pub fn notifyEvent(level: []const u8, msg: []const u8) void {
    if (!isRunning()) return;

    // Queue for HTTP clients — plain text with level prefix
    var pend_buf: [MAX_EVENT_LEN]u8 = undefined;
    const pend_msg = std.fmt.bufPrint(&pend_buf, "[event:{s}] {s}", .{ level, msg }) catch msg;
    pendingPush(pend_msg);

    // Push to SSE clients as JSON-RPC notification
    var buf: [1024]u8 = undefined;
    const json = std.fmt.bufPrint(&buf,
        "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{{\"level\":\"{s}\",\"data\":\"{s}\"}}}}",
        .{ level, msg },
    ) catch return;
    var socks: [MAX_SSE_CLIENTS]SOCKET = undefined;
    const count = sseSnapshot(&socks);
    for (socks[0..count]) |sock| {
        sseSendEvent(sock, "message", json);
    }
}

fn fmtU32(val: u32, buf: *[32]u8) usize {
    if (val == 0) { buf[0] = '0'; return 1; }
    var v = val;
    var tmp: [10]u8 = undefined;
    var i: usize = 0;
    while (v > 0) : (i += 1) {
        tmp[i] = '0' + @as(u8, @intCast(v % 10));
        v /= 10;
    }
    var j: usize = 0;
    while (j < i) : (j += 1) {
        buf[j] = tmp[i - 1 - j];
    }
    return i;
}

fn logListening() void {
    var buf: [192]u8 = undefined;
    var ip_buf: [64]u8 = undefined;
    var port: u16 = 0;
    const ip_len = bindTarget(&ip_buf, &port);
    const listen_port = currentBoundPort();
    const prefix = "[x64dbg-MCP Server] MCP (Streamable) listening on http://";
    @memcpy(buf[0..prefix.len], prefix);
    var pos: usize = prefix.len;
    @memcpy(buf[pos .. pos + ip_len], ip_buf[0..ip_len]);
    pos += ip_len;
    buf[pos] = ':';
    pos += 1;
    pos += fmtPort(if (listen_port != 0) listen_port else port, buf[pos..]);
    buf[pos] = '/';
    pos += 1;
    if (listen_port != 0 and listen_port != port) {
        // The configured port was taken, so the server walked up.
        var note_buf: [96]u8 = undefined;
        const note = std.fmt.bufPrint(&note_buf, " (configured port {d} was in use)", .{port}) catch "";
        @memcpy(buf[pos .. pos + note.len], note);
        pos += note.len;
    }
    buf[pos] = 0;
    bridge.logPuts(@ptrCast(&buf));
}

fn fmtPort(val: u16, buf: []u8) usize {
    if (val == 0) { buf[0] = '0'; return 1; }
    var v = val;
    var tmp: [6]u8 = undefined;
    var i: usize = 0;
    while (v > 0) : (i += 1) {
        tmp[i] = '0' + @as(u8, @intCast(v % 10));
        v /= 10;
    }
    var j: usize = 0;
    while (j < i) : (j += 1) {
        buf[j] = tmp[i - 1 - j];
    }
    return i;
}

pub fn start() void {
    if (isRunning()) {
        bridge.logPuts("[x64dbg-MCP Server] Server already running.\x00");
        return;
    }

    setRunning(true);

    server_handle = CreateThread(null, 0, serverThreadProc, null, 0, null);
    if (server_handle == null) {
        setRunning(false);
        bridge.logPuts("[x64dbg-MCP Server] Failed to create server thread.\x00");
        return;
    }

    {
        var buf: [192]u8 = undefined;
        var ip_buf: [64]u8 = undefined;
        var port: u16 = 0;
        const ip_len = bindTarget(&ip_buf, &port);
        const prefix = "[x64dbg-MCP Server] Starting MCP server on ";
        @memcpy(buf[0..prefix.len], prefix);
        var pos: usize = prefix.len;
        @memcpy(buf[pos .. pos + ip_len], ip_buf[0..ip_len]);
        pos += ip_len;
        buf[pos] = ':';
        pos += 1;
        pos += fmtPort(port, buf[pos..]);
        const suffix = "...";
        @memcpy(buf[pos .. pos + suffix.len], suffix);
        pos += suffix.len;
        buf[pos] = 0;
        bridge.logPuts(@ptrCast(&buf));
    }
}

pub fn stop() void {
    if (!isRunning()) return;
    setRunning(false);

    // Close all SSE client sockets to unblock their keepalive loops
    sseCloseAll();

    // Close listen socket to unblock accept()
    closeListenSocket();

    // Wait for server thread to exit (up to 5s)
    if (server_handle) |h| {
        _ = WaitForSingleObject(h, 5000);
        _ = CloseHandle(h);
        server_handle = null;
    }
    {
        var buf: [192]u8 = undefined;
        var ip_buf: [64]u8 = undefined;
        var port: u16 = 0;
        const ip_len = bindTarget(&ip_buf, &port);
        const listen_port = currentBoundPort();
        const prefix = "[x64dbg-MCP Server] MCP server stopped (was on ";
        @memcpy(buf[0..prefix.len], prefix);
        var pos: usize = prefix.len;
        @memcpy(buf[pos .. pos + ip_len], ip_buf[0..ip_len]);
        pos += ip_len;
        buf[pos] = ':';
        pos += 1;
        pos += fmtPort(if (listen_port != 0) listen_port else port, buf[pos..]);
        buf[pos] = ')';
        pos += 1;
        buf[pos] = 0;
        bridge.logPuts(@ptrCast(&buf));
    }
}

/// Close the listening socket, if one is open.  Used to unblock accept().
fn closeListenSocket() void {
    state_lock.lock();
    defer state_lock.unlock();
    if (listen_sock != INVALID_SOCKET) {
        _ = ws2.closesocket(listen_sock);
        listen_sock = INVALID_SOCKET;
    }
}

fn serverThreadProc(_: ?*anyopaque) callconv(.winapi) u32 {
    serverLoop();
    return 0;
}

fn clientThreadProc(param: ?*anyopaque) callconv(.winapi) u32 {
    const sock: SOCKET = @intCast(@intFromPtr(param.?));
    handleClient(sock);
    return 0;
}

fn serverLoop() void {
    var wsa_data: ws2.WSADATA = undefined;
    if (ws2.WSAStartup(0x0202, &wsa_data) != 0) {
        setRunning(false);
        bridge.logPuts("[x64dbg-MCP Server] WSAStartup failed.\x00");
        return;
    }

    const sock = ws2.socket(@intCast(ws2.AF_INET), ws2.SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        setRunning(false);
        bridge.logPuts("[x64dbg-MCP Server] socket() failed.\x00");
        _ = ws2.WSACleanup();
        return;
    }
    state_lock.lock();
    listen_sock = sock;
    state_lock.unlock();
    defer {
        // stop() may already have closed the listening socket.
        state_lock.lock();
        const still_ours = listen_sock == sock;
        listen_sock = INVALID_SOCKET;
        bound_port = 0;
        state_lock.unlock();
        if (still_ours) _ = ws2.closesocket(sock);
        _ = ws2.WSACleanup();
    }

    const one: i32 = 1;
    _ = ws2.setsockopt(sock, ws2.SOL_SOCKET, ws2.SO_REUSEADDR, @ptrCast(&one), @sizeOf(i32));

    var ip_buf: [64]u8 = undefined;
    var port: u16 = 0;
    const ip_len = bindTarget(&ip_buf, &port);
    const ip = parseIpAddr(ip_buf[0..ip_len]);

    // Walk up to the next free port when the configured one is taken.
    // A second x64dbg instance must not silently stop serving: the
    // plugin binds 9094 by default, and the first instance already has
    // it.
    var bound: u16 = 0;
    var attempt: u16 = 0;
    while (attempt < MAX_PORT_ATTEMPTS) : (attempt += 1) {
        const candidate = port +% attempt;
        if (candidate == 0) break;
        var addr: ws2.SOCKADDR_IN = .{
            .family = ws2.AF_INET,
            .port = ws2.htons(candidate),
            .addr = ip,
        };
        if (ws2.bind(sock, &addr, @sizeOf(ws2.SOCKADDR_IN)) == 0) {
            bound = candidate;
            break;
        }
    }
    if (bound == 0) {
        setRunning(false);
        bridge.logPuts("[x64dbg-MCP Server] bind() failed on every port in the range.\x00");
        return;
    }
    state_lock.lock();
    bound_port = bound;
    state_lock.unlock();

    if (ws2.listen(sock, 10) != 0) {
        setRunning(false);
        bridge.logPuts("[x64dbg-MCP Server] listen() failed.\x00");
        return;
    }

    logListening();

    while (isRunning()) {
        const client = ws2.accept(sock, null, null);
        if (client == INVALID_SOCKET) {
            if (!isRunning()) break;
            continue;
        }

        const h = CreateThread(null, 0, clientThreadProc, @ptrFromInt(client), 0, null);
        if (h == null) {
            _ = ws2.closesocket(client);
        } else {
            _ = CloseHandle(h);
        }
    }

    // Let in-flight client handlers finish before thread exits
    Sleep(200);
}

fn wsSend(sock: SOCKET, data: []const u8) void {
    var sent: usize = 0;
    while (sent < data.len) {
        const remaining = data.len - sent;
        const chunk: i32 = @intCast(@min(remaining, 0x7FFFFFFF));
        const n = ws2.send(sock, @ptrCast(data.ptr + sent), chunk, 0);
        if (n <= 0) return;
        sent += @intCast(n);
    }
}

const RecvResult = struct { buf: [65536]u8 = undefined, len: usize = 0 };

fn wsRecv(sock: SOCKET) RecvResult {
    var result: RecvResult = .{};

    while (result.len < result.buf.len) {
        const max_len: i32 = @intCast(@min(result.buf.len - result.len, 0x7FFFFFFF));
        const n = ws2.recv(sock, result.buf[result.len..].ptr, max_len, 0);
        if (n <= 0) return result;
        result.len += @intCast(n);

        if (findHeaderEnd(result.buf[0..result.len])) |header_end| {
            const content_length = parseContentLength(result.buf[0..header_end]);
            if (content_length == 0 or result.len >= header_end +| 4 +| content_length) break;
        }
    }
    return result;
}

fn handleClient(sock: SOCKET) void {
    const recv_result = wsRecv(sock);
    if (recv_result.len == 0) {
        _ = ws2.closesocket(sock);
        return;
    }

    const request = recv_result.buf[0..recv_result.len];
    const method_line = getFirstLine(request);
    const headers_slice = if (findHeaderEnd(request)) |he| request[0..he] else request;

    // The CORS headers of this request.  Only the origin the server is
    // reachable at is allowed.
    setCorsHeaders(parseHeaderValue(headers_slice, "Origin"));

    {
        const tok = parseHeaderValue(headers_slice, "Authorization");
        var authorized = false;
        if (tok) |t| {
            if (t.len > 7 and std.mem.eql(u8, t[0..7], "Bearer ")) {
                const bearer = t[7..];
                if (authTokenMatches(bearer)) {
                    authorized = true;
                }
            }
        }
        if (!authorized) {
            sendSimple(sock, "401 Unauthorized", "Content-Length: 24\r\n");
            wsSend(sock, "{\"error\":\"Unauthorized\"}");
            _ = ws2.closesocket(sock);
            return;
        }
    }

    // The preflight is authenticated like every other request: the
    // server must not be usable from a web page that a user happens to
    // have open.
    if (std.mem.startsWith(u8, method_line, "OPTIONS ")) {
        sendSimple(sock, "204 No Content", "");
        _ = ws2.closesocket(sock);
        return;
    }

    if (std.mem.startsWith(u8, method_line, "GET ")) {
        const path = getPath(method_line);
        if (std.mem.indexOf(u8, path, ".well-known") != null) {
            sendSimple(sock, "404 Not Found", "Content-Length: 0\r\n");
            _ = ws2.closesocket(sock);
            return;
        }
        if (std.mem.eql(u8, path, "/sse")) {
            handleSseConnect(sock);
            return;
        }
        sendServerInfo(sock);
        _ = ws2.closesocket(sock);
        return;
    }

    if (std.mem.startsWith(u8, method_line, "POST ")) {
        const path = getPath(method_line);
        if (std.mem.indexOf(u8, path, ".well-known") != null) {
            sendSimple(sock, "404 Not Found", "Content-Length: 0\r\n");
            _ = ws2.closesocket(sock);
            return;
        }

        if (findHeaderEnd(request)) |header_end| {
            const body = request[header_end + 4 ..];
            const headers = request[0..header_end];

            if (std.mem.eql(u8, path, "/messages") or std.mem.startsWith(u8, path, "/messages?")) {
                const session_id = parseQueryParam(path, "sessionId") orelse
                    parseHeaderValue(headers, "Mcp-Session-Id");
                handleSseMessage(sock, body, session_id);
            } else {
                handleJsonRpc(sock, body);
            }
        } else {
            sendSimple(sock, "400 Bad Request", "Content-Length: 0\r\n");
        }
        _ = ws2.closesocket(sock);
        return;
    }

    sendSimple(sock, "405 Method Not Allowed", "Content-Length: 0\r\n");
    _ = ws2.closesocket(sock);
}

fn handleJsonRpc(sock: SOCKET, body: []const u8) void {
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, body, .{}) catch {
        sendJsonRpcError(sock, null, -32700, "Parse error");
        return;
    };
    defer parsed.deinit();

    const root = parsed.value;
    const method_val = json_mod.getStringField(root, "method") orelse {
        sendJsonRpcError(sock, null, -32600, "Invalid request: missing method");
        return;
    };
    const id = json_mod.getObjectField(root, "id");

    if (id == null or std.mem.startsWith(u8, method_val, "notifications/")) {
        sendSimple(sock, "202 Accepted", "Content-Length: 0\r\n");
        return;
    }

    if (std.mem.eql(u8, method_val, "initialize")) {
        handleInitialize(sock, id);
    } else if (std.mem.eql(u8, method_val, "tools/list")) {
        handleToolsList(sock, id);
    } else if (std.mem.eql(u8, method_val, "tools/call")) {
        handleToolsCall(sock, id, root);
    } else if (std.mem.eql(u8, method_val, "ping")) {
        sendJsonRpcResult(sock, id, "{}");
    } else {
        sendJsonRpcError(sock, id, -32601, "Method not found");
    }
}

fn handleInitialize(sock: SOCKET, id: ?std.json.Value) void {
    var buffer = json_mod.ByteBuffer.init(std.heap.page_allocator);
    defer buffer.deinit();
    var w = JsonWriter.initGrowable(&buffer);
    buildInitializeResult(&w);
    sendJsonRpcResult(sock, id, w.slice());
}

fn handleToolsList(sock: SOCKET, id: ?std.json.Value) void {
    // The tool list grows with every tool that is added, so the
    // response is written into a buffer that grows with it.  A fixed
    // buffer would silently truncate the JSON once the list outgrows
    // it, and the client would fail to parse the answer.
    var buffer = json_mod.ByteBuffer.init(std.heap.page_allocator);
    defer buffer.deinit();
    var w = JsonWriter.initGrowable(&buffer);
    buildToolsListResult(&w);
    sendJsonRpcResult(sock, id, w.slice());
}

fn handleToolsCall(sock: SOCKET, id: ?std.json.Value, root: std.json.Value) void {
    var buffer = json_mod.ByteBuffer.init(std.heap.page_allocator);
    defer buffer.deinit();
    var w = JsonWriter.initGrowable(&buffer);
    buildToolsCallResult(&w, root);
    const result_str = w.slice();
    if (std.mem.startsWith(u8, result_str, "{\"error\":")) {
        sendJsonRpcError(sock, id, -32602, result_str);
    } else {
        sendJsonRpcResult(sock, id, result_str);
    }
}

// ── SSE transport ──────────────────────────────────────────────────

fn handleSseConnect(sock: SOCKET) void {
    const slot = sseAddClient(sock) orelse {
        sendSimple(sock, "503 Service Unavailable", "Content-Length: 0\r\n");
        _ = ws2.closesocket(sock);
        return;
    };

    const session_id = slot.session_id[0..slot.session_len];

    sendSimple(sock, "200 OK", "Content-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n");

    var endpoint_buf: [128]u8 = undefined;
    const endpoint = std.fmt.bufPrint(&endpoint_buf, "/messages?sessionId={s}", .{session_id}) catch "/messages";
    sseSendEvent(sock, "endpoint", endpoint);

    bridge.logPuts("[x64dbg-MCP Server] SSE client connected.\x00");

    // Keep connection alive until client disconnects or server stops
    while (isRunning()) {
        Sleep(5000);
        // Send keep-alive comment
        const n = ws2.send(sock, ": keepalive\n\n", 13, 0);
        if (n <= 0) break;
    }

    sseRemoveClient(slot.index, sock);
    _ = ws2.closesocket(sock);
    bridge.logPuts("[x64dbg-MCP Server] SSE client disconnected.\x00");
}

fn handleSseMessage(sock: SOCKET, body: []const u8, session_id: ?[]const u8) void {
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, body, .{}) catch {
        sendJsonRpcError(sock, null, -32700, "Parse error");
        return;
    };
    defer parsed.deinit();

    const root = parsed.value;
    const method_val = json_mod.getStringField(root, "method") orelse {
        sendJsonRpcError(sock, null, -32600, "Invalid request: missing method");
        return;
    };
    const id = json_mod.getObjectField(root, "id");

    // Notifications get 202
    if (id == null or std.mem.startsWith(u8, method_val, "notifications/")) {
        sendSimple(sock, "202 Accepted", "Content-Length: 0\r\n");
        return;
    }

    // Process the RPC call and build the result
    var result_buffer = json_mod.ByteBuffer.init(std.heap.page_allocator);
    defer result_buffer.deinit();
    var rw = JsonWriter.initGrowable(&result_buffer);

    if (std.mem.eql(u8, method_val, "initialize")) {
        buildInitializeResult(&rw);
    } else if (std.mem.eql(u8, method_val, "tools/list")) {
        buildToolsListResult(&rw);
    } else if (std.mem.eql(u8, method_val, "tools/call")) {
        buildToolsCallResult(&rw, root);
    } else if (std.mem.eql(u8, method_val, "ping")) {
        rw.raw("{}");
    } else {
        // Method not found — respond directly on POST socket
        sendJsonRpcError(sock, id, -32601, "Method not found");
        return;
    }

    // Build full JSON-RPC response
    var response_buffer = json_mod.ByteBuffer.init(std.heap.page_allocator);
    defer response_buffer.deinit();
    var w = JsonWriter.initGrowable(&response_buffer);
    w.raw("{\"jsonrpc\":\"2.0\",\"id\":");
    writeJsonValue(&w, id);
    w.raw(",\"result\":");
    w.raw(rw.slice());
    w.raw("}");
    const resp_json = w.slice();

    // Try to push response via SSE channel
    const sse_sock = if (session_id) |sid| sseFindBySessionId(sid) else null;
    if (sse_sock) |sse_client| {
        sseSendEvent(sse_client, "message", resp_json);
    }

    // Also respond on the POST connection
    sendSimple(sock, "200 OK", "Content-Type: application/json\r\nContent-Length: 0\r\n");
}

fn buildInitializeResult(w: *JsonWriter) void {
    w.beginObject();
    w.fieldStr("protocolVersion", PROTOCOL_VERSION);
    w.key("serverInfo");
    w.beginObject();
    w.fieldStr("name", SERVER_NAME);
    w.fieldStr("version", SERVER_VERSION);
    w.endObject();
    w.raw(",");
    w.key("capabilities");
    w.beginObject();
    w.key("tools");
    w.raw("{\"listChanged\":true},");
    w.endObject();
    w.raw(",");
    w.fieldStr("instructions",
        \\You are controlling x64dbg, a Windows debugger, via MCP tools.
        \\
        \\CRITICAL RULES:
        \\1. ALWAYS call GetDebugState first to understand the current state before doing anything.
        \\2. After every stepping operation (StepInto, StepOver, StepOut), the response includes the new address and disassembly. Read it carefully before deciding your next action.
        \\3. The target must be PAUSED to read memory, disassemble, or inspect state. If it is RUNNING, call PauseDebug or WaitForPause first.
        \\4. After calling run, ALWAYS call WaitForEvent or WaitForPause immediately to detect breakpoint hits, exceptions, and state changes. NEVER go idle or ask the user to tell you when something happens — you MUST actively monitor by calling WaitForEvent. This is your only way to know when the debugger state changes over HTTP.
        \\5. Use EvalExpression to resolve symbols and addresses (e.g. kernel32:CreateFileA, cip, eax+4).
        \\6. When analyzing a binary: LoadBinary, then WaitForPause, then GetDebugState, then proceed with analysis.
        \\7. Breakpoint workflow: SetBreakpoint, run, WaitForEvent (or WaitForPause), then inspect state. Never wait for user confirmation — monitor actively.
        \\8. For function analysis: use DisassembleFunction (needs analysis, run ExecuteDebuggerCommand with analr <address> first).
        \\9. SearchSymbols searches exports across all loaded modules. Use it to find API functions.
        \\10. Keep track of what binary is loaded and where you are in the code. Reference addresses and module names in your explanations.
        \\11. Every tool response includes a [state] line and any queued [event:*] lines from debugger events that fired since your last call. Always read these — they tell you exactly what happened.
        \\12. When the user is interacting with the GUI (clicking buttons, navigating menus) while you wait for a breakpoint, call WaitForEvent with a longer timeout (e.g. 60000-120000ms) to stay monitoring. Loop WaitForEvent calls if needed until the expected event fires.
    );
    w.endObject();
}

fn buildToolsListResult(w: *JsonWriter) void {
    w.beginObject();
    w.key("tools");
    w.beginArray();
    for (&tools_mod.tools) |*t| {
        w.beginObject();
        w.fieldStr("name", t.name);
        w.fieldStr("description", t.description);
        w.key("inputSchema");
        t.schema_fn(w);
        w.raw(",");
        w.key("annotations");
        w.beginObject();
        w.fieldBool("readOnlyHint", t.read_only);
        w.fieldBool("openWorldHint", false);
        w.endObject();
        w.raw(",");
        w.endObject();
        w.raw(",");
    }
    w.endArray();
    w.endObject();
}

test "only the origin the server is reachable at is allowed" {
    // The server binds the loopback address by default.
    try std.testing.expect(originAllowedFor("http://127.0.0.1:9094", 9094, "127.0.0.1"));
    try std.testing.expect(originAllowedFor("http://localhost:9094", 9094, "127.0.0.1"));

    // Another host, another port, another scheme: not this server.
    try std.testing.expect(!originAllowedFor("http://evil.example:9094", 9094, "127.0.0.1"));
    try std.testing.expect(!originAllowedFor("http://127.0.0.1:9095", 9094, "127.0.0.1"));
    try std.testing.expect(!originAllowedFor("https://127.0.0.1:9094", 9094, "127.0.0.1"));
    try std.testing.expect(!originAllowedFor("file:///etc/passwd", 9094, "127.0.0.1"));
    try std.testing.expect(!originAllowedFor("null", 9094, "127.0.0.1"));
    try std.testing.expect(!originAllowedFor("", 9094, "127.0.0.1"));

    // Bound to every interface: the loopback names are still the only
    // ones answered.
    try std.testing.expect(originAllowedFor("http://127.0.0.1:9094", 9094, "0.0.0.0"));
    try std.testing.expect(!originAllowedFor("http://192.168.0.5:9094", 9094, "0.0.0.0"));

    // Bound to a specific address: only that address is answered.
    try std.testing.expect(originAllowedFor("http://192.168.0.5:9094", 9094, "192.168.0.5"));
    try std.testing.expect(!originAllowedFor("http://127.0.0.1:9094", 9094, "192.168.0.5"));
}

test "the tool list comes out complete and parseable" {
    var buffer = json_mod.ByteBuffer.init(std.testing.allocator);
    defer buffer.deinit();
    var w = JsonWriter.initGrowable(&buffer);
    buildToolsListResult(&w);

    try std.testing.expect(!w.isTruncated());

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, buffer.slice(), .{});
    defer parsed.deinit();

    const tools = parsed.value.object.get("tools").?.array;
    try std.testing.expectEqual(tools_mod.tools.len, tools.items.len);
    for (tools.items, tools_mod.tools) |item, tool| {
        try std.testing.expectEqualStrings(tool.name, item.object.get("name").?.string);
        try std.testing.expect(item.object.get("description") != null);
        try std.testing.expect(item.object.get("inputSchema") != null);
    }
}

fn buildToolsCallResult(w: *JsonWriter, root: std.json.Value) void {
    const params_obj = json_mod.getObjectField(root, "params");
    const tool_name = if (params_obj) |p| json_mod.getStringField(p, "name") else null;
    if (tool_name == null) {
        w.raw("{\"error\":\"Missing params.name\"}");
        return;
    }
    const name = tool_name.?;
    const arguments = if (params_obj) |p| json_mod.getObjectField(p, "arguments") else null;

    for (&tools_mod.tools) |*t| {
        if (std.mem.eql(u8, t.name, name)) {
            if (t.debug_only and !bridge.isDebugging()) {
                w.raw("{\"error\":\"Tool requires an active debug session.\"}");
                return;
            }
            var out_buf: [65536]u8 = undefined;
            const tr = t.handler(arguments, &out_buf);

            w.beginObject();
            w.key("content");
            w.beginArray();
            w.beginObject();
            w.fieldStr("type", "text");
            w.key("text");
            w.writeString(tr.text);
            w.endObject();

            // Drain any pending events (breakpoint hit, paused, etc.) that arrived between calls
            pendingDrain(w);

            // Append debugger state to every response (skip GetDebugState itself to avoid redundancy)
            if (!std.mem.eql(u8, name, "GetDebugState") and !std.mem.eql(u8, name, "Echo")) {
                var state_buf: [256]u8 = undefined;
                const state_str = buildStateSnippet(&state_buf);
                if (state_str.len > 0) {
                    w.raw(",");
                    w.beginObject();
                    w.fieldStr("type", "text");
                    w.key("text");
                    w.writeString(state_str);
                    w.endObject();
                }
            }

            w.endArray();
            w.raw(",");
            if (tr.is_error) {
                w.fieldBool("isError", true);
            }
            w.endObject();
            return;
        }
    }
    w.raw("{\"error\":\"Tool not found.\"}");
}

fn buildStateSnippet(buf: *[256]u8) []const u8 {
    const debugging = bridge.isDebugging();
    if (!debugging) {
        const s = "[state] NO_TARGET";
        @memcpy(buf[0..s.len], s);
        return buf[0..s.len];
    }
    const running = bridge.isRunning();
    if (running) {
        const s = "[state] RUNNING — call WaitForPause before inspecting";
        @memcpy(buf[0..s.len], s);
        return buf[0..s.len];
    }
    const cip = bridge.valFromString("cip");
    var mod_buf: [bridge.MAX_MODULE_SIZE]u8 = undefined;
    const has_mod = bridge.getModuleAt(cip, &mod_buf);
    const mod_name = if (has_mod) bridge.cstrSlice(&mod_buf) else "unknown";

    var dis_buf: [256]u8 = undefined;
    const has_dis = bridge.disasmTextAt(cip, &dis_buf);
    const dis_text = if (has_dis) bridge.cstrSlice(&dis_buf) else "";

    return std.fmt.bufPrint(buf, "[state] PAUSED at 0x{X} ({s}) | {s}", .{ cip, mod_name, dis_text }) catch buf[0..0];
}

fn parseQueryParam(path: []const u8, param: []const u8) ?[]const u8 {
    const qmark = std.mem.indexOf(u8, path, "?") orelse return null;
    var rest = path[qmark + 1 ..];
    while (rest.len > 0) {
        const amp = std.mem.indexOf(u8, rest, "&") orelse rest.len;
        const pair = rest[0..amp];
        const eq = std.mem.indexOf(u8, pair, "=") orelse {
            rest = if (amp < rest.len) rest[amp + 1 ..] else rest[rest.len..];
            continue;
        };
        if (std.mem.eql(u8, pair[0..eq], param)) {
            return pair[eq + 1 ..];
        }
        rest = if (amp < rest.len) rest[amp + 1 ..] else rest[rest.len..];
    }
    return null;
}

fn parseHeaderValue(headers: []const u8, name: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos < headers.len) {
        const line_end = std.mem.indexOf(u8, headers[pos..], "\r\n") orelse headers.len - pos;
        const line = headers[pos .. pos + line_end];
        if (line.len > name.len + 2) {
            if (std.ascii.eqlIgnoreCase(line[0..name.len], name) and line[name.len] == ':') {
                var val_start = name.len + 1;
                while (val_start < line.len and line[val_start] == ' ') val_start += 1;
                return line[val_start..];
            }
        }
        pos += line_end + 2;
    }
    return null;
}

// ── CORS ────────────────────────────────────────────────────────────
//
// The server drives a debugger: it writes memory, sets breakpoints and
// runs commands in the debuggee.  It therefore does not answer with a
// wildcard origin any more.  The Origin header is echoed back only when
// it names the origin the server itself is reachable at — the bind
// address, on the port it listens on.  Every other origin gets no CORS
// headers at all, which makes the browser refuse the response.
//
// The headers belong to one request and every request is handled by
// exactly one thread, so they are kept in thread-local storage.
const CORS_METHODS = "GET, POST, OPTIONS, DELETE";
const CORS_REQUEST_HEADERS = "Content-Type, Authorization, Mcp-Session-Id, Accept";

threadlocal var cors_buf: [512]u8 = undefined;
threadlocal var cors_len: usize = 0;

/// The CORS headers of the request that is being handled.
fn corsHeaders() []const u8 {
    return cors_buf[0..cors_len];
}

/// Build the CORS headers of a request from its Origin header.
fn setCorsHeaders(origin: ?[]const u8) void {
    cors_len = 0;
    const o = origin orelse return;
    if (!originAllowed(o)) return;
    var pos: usize = 0;
    pos += copyHeader(cors_buf[pos..], "Access-Control-Allow-Origin: ");
    pos += copyHeader(cors_buf[pos..], o);
    pos += copyHeader(cors_buf[pos..], "\r\n");
    pos += copyHeader(cors_buf[pos..], "Vary: Origin\r\n");
    pos += copyHeader(cors_buf[pos..], "Access-Control-Allow-Methods: " ++ CORS_METHODS ++ "\r\n");
    pos += copyHeader(cors_buf[pos..], "Access-Control-Allow-Headers: " ++ CORS_REQUEST_HEADERS ++ "\r\n");
    pos += copyHeader(cors_buf[pos..], "Access-Control-Expose-Headers: Mcp-Session-Id\r\n");
    cors_len = pos;
}

fn copyHeader(out: []u8, text: []const u8) usize {
    const n = @min(out.len, text.len);
    @memcpy(out[0..n], text[0..n]);
    return n;
}

/// Whether the Origin header names the origin the server is reachable
/// at: the host it is bound to, on the port it listens on.
fn originAllowed(origin: []const u8) bool {
    var ip_buf: [64]u8 = undefined;
    var port: u16 = 0;
    const ip_len = bindTarget(&ip_buf, &port);
    return originAllowedFor(origin, currentBoundPort(), ip_buf[0..ip_len]);
}

/// The origin check on its own, without the server state.
fn originAllowedFor(origin: []const u8, listen_port: u16, bind_ip: []const u8) bool {
    if (origin.len == 0 or origin.len > 128) return false;
    const scheme_end = std.mem.indexOf(u8, origin, "://") orelse return false;
    const scheme = origin[0..scheme_end];
    // The server speaks plain HTTP, so only an http origin can refer
    // to it.
    if (!std.mem.eql(u8, scheme, "http")) return false;
    var host = origin[scheme_end + 3 ..];
    if (std.mem.indexOfScalar(u8, host, '/')) |slash| host = host[0..slash];

    if (listen_port == 0) return false;
    var origin_port = listen_port;
    if (std.mem.lastIndexOfScalar(u8, host, ':')) |colon| {
        origin_port = std.fmt.parseInt(u16, host[colon + 1 ..], 10) catch return false;
        host = host[0..colon];
    }
    if (origin_port != listen_port) return false;
    return hostAllowedFor(host, bind_ip);
}

/// Whether the host of an Origin header is one the server answers to.
fn hostAllowed(host: []const u8) bool {
    var ip_buf: [64]u8 = undefined;
    var port: u16 = 0;
    const ip_len = bindTarget(&ip_buf, &port);
    return hostAllowedFor(host, ip_buf[0..ip_len]);
}

/// The host check on its own, without the server state.
fn hostAllowedFor(host: []const u8, bind_ip: []const u8) bool {
    if (std.mem.eql(u8, host, bind_ip)) return true;
    // The loopback names are answered when the server is bound to the
    // loopback address or to every interface.
    const local = std.mem.eql(u8, bind_ip, "127.0.0.1") or std.mem.eql(u8, bind_ip, "0.0.0.0");
    if (local and (std.mem.eql(u8, host, "127.0.0.1") or std.mem.eql(u8, host, "localhost"))) return true;
    return false;
}

// ── HTTP helpers ────────────────────────────────────────────────────

/// Send a response with the given status line, the CORS headers of the
/// current request and the given extra headers.
fn sendSimple(sock: SOCKET, status: []const u8, extra: []const u8) void {
    var buf: [768]u8 = undefined;
    const resp = std.fmt.bufPrint(&buf, "HTTP/1.1 {s}\r\n{s}{s}\r\n", .{ status, corsHeaders(), extra }) catch return;
    wsSend(sock, resp);
}

fn sendServerInfo(sock: SOCKET) void {
    var body_buf: [256]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{{\"name\":\"{s}\",\"version\":\"{s}\",\"transport\":\"streamable-http\",\"endpoint\":\"/\"}}", .{ SERVER_NAME, SERVER_VERSION }) catch return;
    var buf: [768]u8 = undefined;
    const resp = std.fmt.bufPrint(&buf, "HTTP/1.1 200 OK\r\n{s}Content-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}", .{ corsHeaders(), body.len, body }) catch return;
    wsSend(sock, resp);
}

fn sendJsonRpcResult(sock: SOCKET, id: ?std.json.Value, result_json: []const u8) void {
    // The envelope grows with the result: the result of a tool call is
    // a JSON document that is escaped again here, so a fixed buffer
    // would truncate the answer for large tool results.
    var buffer = json_mod.ByteBuffer.init(std.heap.page_allocator);
    defer buffer.deinit();
    var w = JsonWriter.initGrowable(&buffer);
    w.raw("{\"jsonrpc\":\"2.0\",\"id\":");
    writeJsonValue(&w, id);
    w.raw(",\"result\":");
    w.raw(result_json);
    w.raw("}");

    const body_slice = w.slice();
    var header_buf: [768]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\n{s}Content-Type: application/json\r\nContent-Length: {d}\r\n\r\n", .{ corsHeaders(), body_slice.len }) catch return;

    wsSend(sock, header);
    wsSend(sock, body_slice);
}

fn sendJsonRpcError(sock: SOCKET, id: ?std.json.Value, code: i32, message: []const u8) void {
    var body_buf: [4096]u8 = undefined;
    var w = JsonWriter.init(&body_buf);
    w.raw("{\"jsonrpc\":\"2.0\",\"id\":");
    writeJsonValue(&w, id);
    w.raw(",\"error\":{\"code\":");
    w.writeInt(code);
    w.raw(",\"message\":");
    w.writeString(message);
    w.raw("}}");

    if (w.isTruncated()) {
        // The message did not fit: send a short error instead of a
        // truncated, unparseable document.
        const fallback = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"Error message too long\"}}";
        var header_buf: [768]u8 = undefined;
        const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\n{s}Content-Type: application/json\r\nContent-Length: {d}\r\n\r\n", .{ corsHeaders(), fallback.len }) catch return;
        wsSend(sock, header);
        wsSend(sock, fallback);
        return;
    }

    const body_slice = w.slice();
    var header_buf: [768]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\n{s}Content-Type: application/json\r\nContent-Length: {d}\r\n\r\n", .{ corsHeaders(), body_slice.len }) catch return;

    wsSend(sock, header);
    wsSend(sock, body_slice);
}

fn writeJsonValue(w: *JsonWriter, val: ?std.json.Value) void {
    if (val == null) {
        w.raw("null");
        return;
    }
    switch (val.?) {
        .integer => |i| w.writeInt(i),
        .string => |s| w.writeString(s),
        .null => w.raw("null"),
        .float => |f| {
            var tmp: [32]u8 = undefined;
            const s = std.fmt.bufPrint(&tmp, "{d}", .{f}) catch "0";
            w.raw(s);
        },
        .bool => |b| w.raw(if (b) "true" else "false"),
        else => w.raw("null"),
    }
}

// ── HTTP parsing ────────────────────────────────────────────────────

fn findHeaderEnd(data: []const u8) ?usize {
    return std.mem.indexOf(u8, data, "\r\n\r\n");
}

fn parseContentLength(headers: []const u8) usize {
    const needle = "Content-Length: ";
    const idx = std.mem.indexOf(u8, headers, needle) orelse
        std.mem.indexOf(u8, headers, "content-length: ") orelse
        return 0;
    const val_start = idx + needle.len;
    var val_end = val_start;
    while (val_end < headers.len and headers[val_end] >= '0' and headers[val_end] <= '9') : (val_end += 1) {}
    return std.fmt.parseInt(usize, headers[val_start..val_end], 10) catch 0;
}

fn getFirstLine(data: []const u8) []const u8 {
    const end = std.mem.indexOf(u8, data, "\r\n") orelse data.len;
    return data[0..end];
}

fn getPath(request_line: []const u8) []const u8 {
    const space1 = std.mem.indexOf(u8, request_line, " ") orelse return "/";
    const rest = request_line[space1 + 1 ..];
    const space2 = std.mem.indexOf(u8, rest, " ") orelse rest.len;
    return rest[0..space2];
}
