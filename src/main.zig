// x64dbg-MCP Server plugin.

const std = @import("std");
const bridge = @import("core/bridge.zig");
const mcp = @import("core/mcp_server.zig");
const config = @import("core/config.zig");
const icons = @import("resources/icons.zig");
const sync = @import("core/sync.zig");
const tools_mod = @import("mcp/tools.zig");

const PLUGIN_NAME = "x64dbg-MCP Server";
const PLUGIN_VERSION = 1;

// x64dbg's command namespace is flat and global, so the commands of
// this plugin carry the plugin name as their namespace.
const COMMAND_START: [*:0]const u8 = "mcpserver.start\x00";
const COMMAND_STOP: [*:0]const u8 = "mcpserver.stop\x00";

var plugin_handle: c_int = 0;
var main_menu: c_int = 0;
var host_hwnd: usize = 0;

const MENU_TOGGLE: c_int = 1;
const MENU_CONFIG: c_int = 2;
const MENU_ABOUT: c_int = 3;

// ── Event log ring buffer ──────────────────────────────────────────
//
// The ring buffer is written from x64dbg's debugger callbacks and read
// from the HTTP worker threads, so every access goes through the lock.
const EVENT_LOG_SIZE = 64;
const EVENT_MSG_SIZE = 192;

var event_log: [EVENT_LOG_SIZE][EVENT_MSG_SIZE]u8 = undefined;
var event_log_lens: [EVENT_LOG_SIZE]usize = @splat(0);
var event_log_head: usize = 0;
var event_log_count: usize = 0;
var event_log_lock: sync.Mutex = .{};

pub fn initLocks() void {
    event_log_lock.init();
    debuggee_path_lock.init();
}

pub fn pushEvent(msg: []const u8) void {
    const len = @min(msg.len, EVENT_MSG_SIZE);
    event_log_lock.lock();
    defer event_log_lock.unlock();
    @memcpy(event_log[event_log_head][0..len], msg[0..len]);
    event_log_lens[event_log_head] = len;
    event_log_head = (event_log_head + 1) % EVENT_LOG_SIZE;
    if (event_log_count < EVENT_LOG_SIZE) event_log_count += 1;
}

pub fn getEventCount() usize {
    event_log_lock.lock();
    defer event_log_lock.unlock();
    return event_log_count;
}

/// Copy the event at `index` into `dst` and return the event's full
/// length.  The copy happens under the lock so the caller never reads a
/// slot the debugger callback thread is already overwriting.
pub fn copyEvent(index: usize, dst: []u8) usize {
    event_log_lock.lock();
    defer event_log_lock.unlock();
    if (index >= event_log_count) return 0;
    const start = if (event_log_count < EVENT_LOG_SIZE) 0 else event_log_head;
    const i = (start + index) % EVENT_LOG_SIZE;
    const n = @min(event_log_lens[i], dst.len);
    @memcpy(dst[0..n], event_log[i][0..n]);
    return event_log_lens[i];
}

pub fn clearEvents() void {
    event_log_lock.lock();
    defer event_log_lock.unlock();
    event_log_count = 0;
    event_log_head = 0;
}

// ── Current debuggee path ───────────────────────────────────────────
//
// x64dbg supplies the full executable path in CB_INITDEBUG.  Keep a
// private copy so RestartDebug can issue the same "init <path>"
// operation as x64dbg's normal restart behaviour.
const DEBUGGEE_PATH_SIZE = 1024;
var current_debuggee_path: [DEBUGGEE_PATH_SIZE]u8 = undefined;
var current_debuggee_path_len: usize = 0;
var debuggee_path_lock: sync.Mutex = .{};

pub fn setCurrentDebuggeePath(path: []const u8) void {
    const len = @min(path.len, DEBUGGEE_PATH_SIZE - 1);
    debuggee_path_lock.lock();
    defer debuggee_path_lock.unlock();
    @memcpy(current_debuggee_path[0..len], path[0..len]);
    current_debuggee_path[len] = 0;
    current_debuggee_path_len = len;
}

/// Copy the current debuggee path into `dst` and return its length.  The
/// copy happens under the lock: the path is written by the debugger
/// callback thread and read by an HTTP worker thread.
pub fn copyCurrentDebuggeePath(dst: []u8) usize {
    debuggee_path_lock.lock();
    defer debuggee_path_lock.unlock();
    const n = @min(current_debuggee_path_len, dst.len);
    @memcpy(dst[0..n], current_debuggee_path[0..n]);
    return n;
}

const HWND = ?*anyopaque;
extern "user32" fn MessageBoxA(hWnd: HWND, lpText: [*:0]const u8, lpCaption: [*:0]const u8, uType: u32) callconv(.winapi) i32;

// ── Plugin exports ──────────────────────────────────────────────────

export fn pluginit(initStruct: *bridge.PLUG_INITSTRUCT) callconv(.c) c_int {
    bridge.init() catch return 0;

    // The debugger callbacks and the HTTP worker threads share state, so
    // the locks protecting it have to be ready before either side runs.
    initLocks();
    mcp.initLocks();

    initStruct.sdkVersion = bridge.PLUG_SDKVERSION;
    initStruct.pluginVersion = PLUGIN_VERSION;

    const name = PLUGIN_NAME;
    for (name, 0..) |c, i| {
        initStruct.pluginName[i] = c;
    }
    initStruct.pluginName[name.len] = 0;

    plugin_handle = initStruct.pluginHandle;
    bridge.logPuts("[x64dbg-MCP Server] Plugin initialized.\x00");

    // x64dbg has one flat command namespace: a command name that
    // another plugin already registered cannot be registered twice, and
    // the registration fails silently.  The commands are therefore
    // namespaced with the plugin name.
    registerCommand(COMMAND_START, cmdStartServer);
    registerCommand(COMMAND_STOP, cmdStopServer);

    return 1;
}

/// Register a command and report whether it actually was registered.
fn registerCommand(name: [*:0]const u8, cb: bridge.CBPLUGINCOMMAND) void {
    const ok = bridge._plugin_registercommand(plugin_handle, name, cb, 0) != 0;
    const text = if (ok) "registered!" else "could not be registered, the name is already taken!";
    var buf: [192]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "[x64dbg-MCP Server] Command \"{s}\" {s}\x00", .{ std.mem.span(name), text }) catch return;
    bridge.logPuts(@ptrCast(msg.ptr));
}

export fn plugsetup(setupStruct: *bridge.PLUG_SETUPSTRUCT) callconv(.c) void {
    main_menu = setupStruct.hMenu;
    host_hwnd = setupStruct.hwndDlg;

    setMenuIcon(main_menu, icons.mcp_icon);

    _ = bridge._plugin_menuaddentry(main_menu, MENU_TOGGLE, "&Stop MCP Server\x00");
    setEntryIcon(MENU_TOGGLE, icons.stop_icon);
    _ = bridge._plugin_menuaddseparator(main_menu);
    _ = bridge._plugin_menuaddentry(main_menu, MENU_CONFIG, "&Configure MCP Server...\x00");
    setEntryIcon(MENU_CONFIG, icons.settings_icon);
    _ = bridge._plugin_menuaddseparator(main_menu);
    _ = bridge._plugin_menuaddentry(main_menu, MENU_ABOUT, "&About...\x00");
    setEntryIcon(MENU_ABOUT, icons.info_icon);

    bridge.logPuts("[x64dbg-MCP Server] Menu setup complete.\x00");

    const CB = bridge.CBTYPE;
    const cbs = .{
        .{ CB.CB_INITDEBUG, cbInitDebug, "CB_INITDEBUG" },
        .{ CB.CB_STOPDEBUG, cbStopDebug, "CB_STOPDEBUG" },
        .{ CB.CB_CREATEPROCESS, cbCreateProcess, "CB_CREATEPROCESS" },
        .{ CB.CB_EXITPROCESS, cbExitProcess, "CB_EXITPROCESS" },
        .{ CB.CB_CREATETHREAD, cbCreateThread, "CB_CREATETHREAD" },
        .{ CB.CB_EXITTHREAD, cbExitThread, "CB_EXITTHREAD" },
        .{ CB.CB_SYSTEMBREAKPOINT, cbSystemBreakpoint, "CB_SYSTEMBREAKPOINT" },
        .{ CB.CB_LOADDLL, cbLoadDll, "CB_LOADDLL" },
        .{ CB.CB_UNLOADDLL, cbUnloadDll, "CB_UNLOADDLL" },
        .{ CB.CB_OUTPUTDEBUGSTRING, cbOutputDebugString, "CB_OUTPUTDEBUGSTRING" },
        .{ CB.CB_EXCEPTION, cbException, "CB_EXCEPTION" },
        .{ CB.CB_BREAKPOINT, cbBreakpoint, "CB_BREAKPOINT" },
        .{ CB.CB_PAUSEDEBUG, cbPauseDebug, "CB_PAUSEDEBUG" },
        .{ CB.CB_RESUMEDEBUG, cbResumeDebug, "CB_RESUMEDEBUG" },
        .{ CB.CB_STEPPED, cbStepped, "CB_STEPPED" },
        .{ CB.CB_ATTACH, cbAttach, "CB_ATTACH" },
        .{ CB.CB_DETACH, cbDetach, "CB_DETACH" },
        .{ CB.CB_DEBUGEVENT, cbDebugEvent, "CB_DEBUGEVENT" },
        .{ CB.CB_TRACEEXECUTE, cbTraceExecute, "CB_TRACEEXECUTE" },
        .{ CB.CB_SELCHANGED, cbSelChanged, "CB_SELCHANGED" },
        .{ CB.CB_ANALYZE, cbAnalyze, "CB_ANALYZE" },
        .{ CB.CB_STOPPINGDEBUG, cbStoppingDebug, "CB_STOPPINGDEBUG" },
    };
    inline for (cbs) |cb| {
        bridge._plugin_registercallback(plugin_handle, cb[0], cb[1]);
        logCallback(cb[2]);
    }

    // Log registered MCP tools
    for (&tools_mod.tools) |*t| {
        logTool(t.name);
    }
    logToolCount(tools_mod.tools.len);

    // Load saved config or use defaults
    const cfg = config.load();
    mcp.setConfig(cfg.ip[0..cfg.ip_len], cfg.port, cfg.tokenSlice());

    // Log plugin handle
    logPluginHandle();

    if (cfg.auto_start) {
        mcp.start();
    } else {
        bridge.logPuts("[x64dbg-MCP Server] Auto-start disabled. Use menu to start.\x00");
    }
}

export fn plugstop() callconv(.c) c_int {
    mcp.stop();
    _ = bridge._plugin_unregistercommand(plugin_handle, COMMAND_START);
    _ = bridge._plugin_unregistercommand(plugin_handle, COMMAND_STOP);
    bridge.logPuts("[x64dbg-MCP Server] Plugin stopped.\x00");
    return 1;
}

export fn CBMENUENTRY(_: bridge.CBTYPE, info: *bridge.PLUG_CB_MENUENTRY) callconv(.c) void {
    switch (info.hEntry) {
        MENU_TOGGLE => toggleServer(),
        MENU_CONFIG => config.showDialog(host_hwnd),
        MENU_ABOUT => showAbout(),
        else => {},
    }
}

fn toggleServer() void {
    if (mcp.isRunning()) {
        mcp.stop();
    } else {
        mcp.start();
    }
    rebuildMenu();
}

fn rebuildMenu() void {
    _ = bridge._plugin_menuclear(main_menu);

    if (mcp.isRunning()) {
        _ = bridge._plugin_menuaddentry(main_menu, MENU_TOGGLE, "&Stop MCP Server\x00");
        setEntryIcon(MENU_TOGGLE, icons.stop_icon);
    } else {
        _ = bridge._plugin_menuaddentry(main_menu, MENU_TOGGLE, "&Start MCP Server\x00");
        setEntryIcon(MENU_TOGGLE, icons.play_icon);
    }
    _ = bridge._plugin_menuaddseparator(main_menu);
    _ = bridge._plugin_menuaddentry(main_menu, MENU_CONFIG, "&Configure MCP Server...\x00");
    setEntryIcon(MENU_CONFIG, icons.settings_icon);
    _ = bridge._plugin_menuaddseparator(main_menu);
    _ = bridge._plugin_menuaddentry(main_menu, MENU_ABOUT, "&About...\x00");
}

fn setMenuIcon(menu: c_int, data: []const u8) void {
    if (bridge._plugin_menuseticon) |seticon| {
        var icon_data = bridge.ICONDATA{ .data = data.ptr, .size = data.len };
        seticon(menu, &icon_data);
    }
}

fn setEntryIcon(entry: c_int, data: []const u8) void {
    if (bridge._plugin_menuentryseticon) |seticon| {
        var icon_data = bridge.ICONDATA{ .data = data.ptr, .size = data.len };
        seticon(plugin_handle, entry, &icon_data);
    }
}

fn logCallback(name: []const u8) void {
    var buf: [192]u8 = undefined;
    const prefix = "[x64dbg-MCP Server] Event callback ";
    @memcpy(buf[0..prefix.len], prefix);
    var pos: usize = prefix.len;
    const copy_len = @min(name.len, buf.len - pos - 13);
    @memcpy(buf[pos .. pos + copy_len], name[0..copy_len]);
    pos += copy_len;
    const suffix = " registered!";
    @memcpy(buf[pos .. pos + suffix.len], suffix);
    pos += suffix.len;
    buf[pos] = 0;
    bridge.logPuts(@ptrCast(&buf));
}

fn logTool(name: []const u8) void {
    var buf: [192]u8 = undefined;
    const prefix = "[x64dbg-MCP Server] MCP Tool registered: ";
    @memcpy(buf[0..prefix.len], prefix);
    var pos: usize = prefix.len;
    const copy_len = @min(name.len, buf.len - pos - 1);
    @memcpy(buf[pos .. pos + copy_len], name[0..copy_len]);
    pos += copy_len;
    buf[pos] = 0;
    bridge.logPuts(@ptrCast(&buf));
}

fn logToolCount(count: usize) void {
    var buf: [192]u8 = undefined;
    const prefix = "[x64dbg-MCP Server] Total MCP tools: ";
    @memcpy(buf[0..prefix.len], prefix);
    var pos: usize = prefix.len;
    pos += fmtInt(@intCast(count), buf[pos..]);
    buf[pos] = 0;
    bridge.logPuts(@ptrCast(&buf));
}

fn logPluginHandle() void {
    var buf: [80]u8 = undefined;
    const prefix = "[x64dbg-MCP Server] PluginHandle: ";
    @memcpy(buf[0..prefix.len], prefix);
    var pos: usize = prefix.len;
    pos += fmtInt(plugin_handle, buf[pos..]);
    buf[pos] = 0;
    bridge.logPuts(@ptrCast(&buf));
}

fn fmtInt(val: c_int, buf: []u8) usize {
    if (val == 0) {
        buf[0] = '0';
        return 1;
    }
    var v: u32 = if (val < 0) @intCast(-val) else @intCast(val);
    var tmp: [12]u8 = undefined;
    var i: usize = 0;
    while (v > 0) : (i += 1) {
        tmp[i] = '0' + @as(u8, @intCast(v % 10));
        v /= 10;
    }
    var pos: usize = 0;
    if (val < 0) {
        buf[0] = '-';
        pos = 1;
    }
    var j: usize = 0;
    while (j < i) : (j += 1) {
        buf[pos + j] = tmp[i - 1 - j];
    }
    return pos + i;
}

fn fmtHex(val: u32, buf: []u8) usize {
    const hex = "0123456789ABCDEF";
    var tmp: [8]u8 = undefined;
    var v = val;
    var i: usize = 0;
    if (v == 0) {
        buf[0] = '0';
        return 1;
    }
    while (v > 0) : (i += 1) {
        tmp[i] = hex[@intCast(v & 0xF)];
        v >>= 4;
    }
    var j: usize = 0;
    while (j < i) : (j += 1) {
        buf[j] = tmp[i - 1 - j];
    }
    return i;
}

fn fmtHexAddr(val: usize, buf: []u8) usize {
    const hex = "0123456789ABCDEF";
    var tmp: [16]u8 = undefined;
    var v = val;
    var i: usize = 0;
    if (v == 0) {
        buf[0] = '0';
        return 1;
    }
    while (v > 0) : (i += 1) {
        tmp[i] = hex[@intCast(v & 0xF)];
        v >>= 4;
    }
    var j: usize = 0;
    while (j < i) : (j += 1) {
        buf[j] = tmp[i - 1 - j];
    }
    return i;
}

// ── UI ──────────────────────────────────────────────────────────────

fn showAbout() void {
    _ = MessageBoxA(
        @ptrFromInt(host_hwnd),
        "x64dbg-MCP Server v" ++ mcp.SERVER_VERSION ++ "\n\nNative MCP plugin for x64dbg.\nProtocol: MCP 2024-11-05 (Streamable HTTP + SSE)\n\nAuthor: duty1g\nhttps://github.com/duty1g\x00",
        "x64dbg-MCP Server\x00",
        0x40,
    );
}

// ── Commands ────────────────────────────────────────────────────────

fn cmdStartServer(_: c_int, _: [*]const [*:0]const u8) callconv(.c) c_int {
    mcp.start();
    return 1;
}

fn cmdStopServer(_: c_int, _: [*]const [*:0]const u8) callconv(.c) c_int {
    mcp.stop();
    return 1;
}

// ── Callbacks ───────────────────────────────────────────────────────

fn logAndPush(msg: []const u8) void {
    bridge.logPuts(@ptrCast(msg.ptr));
    pushEvent(msg[0 .. msg.len - 1]); // strip null terminator for event log
}

fn cbInitDebug(_: bridge.CBTYPE, info: *anyopaque) callconv(.c) void {
    const cb: *bridge.PLUG_CB_INITDEBUG = @ptrCast(@alignCast(info));
    const path = std.mem.span(cb.szFileName);
    setCurrentDebuggeePath(path);

    logAndPush("[x64dbg-MCP Server] Debug session started.\x00");
    mcp.notifyEvent("info", "Debug session started. Binary loaded.");
}

fn cbStopDebug(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] Debug session stopped.\x00");
    mcp.notifyEvent("info", "Debug session stopped. No target.");
}

fn cbCreateProcess(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] Process created.\x00");
}

fn cbExitProcess(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] Process exited.\x00");
}

fn cbCreateThread(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] Thread created.\x00");
}

fn cbExitThread(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] Thread exited.\x00");
}

fn cbSystemBreakpoint(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] System breakpoint.\x00");
    mcp.notifyEvent("info", "System breakpoint hit. Target is now PAUSED at entry point.");
}

fn cbLoadDll(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] DLL loaded.\x00");
}

fn cbUnloadDll(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] DLL unloaded.\x00");
}

fn cbOutputDebugString(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] OutputDebugString received.\x00");
}

fn cbException(_: bridge.CBTYPE, info: *anyopaque) callconv(.c) void {
    const cb: *bridge.PLUG_CB_EXCEPTION = @ptrCast(@alignCast(info));
    const rec = &cb.Exception.ExceptionRecord;
    const first_chance = cb.Exception.dwFirstChance;

    var buf: [256]u8 = undefined;
    const prefix = "Exception 0x";
    @memcpy(buf[0..prefix.len], prefix);
    var pos: usize = prefix.len;
    pos += fmtHex(rec.ExceptionCode, buf[pos..]);
    const at = " at 0x";
    @memcpy(buf[pos .. pos + at.len], at);
    pos += at.len;
    pos += fmtHexAddr(rec.ExceptionAddress, buf[pos..]);
    if (first_chance != 0) {
        const fc = " (first chance)";
        @memcpy(buf[pos .. pos + fc.len], fc);
        pos += fc.len;
    } else {
        const sc = " (second chance)";
        @memcpy(buf[pos .. pos + sc.len], sc);
        pos += sc.len;
    }
    pushEvent(buf[0..pos]);

    // Also log to x64dbg console with prefix
    var log_buf: [256]u8 = undefined;
    const log_prefix = "[x64dbg-MCP Server] ";
    @memcpy(log_buf[0..log_prefix.len], log_prefix);
    @memcpy(log_buf[log_prefix.len .. log_prefix.len + pos], buf[0..pos]);
    log_buf[log_prefix.len + pos] = 0;
    bridge.logPuts(@ptrCast(&log_buf));

    mcp.notifyEvent("error", buf[0..pos]);
}

fn cbBreakpoint(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] Breakpoint hit.\x00");
    mcp.notifyEvent("warning", "Breakpoint hit. Target is now PAUSED. Call GetDebugState to inspect.");
}

fn cbPauseDebug(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] Debugger paused.\x00");
    mcp.notifyEvent("info", "Debugger paused. Target is now PAUSED. Call GetDebugState to inspect.");
}

fn cbResumeDebug(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] Debugger resumed.\x00");
    mcp.notifyEvent("info", "Debugger resumed. Target is now RUNNING.");
}

fn cbStepped(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] Single step completed.\x00");
}

fn cbAttach(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] Attached to process.\x00");
}

fn cbDetach(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] Detached from process.\x00");
}

fn cbDebugEvent(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {}

fn cbTraceExecute(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] Trace execute.\x00");
}

fn cbSelChanged(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {}

fn cbAnalyze(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] Analysis complete.\x00");
}

fn cbStoppingDebug(_: bridge.CBTYPE, _: *anyopaque) callconv(.c) void {
    logAndPush("[x64dbg-MCP Server] Debug session stopping.\x00");
}
