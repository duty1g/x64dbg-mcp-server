// x64dbg Bridge API bindings.
// Source: https://github.com/x64dbg/x64dbg/blob/development/src/bridge/bridgemain.h
//
// At load-time the plugin sits inside x32dbg.exe or x64dbg.exe, which
// already has x32bridge.dll / x64bridge.dll loaded.  We resolve every
// symbol at runtime via GetProcAddress so a single source file works
// for both architectures.

const std = @import("std");
const win = std.os.windows;

// The x64dbg bridge API returns C++ `bool` (one byte in AL).  Zig's
// std.os.windows.BOOL changed shape between 0.14 and 0.17, so the plugin
// uses a plain c_int and masks the low byte where it matters.
const BOOL = c_int;
const HMODULE = win.HMODULE;

extern "kernel32" fn GetModuleHandleA(lpModuleName: ?[*:0]const u8) callconv(.winapi) ?HMODULE;
extern "kernel32" fn GetProcAddress(hModule: HMODULE, lpProcName: [*:0]const u8) callconv(.winapi) ?*anyopaque;

// ── pointer-width type (duint in x64dbg) ────────────────────────────
pub const duint = usize;

// ── Constants ───────────────────────────────────────────────────────
pub const PLUG_SDKVERSION: c_int = 1;
pub const MAX_LABEL_SIZE = 256;
pub const MAX_COMMENT_SIZE = 512;
pub const MAX_MODULE_SIZE = 256;
pub const MAX_BREAKPOINT_SIZE = 256;
pub const MAX_STRING_SIZE = 512;
pub const MAX_MNEMONIC_SIZE = 64;
pub const MAX_SETTING_SIZE = 65536;

// ── Callback types (CBTYPE enum) ────────────────────────────────────
pub const CBTYPE = enum(c_int) {
    CB_INITDEBUG = 0,
    CB_STOPDEBUG,
    CB_CREATEPROCESS,
    CB_EXITPROCESS,
    CB_CREATETHREAD,
    CB_EXITTHREAD,
    CB_SYSTEMBREAKPOINT,
    CB_LOADDLL,
    CB_UNLOADDLL,
    CB_OUTPUTDEBUGSTRING,
    CB_EXCEPTION,
    CB_BREAKPOINT,
    CB_PAUSEDEBUG,
    CB_RESUMEDEBUG,
    CB_STEPPED,
    CB_ATTACH,
    CB_DETACH,
    CB_DEBUGEVENT,
    CB_MENUENTRY,
    CB_WINEVENT,
    CB_WINEVENTGLOBAL,
    CB_LOADDB,
    CB_SAVEDB,
    CB_FILTERSYMBOL,
    CB_TRACEEXECUTE,
    CB_SELCHANGED,
    CB_ANALYZE,
    CB_ADDRINFO,
    CB_VALFROMSTRING,
    CB_VALTOSTRING,
    CB_MENUPREPARE,
    CB_STOPPINGDEBUG,
    CB_LAST,
};

// ── Plugin init / setup structs (ABI-compatible) ────────────────────
pub const PLUG_INITSTRUCT = extern struct {
    pluginHandle: c_int,
    sdkVersion: c_int,
    pluginVersion: c_int,
    pluginName: [256]u8,
};

pub const PLUG_SETUPSTRUCT = extern struct {
    hwndDlg: usize, // HWND
    hMenu: c_int,
    hMenuDisasm: c_int,
    hMenuDump: c_int,
    hMenuStack: c_int,
    hMenuGraph: c_int,
    hMenuMemmap: c_int,
    hMenuSymmod: c_int,
};

// ── Callback info structs ───────────────────────────────────────────
pub const PLUG_CB_INITDEBUG = extern struct {
    szFileName: [*:0]const u8,
};

pub const PLUG_CB_STOPDEBUG = extern struct {
    reserved: usize,
};

pub const PLUG_CB_MENUENTRY = extern struct {
    hEntry: c_int,
};

pub const BPXTYPE = enum(u32) {
    None = 0,
    Normal = 1,
    Hardware = 2,
    Memory = 4,
    Dll = 8,
    Exception = 16,
};

pub const BRIDGEBP = extern struct {
    @"type": BPXTYPE,
    addr: usize,
    enabled: u8,
    singleshoot: u8,
    active: u8,
    name: [MAX_BREAKPOINT_SIZE]u8,
    mod: [MAX_MODULE_SIZE]u8,
    slot: u16,
    typeEx: u8,
    hwSize: u8,
    hitCount: u32,
    fastResume: u8,
    silent: u8,
    breakCondition: [MAX_BREAKPOINT_SIZE]u8,
    logText: [MAX_BREAKPOINT_SIZE]u8,
    logCondition: [MAX_BREAKPOINT_SIZE]u8,
    commandText: [MAX_BREAKPOINT_SIZE]u8,
    commandCondition: [MAX_BREAKPOINT_SIZE]u8,
};

pub const PLUG_CB_BREAKPOINT = extern struct {
    breakpoint: *const BRIDGEBP,
};

pub const PLUG_CB_SYSTEMBREAKPOINT = extern struct {
    reserved: usize,
};

pub const EXCEPTION_RECORD = extern struct {
    ExceptionCode: u32,
    ExceptionFlags: u32,
    ExceptionRecord: ?*EXCEPTION_RECORD,
    ExceptionAddress: usize,
    NumberParameters: u32,
    ExceptionInformation: [15]usize,
};

pub const EXCEPTION_DEBUG_INFO = extern struct {
    ExceptionRecord: EXCEPTION_RECORD,
    dwFirstChance: u32,
};

pub const PLUG_CB_EXCEPTION = extern struct {
    Exception: *EXCEPTION_DEBUG_INFO,
};

// ── Disassembly structs ────────────────────────────────────────────
pub const VALUE_INFO = extern struct {
    value: duint,
    size: u32,
};

pub const DISASM_MEMORY_INFO = extern struct {
    value: duint,
    size: u32,
    mnemonic: [MAX_MNEMONIC_SIZE]u8,
};

pub const BASIC_INSTRUCTION_INFO = extern struct {
    @"type": u32,
    value: VALUE_INFO,
    memory: DISASM_MEMORY_INFO,
    size: u32,
    instruction: [MAX_MNEMONIC_SIZE * 4]u8,
    addr: duint,
    branch: bool,
    call: bool,
    argcount: c_int,
    argvalue: [4]duint,
};

// ── Memory map structs ─────────────────────────────────────────────
const is_64 = @sizeOf(usize) == 8;
pub const MEMPAGE = extern struct {
    mbi_BaseAddress: duint,
    mbi_AllocationBase: duint,
    mbi_AllocationProtect: u32,
    mbi_RegionSize: duint,
    mbi_State: u32,
    mbi_Protect: u32,
    mbi_Type: u32,
    // MEMORY_BASIC_INFORMATION has trailing padding on x64
    _mbi_pad: [if (is_64) 4 else 0]u8,
    info: [MAX_MODULE_SIZE]u8,
};

pub const MEMMAP = extern struct {
    count: c_int,
    page: [*]MEMPAGE,
};

// ── Breakpoint list ────────────────────────────────────────────────
pub const BPMAP = extern struct {
    count: c_int,
    bp: [*]BRIDGEBP,
};

// ── Thread structs ─────────────────────────────────────────────────
pub const FILETIME = extern struct {
    dwLowDateTime: u32,
    dwHighDateTime: u32,
};

pub const MAX_THREAD_NAME_SIZE = 256;

pub const THREADINFO = extern struct {
    ThreadNumber: c_int,
    hThread: usize,
    ThreadId: u32,
    ThreadStartAddress: duint,
    ThreadLocalBase: duint,
    threadName: [MAX_THREAD_NAME_SIZE]u8,
};

pub const THREADALLINFO = extern struct {
    BasicInfo: THREADINFO,
    Cip: duint,
    SuspendCount: u32,
    Priority: c_int,
    WaitReason: c_int,
    LastError: u32,
    UserTime: FILETIME,
    KernelTime: FILETIME,
    CreationTime: FILETIME,
    Cycles: u64,
};

pub const THREADLIST = extern struct {
    count: c_int,
    list: [*]THREADALLINFO,
    CurrentThread: c_int,
};

pub const PLUG_CB_CREATEPROCESS = extern struct {
    CreateProcessInfo: usize,
    modInfo: usize,
    DebugFileName: [*:0]const u8,
    fdProcessInfo: usize,
};

pub const PLUG_CB_LOADDLL = extern struct {
    LoadDll: usize,
    modInfo: usize,
    modname: [*:0]const u8,
};

pub const ICONDATA = extern struct {
    data: [*]const u8,
    size: usize,
};

// ── Callback function pointer types ─────────────────────────────────
pub const CBPLUGIN = *const fn (cbType: CBTYPE, callbackInfo: *anyopaque) callconv(.c) void;
pub const CBPLUGINCOMMAND = *const fn (argc: c_int, argv: [*]const [*:0]const u8) callconv(.c) BOOL;

// ── Runtime-resolved function pointers ──────────────────────────────
// Populated by init() at plugin load time.

var bridge_module: ?HMODULE = null;
var dbg_module: ?HMODULE = null;

// Bridge functions
pub var DbgCmdExec: *const fn ([*:0]const u8) callconv(.c) BOOL = undefined;
pub var DbgCmdExecDirect: *const fn ([*:0]const u8) callconv(.c) BOOL = undefined;
pub var DbgIsDebugging: *const fn () callconv(.c) BOOL = undefined;
pub var DbgIsRunning: *const fn () callconv(.c) BOOL = undefined;
pub var DbgIsRunLocked: *const fn () callconv(.c) BOOL = undefined;
pub var DbgValFromString: *const fn ([*:0]const u8) callconv(.c) duint = undefined;
pub var DbgMemRead: *const fn (va: duint, dest: [*]u8, size: duint) callconv(.c) BOOL = undefined;
pub var DbgMemWrite: *const fn (va: duint, src: [*]const u8, size: duint) callconv(.c) BOOL = undefined;
pub var DbgGetLabelAt: *const fn (addr: duint, segment: c_int, text: [*]u8) callconv(.c) BOOL = undefined;
pub var DbgGetCommentAt: *const fn (addr: duint, text: [*]u8) callconv(.c) BOOL = undefined;
pub var DbgGetModuleAt: *const fn (addr: duint, text: [*]u8) callconv(.c) BOOL = undefined;
pub var DbgModBaseFromName: *const fn ([*:0]const u8) callconv(.c) duint = undefined;
pub var DbgMemFindBaseAddr: *const fn (addr: duint, size: *duint) callconv(.c) duint = undefined;
pub var DbgSetCommentAt: *const fn (addr: duint, text: [*:0]const u8) callconv(.c) BOOL = undefined;
pub var DbgSetLabelAt: *const fn (addr: duint, text: [*:0]const u8) callconv(.c) BOOL = undefined;

// Plugin functions
pub var _plugin_registercallback: *const fn (pluginHandle: c_int, cbType: CBTYPE, cbPlugin: CBPLUGIN) callconv(.c) void = undefined;
pub var _plugin_unregistercallback: *const fn (pluginHandle: c_int, cbType: CBTYPE) callconv(.c) BOOL = undefined;
pub var _plugin_registercommand: *const fn (pluginHandle: c_int, command: [*:0]const u8, cbCommand: CBPLUGINCOMMAND, debugonly: BOOL) callconv(.c) BOOL = undefined;
pub var _plugin_unregistercommand: *const fn (pluginHandle: c_int, command: [*:0]const u8) callconv(.c) BOOL = undefined;
pub var _plugin_menuadd: *const fn (hMenu: c_int, title: [*:0]const u8) callconv(.c) c_int = undefined;
pub var _plugin_menuaddentry: *const fn (hMenu: c_int, hEntry: c_int, title: [*:0]const u8) callconv(.c) BOOL = undefined;
pub var _plugin_menuaddseparator: *const fn (hMenu: c_int) callconv(.c) BOOL = undefined;
const MenuSetIconFn = *const fn (hMenu: c_int, icon: *const ICONDATA) callconv(.c) void;
pub var _plugin_menuseticon: ?MenuSetIconFn = null;
pub var _plugin_logputs: *const fn ([*:0]const u8) callconv(.c) void = undefined;
pub var _plugin_menuclear: *const fn (hMenu: c_int) callconv(.c) BOOL = undefined;
const EntrySetIconFn = *const fn (pluginHandle: c_int, hEntry: c_int, icon: *const ICONDATA) callconv(.c) void;
pub var _plugin_menuentryseticon: ?EntrySetIconFn = null;

// Extended bridge functions (optional)
const DbgDisasmFastAtFn = *const fn (addr: duint, info: *BASIC_INSTRUCTION_INFO) callconv(.c) BOOL;
pub var DbgDisasmFastAt: ?DbgDisasmFastAtFn = null;
const DbgGetBpListFn = *const fn (bptype: c_int, list: *BPMAP) callconv(.c) BOOL;
pub var DbgGetBpList: ?DbgGetBpListFn = null;
const DbgMemMapFn = *const fn (memmap: *MEMMAP) callconv(.c) BOOL;
pub var DbgMemMap: ?DbgMemMapFn = null;
const DbgGetThreadListFn = *const fn (list: *THREADLIST) callconv(.c) void;
pub var DbgGetThreadList: ?DbgGetThreadListFn = null;
const BridgeFreeFn = *const fn (ptr: *anyopaque) callconv(.c) void;
pub var BridgeFree: ?BridgeFreeFn = null;

// Extended bridge functions (optional) — continued
const DbgFunctionGetFn = *const fn (addr: duint, start: *duint, end: *duint) callconv(.c) BOOL;
pub var DbgFunctionGet: ?DbgFunctionGetFn = null;

// GUI functions (from x64bridge.dll)
const GuiGetDisassemblyFn = *const fn (addr: duint, text: [*]u8) callconv(.c) BOOL;
pub var GuiGetDisassembly: ?GuiGetDisassemblyFn = null;

fn resolve(comptime T: type, module: HMODULE, name: [*:0]const u8) T {
    const raw = GetProcAddress(module, name);
    if (raw) |ptr| {
        return @ptrCast(ptr);
    }
    @panic("x64dbg bridge symbol not found");
}

fn resolveOptional(comptime T: type, module: HMODULE, name: [*:0]const u8) ?T {
    const raw = GetProcAddress(module, name);
    if (raw) |ptr| {
        return @ptrCast(ptr);
    }
    return null;
}

pub fn init() !void {
    const bridge_dll: [*:0]const u8 = if (@sizeOf(usize) == 8)
        "x64bridge.dll"
    else
        "x32bridge.dll";

    const plugin_dll: [*:0]const u8 = if (@sizeOf(usize) == 8)
        "x64dbg.dll"
    else
        "x32dbg.dll";

    bridge_module = GetModuleHandleA(bridge_dll) orelse
        return error.BridgeNotFound;

    dbg_module = GetModuleHandleA(plugin_dll) orelse
        return error.BridgeNotFound;

    const m = bridge_module.?;
    const d = dbg_module.?;

    // Dbg functions (from x64bridge.dll / x32bridge.dll)
    DbgCmdExec = resolve(@TypeOf(DbgCmdExec), m, "DbgCmdExec");
    DbgCmdExecDirect = resolve(@TypeOf(DbgCmdExecDirect), m, "DbgCmdExecDirect");
    DbgIsDebugging = resolve(@TypeOf(DbgIsDebugging), m, "DbgIsDebugging");
    DbgIsRunning = resolve(@TypeOf(DbgIsRunning), m, "DbgIsRunning");
    DbgIsRunLocked = resolve(@TypeOf(DbgIsRunLocked), m, "DbgIsRunLocked");
    DbgValFromString = resolve(@TypeOf(DbgValFromString), m, "DbgValFromString");
    DbgMemRead = resolve(@TypeOf(DbgMemRead), m, "DbgMemRead");
    DbgMemWrite = resolve(@TypeOf(DbgMemWrite), m, "DbgMemWrite");
    DbgGetLabelAt = resolve(@TypeOf(DbgGetLabelAt), m, "DbgGetLabelAt");
    DbgGetCommentAt = resolve(@TypeOf(DbgGetCommentAt), m, "DbgGetCommentAt");
    DbgGetModuleAt = resolve(@TypeOf(DbgGetModuleAt), m, "DbgGetModuleAt");
    DbgModBaseFromName = resolve(@TypeOf(DbgModBaseFromName), m, "DbgModBaseFromName");
    DbgMemFindBaseAddr = resolve(@TypeOf(DbgMemFindBaseAddr), m, "DbgMemFindBaseAddr");
    DbgSetCommentAt = resolve(@TypeOf(DbgSetCommentAt), m, "DbgSetCommentAt");
    DbgSetLabelAt = resolve(@TypeOf(DbgSetLabelAt), m, "DbgSetLabelAt");

    // Extended bridge functions (optional)
    DbgDisasmFastAt = resolveOptional(DbgDisasmFastAtFn, m, "DbgDisasmFastAt");
    DbgGetBpList = resolveOptional(DbgGetBpListFn, m, "DbgGetBpList");
    DbgMemMap = resolveOptional(DbgMemMapFn, m, "DbgMemMap");
    DbgGetThreadList = resolveOptional(DbgGetThreadListFn, m, "DbgGetThreadList");
    BridgeFree = resolveOptional(BridgeFreeFn, m, "BridgeFree");
    GuiGetDisassembly = resolveOptional(GuiGetDisassemblyFn, m, "GuiGetDisassembly");
    DbgFunctionGet = resolveOptional(DbgFunctionGetFn, m, "DbgFunctionGet");

    // Plugin functions (from x64dbg.dll / x32dbg.dll)
    _plugin_registercallback = resolve(@TypeOf(_plugin_registercallback), d, "_plugin_registercallback");
    _plugin_unregistercallback = resolve(@TypeOf(_plugin_unregistercallback), d, "_plugin_unregistercallback");
    _plugin_registercommand = resolve(@TypeOf(_plugin_registercommand), d, "_plugin_registercommand");
    _plugin_unregistercommand = resolve(@TypeOf(_plugin_unregistercommand), d, "_plugin_unregistercommand");
    _plugin_menuadd = resolve(@TypeOf(_plugin_menuadd), d, "_plugin_menuadd");
    _plugin_menuaddentry = resolve(@TypeOf(_plugin_menuaddentry), d, "_plugin_menuaddentry");
    _plugin_menuaddseparator = resolve(@TypeOf(_plugin_menuaddseparator), d, "_plugin_menuaddseparator");
    _plugin_menuseticon = resolveOptional(MenuSetIconFn, d, "_plugin_menuseticon");
    _plugin_menuclear = resolve(@TypeOf(_plugin_menuclear), d, "_plugin_menuclear");
    _plugin_menuentryseticon = resolveOptional(EntrySetIconFn, d, "_plugin_menuentryseticon");
    _plugin_logputs = resolve(@TypeOf(_plugin_logputs), d, "_plugin_logputs");
}

// ── Helpers ─────────────────────────────────────────────────────────

pub fn logPuts(msg: [*:0]const u8) void {
    _plugin_logputs(msg);
}

// x64dbg bridge functions return C++ bool (1 byte in AL).
// Our fn pointers declare BOOL (i32 / full EAX). On x86 the upper
// 3 bytes of EAX can be garbage, so mask to the low byte.
pub fn isDebugging() bool {
    return (@as(u32, @bitCast(DbgIsDebugging())) & 0xFF) != 0;
}

pub fn isRunning() bool {
    return (@as(u32, @bitCast(DbgIsRunning())) & 0xFF) != 0;
}

pub fn isRunLocked() bool {
    return (@as(u32, @bitCast(DbgIsRunLocked())) & 0xFF) != 0;
}

pub fn valFromString(expr: [*:0]const u8) duint {
    return DbgValFromString(expr);
}

pub fn cmdExec(cmd: [*:0]const u8) bool {
    return DbgCmdExec(cmd) != 0;
}

pub fn cmdExecDirect(cmd: [*:0]const u8) bool {
    return DbgCmdExecDirect(cmd) != 0;
}

pub fn memRead(addr: duint, buf: []u8) bool {
    return DbgMemRead(addr, buf.ptr, buf.len) != 0;
}

pub fn memWrite(addr: duint, data: []const u8) bool {
    return DbgMemWrite(addr, data.ptr, data.len) != 0;
}

pub fn getLabelAt(addr: duint, buf: *[MAX_LABEL_SIZE]u8) bool {
    return DbgGetLabelAt(addr, 0, buf) != 0;
}

pub fn getCommentAt(addr: duint, buf: *[MAX_COMMENT_SIZE]u8) bool {
    return DbgGetCommentAt(addr, buf) != 0;
}

pub fn getModuleAt(addr: duint, buf: *[MAX_MODULE_SIZE]u8) bool {
    return DbgGetModuleAt(addr, buf) != 0;
}

pub fn cstrSlice(buf: []const u8) []const u8 {
    for (buf, 0..) |c, i| {
        if (c == 0) return buf[0..i];
    }
    return buf;
}
