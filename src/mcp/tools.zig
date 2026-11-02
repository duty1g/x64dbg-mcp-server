// MCP tool implementations.
// Each tool is a function that takes parsed JSON params and writes
// a result string into a buffer.

const std = @import("std");
const bridge = @import("../core/bridge.zig");
const json = @import("json.zig");
const JsonWriter = json.JsonWriter;
const main = @import("../main.zig");
const mcp = @import("../core/mcp_server.zig");

extern "kernel32" fn Sleep(dwMilliseconds: u32) callconv(.winapi) void;
extern "kernel32" fn GetTickCount64() callconv(.winapi) u64;

pub const ToolResult = struct {
    text: []const u8,
    is_error: bool = false,
};

// ── Tool registry ───────────────────────────────────────────────────

pub const ToolDef = struct {
    name: []const u8,
    description: []const u8,
    /// The group the tool belongs to.  ListCommandsByCategory lists the
    /// tools grouped by it.
    category: []const u8 = "General",
    debug_only: bool,
    read_only: bool,
    handler: *const fn (params: ?std.json.Value, out: []u8) ToolResult,
    schema_fn: *const fn (w: *JsonWriter) void,
};

/// The categories the tools are grouped in, in the order they are
/// listed.
pub const categories = [_][]const u8{
    "State & Control",
    "Stepping",
    "Breakpoints",
    "Disassembly & Code",
    "Registers & Stack",
    "Memory",
    "Modules & Symbols",
    "Analysis",
    "Bookmarks & Comments",
    "Threads",
};

pub const tools = [_]ToolDef{
    // ── Always available ────────────────────────────────────────
    .{
        .name = "GetDebugState",
        .category = "State & Control",
        .description = "Returns the current debugger state: whether a binary is loaded, whether it is running or paused, the PID, current instruction pointer, and current module. Always available. Takes no arguments.",
        .debug_only = false,
        .read_only = true,
        .handler = getDebugState,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "LoadBinary",
        .category = "State & Control",
        .description = "Loads an executable into the debugger for a new debugging session. Equivalent to File > Open in the GUI. If a session is already active it is terminated first. The debuggee pauses at the system breakpoint.",
        .debug_only = false,
        .read_only = false,
        .handler = loadBinary,
        .schema_fn = schemaLoadBinary,
    },
    .{
        .name = "ExecuteDebuggerCommand",
        .category = "State & Control",
        .description = "Executes a native x64dbg command string (like 'erun', 'analr', 'graph'). This is for x64dbg-internal commands ONLY — do NOT pass MCP tool names here. MCP tools (WaitForEvent, GetDebugState, Disassemble, etc.) must be called directly as tools.",
        .debug_only = false,
        .read_only = false,
        .handler = executeDebuggerCommand,
        .schema_fn = schemaExecuteDebuggerCommand,
    },
    .{
        .name = "ListCommandsByCategory",
        .category = "State & Control",
        .description = "Lists the available MCP tools, optionally filtered to a single category.",
        .debug_only = false,
        .read_only = true,
        .handler = listCommandsByCategory,
        .schema_fn = schemaListCommandsByCategory,
    },
    .{
        .name = "SearchForStrings",
        .category = "State & Control",
        .description = "Searches process memory for a specific text string and returns the addresses where it occurs.",
        .debug_only = false,
        .read_only = true,
        .handler = searchForStrings,
        .schema_fn = schemaSearchForStrings,
    },
    .{
        .name = "GetEventLog",
        .category = "State & Control",
        .description = "Returns the last N debugger events (exceptions, breakpoints, DLL loads, thread events, etc.). Keeps the last 64 events in a ring buffer. Use this to see what happened in x64dbg.",
        .debug_only = false,
        .read_only = true,
        .handler = getEventLog,
        .schema_fn = schemaGetEventLog,
    },
    .{
        .name = "ClearEventLog",
        .category = "State & Control",
        .description = "Clears the event log ring buffer.",
        .debug_only = false,
        .read_only = false,
        .handler = clearEventLog,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "EvalExpression",
        .category = "State & Control",
        .description = "Evaluates an x64dbg expression (address, register, arithmetic, symbol) and returns the result in hex and decimal.",
        .debug_only = false,
        .read_only = true,
        .handler = evalExpression,
        .schema_fn = schemaEvalExpression,
    },
    .{
        .name = "AttachProcess",
        .category = "State & Control",
        .description = "Attaches the debugger to a running process by PID.",
        .debug_only = false,
        .read_only = false,
        .handler = attachProcess,
        .schema_fn = schemaAttachProcess,
    },
    .{
        .name = "Echo",
        .category = "State & Control",
        .description = "Echoes the input back to the client.",
        .debug_only = false,
        .read_only = true,
        .handler = echo,
        .schema_fn = schemaEcho,
    },
    .{
        .name = "WaitForEvent",
        .category = "State & Control",
        .description = "Blocks until a debugger event fires (breakpoint hit, paused, resumed, exception, session start/stop) or timeout. Returns all events that occurred. Use this to monitor debugger state changes in real-time over HTTP — call it after 'run' or while waiting for the user to interact with the debugger.",
        .debug_only = false,
        .read_only = true,
        .handler = waitForEvent,
        .schema_fn = schemaWaitForEvent,
    },

    // ── Debug-only ──────────────────────────────────────────────
    .{
        .name = "GetCurrentAddress",
        .category = "Disassembly & Code",
        .description = "Returns the current instruction pointer (EIP/RIP), the module it belongs to, and its label/comment. Takes no arguments.",
        .debug_only = true,
        .read_only = true,
        .handler = getCurrentAddress,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "ReadMemory",
        .category = "Memory",
        .description = "Reads raw bytes from the target process memory and returns a hex dump with ASCII. Example: ReadMemory address=0x7FF600001000, size=128",
        .debug_only = true,
        .read_only = true,
        .handler = readMemory,
        .schema_fn = schemaReadMemory,
    },
    .{
        .name = "WaitForPause",
        .category = "State & Control",
        .description = "Blocks until the debuggee stops running (hits a breakpoint, exception, or exits). Returns the reason for the pause and the current address. Use after 'run' to wait for the target to break.",
        .debug_only = true,
        .read_only = true,
        .handler = waitForPause,
        .schema_fn = schemaWaitForPause,
    },
    .{
        .name = "run",
        .category = "State & Control",
        .description = "Resumes execution and waits for the target to pause (breakpoint, exception, or exit). Blocks until a pause event occurs or timeout. Use timeoutMs to control how long to wait (default 120s). Always returns the reason for the pause and current state.",
        .debug_only = true,
        .read_only = false,
        .handler = runTarget,
        .schema_fn = schemaRunTarget,
    },
    .{
        .name = "StepInto",
        .category = "Stepping",
        .description = "Executes a single instruction, stepping INTO any call encountered (F7). Takes no arguments.",
        .debug_only = true,
        .read_only = false,
        .handler = stepInto,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "StepOver",
        .category = "Stepping",
        .description = "Executes a single instruction, stepping OVER any call/subroutine entirely (F8). Takes no arguments.",
        .debug_only = true,
        .read_only = false,
        .handler = stepOver,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "StepOut",
        .category = "Stepping",
        .description = "Runs until the current function returns to its caller (Ctrl+F9). Takes no arguments.",
        .debug_only = true,
        .read_only = false,
        .handler = stepOut,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "PauseDebug",
        .category = "State & Control",
        .description = "Pauses (suspends) the running debuggee, equivalent to Debug > Pause (F12). Takes no arguments.",
        .debug_only = true,
        .read_only = false,
        .handler = pauseDebug,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "StopDebug",
        .category = "State & Control",
        .description = "Terminates the current debugging session and closes the debuggee process. Takes no arguments.",
        .debug_only = true,
        .read_only = false,
        .handler = stopDebug,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "RestartDebug",
        .category = "State & Control",
        .description = "Restarts the current debugging session from the beginning. Takes no arguments.",
        .debug_only = true,
        .read_only = false,
        .handler = restartDebug,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "SetBreakpoint",
        .category = "Breakpoints",
        .description = "Sets a software execution breakpoint (INT3) at an address or API symbol.",
        .debug_only = true,
        .read_only = false,
        .handler = setBreakpoint,
        .schema_fn = schemaSetBreakpoint,
    },
    .{
        .name = "DeleteBreakpoint",
        .category = "Breakpoints",
        .description = "Removes a breakpoint at an address or API symbol.",
        .debug_only = true,
        .read_only = false,
        .handler = deleteBreakpoint,
        .schema_fn = schemaDeleteBreakpoint,
    },
    .{
        .name = "GetAllRegisters",
        .category = "Registers & Stack",
        .description = "Returns the current values of all general-purpose registers. Takes no arguments.",
        .debug_only = true,
        .read_only = true,
        .handler = getAllRegisters,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "GetCallStack",
        .category = "Registers & Stack",
        .description = "Returns the current thread's call stack. Takes no arguments.",
        .debug_only = true,
        .read_only = true,
        .handler = getCallStack,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "WriteMemToAddress",
        .category = "Memory",
        .description = "Patches memory by writing raw hex bytes to an address. WARNING: this modifies the live process. Example: WriteMemToAddress address=0x12345678, byteString=0F FF 90",
        .debug_only = true,
        .read_only = false,
        .handler = writeMemToAddress,
        .schema_fn = schemaWriteMemToAddress,
    },
    .{
        .name = "CommentOrLabelAtAddress",
        .category = "Bookmarks & Comments",
        .description = "Adds a comment or a label at a specific address in the disassembly.",
        .debug_only = true,
        .read_only = false,
        .handler = commentOrLabelAtAddress,
        .schema_fn = schemaCommentOrLabel,
    },
    .{
        .name = "Disassemble",
        .category = "Disassembly & Code",
        .description = "Disassembles instructions at an address. Returns instruction mnemonics with addresses. Default: 10 instructions from current IP.",
        .debug_only = true,
        .read_only = true,
        .handler = disassemble,
        .schema_fn = schemaDisassemble,
    },
    .{
        .name = "ListModules",
        .category = "Modules & Symbols",
        .description = "Lists all loaded modules (DLLs/EXE) with base addresses and sizes.",
        .debug_only = true,
        .read_only = true,
        .handler = listModules,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "ListBreakpoints",
        .category = "Breakpoints",
        .description = "Lists all active breakpoints (software, hardware, and memory).",
        .debug_only = true,
        .read_only = true,
        .handler = listBreakpoints,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "GetMemoryMap",
        .category = "Memory",
        .description = "Returns the memory map showing all memory regions with base address, size, protection, and module info.",
        .debug_only = true,
        .read_only = true,
        .handler = getMemoryMap,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "SetRegister",
        .category = "Registers & Stack",
        .description = "Sets the value of a CPU register.",
        .debug_only = true,
        .read_only = false,
        .handler = setRegister,
        .schema_fn = schemaSetRegister,
    },
    .{
        .name = "GetThreads",
        .category = "Threads",
        .description = "Lists all threads in the debugged process with IDs, instruction pointers, and names.",
        .debug_only = true,
        .read_only = true,
        .handler = getThreads,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "SwitchThread",
        .category = "Threads",
        .description = "Switches the debugger's active thread context to a different thread.",
        .debug_only = true,
        .read_only = false,
        .handler = switchThread,
        .schema_fn = schemaSwitchThread,
    },
    .{
        .name = "Assemble",
        .category = "Disassembly & Code",
        .description = "Assembles an instruction at a specific address, replacing existing bytes.",
        .debug_only = true,
        .read_only = false,
        .handler = assemble,
        .schema_fn = schemaAssemble,
    },
    .{
        .name = "GetImports",
        .category = "Modules & Symbols",
        .description = "Shows the import table of a loaded module.",
        .debug_only = true,
        .read_only = true,
        .handler = getImports,
        .schema_fn = schemaModuleName,
    },
    .{
        .name = "GetExports",
        .category = "Modules & Symbols",
        .description = "Shows the export table of a loaded module.",
        .debug_only = true,
        .read_only = true,
        .handler = getExports,
        .schema_fn = schemaModuleName,
    },
    .{
        .name = "SetHardwareBreakpoint",
        .category = "Breakpoints",
        .description = "Sets a hardware breakpoint using debug registers (DR0-DR3). Supports read, write, and execute types.",
        .debug_only = true,
        .read_only = false,
        .handler = setHardwareBreakpoint,
        .schema_fn = schemaSetHardwareBreakpoint,
    },
    .{
        .name = "SetMemoryBreakpoint",
        .category = "Breakpoints",
        .description = "Sets a memory breakpoint at an address. Triggers when memory is accessed (read/write/execute). Uses guard pages — slower than hardware breakpoints but no DR register limit.",
        .debug_only = true,
        .read_only = false,
        .handler = setMemoryBreakpoint,
        .schema_fn = schemaSetMemoryBreakpoint,
    },
    .{
        .name = "GetPatches",
        .category = "Memory",
        .description = "Lists all memory patches applied to the debugged process.",
        .debug_only = true,
        .read_only = true,
        .handler = getPatches,
        .schema_fn = schemaNoParams,
    },
    // ── New tools ──────────────────────────────────────────────────
    .{
        .name = "FindPattern",
        .category = "Memory",
        .description = "Scans module memory for a byte pattern with ?? wildcards. Returns matching addresses. Example: FindPattern pattern='E8 ?? ?? ?? ?? 85 C0 74'",
        .debug_only = true,
        .read_only = true,
        .handler = findPattern,
        .schema_fn = schemaFindPattern,
    },
    .{
        .name = "GetStrings",
        .category = "Modules & Symbols",
        .description = "Scans a module's memory for ASCII strings and returns them with their addresses.",
        .debug_only = true,
        .read_only = true,
        .handler = getStrings,
        .schema_fn = schemaGetStrings,
    },
    .{
        .name = "GetReferences",
        .category = "Disassembly & Code",
        .description = "Finds code references (CALL/JMP) to a target address within a module.",
        .debug_only = true,
        .read_only = true,
        .handler = getReferences,
        .schema_fn = schemaGetReferences,
    },
    .{
        .name = "GetFunctions",
        .category = "Disassembly & Code",
        .description = "Lists analyzed functions in a module with start addresses, sizes, and labels. Requires prior analysis (Ctrl+A in x64dbg).",
        .debug_only = true,
        .read_only = true,
        .handler = getFunctions,
        .schema_fn = schemaModuleName,
    },
    .{
        .name = "RunToAddress",
        .category = "Stepping",
        .description = "Sets a temporary breakpoint at the target address, resumes execution, and waits for the debuggee to hit it.",
        .debug_only = true,
        .read_only = false,
        .handler = runToAddress,
        .schema_fn = schemaRunToAddress,
    },
    .{
        .name = "TraceInto",
        .category = "Stepping",
        .description = "Single-steps N instructions recording the address and disassembly of each. Max 100.",
        .debug_only = true,
        .read_only = false,
        .handler = traceInto,
        .schema_fn = schemaTraceInto,
    },
    .{
        .name = "SetConditionalBreakpoint",
        .category = "Breakpoints",
        .description = "Sets a breakpoint with a condition expression and optional log text.",
        .debug_only = true,
        .read_only = false,
        .handler = setConditionalBreakpoint,
        .schema_fn = schemaSetConditionalBreakpoint,
    },
    .{
        .name = "FollowPointer",
        .category = "Registers & Stack",
        .description = "Dereferences a pointer chain N levels deep, showing each level's address and value with module info.",
        .debug_only = true,
        .read_only = true,
        .handler = followPointer,
        .schema_fn = schemaFollowPointer,
    },
    .{
        .name = "WatchExpressions",
        .category = "Registers & Stack",
        .description = "Evaluates multiple x64dbg expressions at once and returns all results. Pass comma-separated expressions.",
        .debug_only = true,
        .read_only = true,
        .handler = watchExpressions,
        .schema_fn = schemaWatchExpressions,
    },
    .{
        .name = "GetSEHChain",
        .category = "Analysis",
        .description = "Walks the Structured Exception Handler chain (x32 only) and shows each handler's address and module.",
        .debug_only = true,
        .read_only = true,
        .handler = getSEHChain,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "GetPEB",
        .category = "Analysis",
        .description = "Reads key fields from the Process Environment Block: image base, being debugged, heaps, NtGlobalFlag, image path, command line.",
        .debug_only = true,
        .read_only = true,
        .handler = getPEB,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "GetArguments",
        .category = "Registers & Stack",
        .description = "Reads function arguments from the stack (x32: [ESP+4]...) or registers (x64: RCX,RDX,R8,R9...) at the current position.",
        .debug_only = true,
        .read_only = true,
        .handler = getArguments,
        .schema_fn = schemaGetArguments,
    },
    .{
        .name = "DumpMemory",
        .category = "Memory",
        .description = "Saves a memory region to a file on disk.",
        .debug_only = true,
        .read_only = false,
        .handler = dumpMemory,
        .schema_fn = schemaDumpMemory,
    },
    .{
        .name = "AllocateMemory",
        .category = "Memory",
        .description = "Allocates a block of memory in the target process.",
        .debug_only = true,
        .read_only = false,
        .handler = allocateMemory,
        .schema_fn = schemaAllocateMemory,
    },
    .{
        .name = "FreeMemory",
        .category = "Memory",
        .description = "Frees a previously allocated memory block in the target process.",
        .debug_only = true,
        .read_only = false,
        .handler = freeMemory,
        .schema_fn = schemaFreeMemory,
    },
    .{
        .name = "EnableBreakpoint",
        .category = "Breakpoints",
        .description = "Enables a breakpoint at a given address.",
        .debug_only = true,
        .read_only = false,
        .handler = enableBreakpoint,
        .schema_fn = schemaTargetAddr,
    },
    .{
        .name = "DisableBreakpoint",
        .category = "Breakpoints",
        .description = "Disables a breakpoint at a given address without deleting it.",
        .debug_only = true,
        .read_only = false,
        .handler = disableBreakpoint,
        .schema_fn = schemaTargetAddr,
    },
    .{
        .name = "ToggleBreakpoint",
        .category = "Breakpoints",
        .description = "Toggles a breakpoint between enabled and disabled.",
        .debug_only = true,
        .read_only = false,
        .handler = toggleBreakpoint,
        .schema_fn = schemaTargetAddr,
    },
    .{
        .name = "DeleteAllBreakpoints",
        .category = "Breakpoints",
        .description = "Removes all breakpoints (normal, hardware, and memory).",
        .debug_only = true,
        .read_only = false,
        .handler = deleteAllBreakpoints,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "ResetHitCount",
        .category = "Breakpoints",
        .description = "Resets the hit counter of a breakpoint at the given address to zero.",
        .debug_only = true,
        .read_only = false,
        .handler = resetHitCount,
        .schema_fn = schemaTargetAddr,
    },
    .{
        .name = "DisassembleFunction",
        .category = "Disassembly & Code",
        .description = "Disassembles an entire function by finding its start/end boundaries from the analysis database.",
        .debug_only = true,
        .read_only = true,
        .handler = disassembleFunction,
        .schema_fn = schemaTargetAddr,
    },
    .{
        .name = "SearchSymbols",
        .category = "Modules & Symbols",
        .description = "Searches for symbols (labels) matching a pattern in a module.",
        .debug_only = true,
        .read_only = true,
        .handler = searchSymbols,
        .schema_fn = schemaSearchSymbols,
    },
    .{
        .name = "ListSymbols",
        .category = "Modules & Symbols",
        .description = "Lists exported symbols of a module.",
        .debug_only = true,
        .read_only = true,
        .handler = listSymbols,
        .schema_fn = schemaListSymbols,
    },
    .{
        .name = "SuspendThread",
        .category = "Threads",
        .description = "Suspends a thread by its thread ID.",
        .debug_only = true,
        .read_only = false,
        .handler = suspendThread,
        .schema_fn = schemaThreadOp,
    },
    .{
        .name = "ResumeThread",
        .category = "Threads",
        .description = "Resumes a suspended thread by its thread ID.",
        .debug_only = true,
        .read_only = false,
        .handler = resumeThread,
        .schema_fn = schemaThreadOp,
    },
    .{
        .name = "SetBookmark",
        .category = "Bookmarks & Comments",
        .description = "Sets a bookmark at the specified address.",
        .debug_only = true,
        .read_only = false,
        .handler = setBookmark,
        .schema_fn = schemaTargetAddr,
    },
    .{
        .name = "DeleteBookmark",
        .category = "Bookmarks & Comments",
        .description = "Deletes a bookmark at the specified address.",
        .debug_only = true,
        .read_only = false,
        .handler = deleteBookmark,
        .schema_fn = schemaTargetAddr,
    },
    .{
        .name = "ListBookmarks",
        .category = "Bookmarks & Comments",
        .description = "Lists all bookmarks with addresses and labels.",
        .debug_only = true,
        .read_only = true,
        .handler = listBookmarks,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "DumpModule",
        .category = "Analysis",
        .description = "Dumps an entire loaded module to a file on disk.",
        .debug_only = true,
        .read_only = false,
        .handler = dumpModule,
        .schema_fn = schemaDumpModule,
    },
    .{
        .name = "AnalyzeModule",
        .category = "Analysis",
        .description = "Shows PE structure analysis: sections, entry point, image size, characteristics.",
        .debug_only = true,
        .read_only = true,
        .handler = analyzeModule,
        .schema_fn = schemaModuleName,
    },
    .{
        .name = "DetectOEP",
        .category = "Analysis",
        .description = "Attempts to detect the Original Entry Point for packed executables by analyzing section characteristics.",
        .debug_only = true,
        .read_only = true,
        .handler = detectOEP,
        .schema_fn = schemaModuleName,
    },
    .{
        .name = "GetDumpableRegions",
        .category = "Memory",
        .description = "Lists memory regions that can be dumped (committed, readable) for a module or the entire process.",
        .debug_only = true,
        .read_only = true,
        .handler = getDumpableRegions,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "RestorePatches",
        .category = "Memory",
        .description = "Restores all patched bytes back to their original values.",
        .debug_only = true,
        .read_only = false,
        .handler = restorePatches,
        .schema_fn = schemaNoParams,
    },
    .{
        .name = "SetExceptionBreakpoint",
        .category = "Breakpoints",
        .description = "Controls how an exception code is handled: break into debugger or pass to application. Use this to ignore Delphi (0EEDFADE), C++ (E06D7363), or other framework exceptions during startup, or to break on specific exceptions like ILLEGAL_INSTRUCTION (C000001D).",
        .debug_only = true,
        .read_only = false,
        .handler = setExceptionBreakpoint,
        .schema_fn = schemaSetExceptionBreakpoint,
    },
    .{
        .name = "DeleteExceptionBreakpoint",
        .category = "Breakpoints",
        .description = "Removes an exception breakpoint, restoring default handling for that exception code.",
        .debug_only = true,
        .read_only = false,
        .handler = deleteExceptionBreakpoint,
        .schema_fn = schemaExceptionCode,
    },
    .{
        .name = "AnalyzeCode",
        .category = "Analysis",
        .description = "Runs x64dbg code analysis on a module or address range. This populates the function list, enables GetFunctions/GetReferences/DisassembleFunction. Must be run before those tools return useful results.",
        .debug_only = true,
        .read_only = false,
        .handler = analyzeCode,
        .schema_fn = schemaAnalyzeCode,
    },
    .{
        .name = "TraceOver",
        .category = "Stepping",
        .description = "Steps N instructions stepping OVER calls (like TraceInto but without diving into subroutines). Records address and disassembly of each step.",
        .debug_only = true,
        .read_only = false,
        .handler = traceOver,
        .schema_fn = schemaTraceInto,
    },
    .{
        .name = "SetBreakpointCommand",
        .category = "Breakpoints",
        .description = "Sets an x64dbg command to execute when a breakpoint at the given address is hit. Use for logging breakpoints (e.g., 'log {x:eax}' to log register values on hit).",
        .debug_only = true,
        .read_only = false,
        .handler = setBreakpointCommand,
        .schema_fn = schemaSetBreakpointCommand,
    },
    .{
        .name = "SetBreakpointFastResume",
        .category = "Breakpoints",
        .description = "Makes a breakpoint auto-resume after hit without pausing. Combined with SetBreakpointCommand, creates logging breakpoints that record state at thousands of call sites without stopping.",
        .debug_only = true,
        .read_only = false,
        .handler = setBreakpointFastResume,
        .schema_fn = schemaBreakpointAddrBool,
    },
    .{
        .name = "SaveDatabase",
        .category = "Analysis",
        .description = "Saves the x64dbg database (labels, comments, breakpoints, analysis) for the current module. Persists your work across sessions.",
        .debug_only = true,
        .read_only = false,
        .handler = saveDatabase,
        .schema_fn = schemaNoParams,
    },
};

// ── Schema helpers ──────────────────────────────────────────────────

fn schemaNoParams(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{},\"required\":[]}");
}

fn schemaLoadBinary(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"filePath\":{\"type\":\"string\",\"description\":\"Absolute file path of the executable to debug.\"},\"arguments\":{\"type\":\"string\",\"description\":\"Optional command-line arguments.\",\"default\":\"\"}},\"required\":[\"filePath\"]}");
}

fn schemaExecuteDebuggerCommand(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\",\"description\":\"The x64dbg command to execute.\"}},\"required\":[\"command\"]}");
}

fn schemaListCommandsByCategory(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"category\":{\"type\":\"string\",\"description\":\"Optional category to list. One of: State & Control, Stepping, Breakpoints, Disassembly & Code, Registers & Stack, Memory, Modules & Symbols, Analysis, Bookmarks & Comments, Threads. Without it, all tools are listed grouped by category.\"}},\"required\":[]}");
}

fn schemaSearchForStrings(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"searchText\":{\"type\":\"string\",\"description\":\"The literal text to search for.\"},\"encoding\":{\"type\":\"string\",\"description\":\"Character encoding: UTF-8 or UTF-16.\",\"default\":\"UTF-8\"}},\"required\":[\"searchText\"]}");
}

fn schemaGetEventLog(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"count\":{\"type\":\"integer\",\"description\":\"Number of most recent events to return (default: all, max 64).\"}},\"required\":[]}");
}

fn schemaEcho(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"message\":{\"type\":\"string\",\"description\":\"Message to echo.\"}},\"required\":[\"message\"]}");
}

fn schemaWaitForEvent(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"timeoutMs\":{\"type\":\"integer\",\"description\":\"Maximum wait time in milliseconds (default 30000, max 120000).\",\"default\":30000}},\"required\":[]}");
}

fn schemaReadMemory(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Hex address or expression to read from.\"},\"size\":{\"type\":\"integer\",\"description\":\"Number of bytes to read (max 4096).\",\"default\":64}},\"required\":[\"address\"]}");
}

fn schemaWaitForPause(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"timeoutMs\":{\"type\":\"integer\",\"description\":\"Maximum wait time in milliseconds.\",\"default\":30000}},\"required\":[]}");
}

fn schemaRunTarget(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"timeoutMs\":{\"type\":\"integer\",\"description\":\"Maximum time to wait for target to pause after resuming (default 300000ms = 5 minutes, max 600000ms = 10 minutes). The tool blocks until a breakpoint/exception fires or timeout.\",\"default\":300000}},\"required\":[]}");
}

fn schemaSetBreakpoint(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"target\":{\"type\":[\"string\",\"integer\"],\"description\":\"Hex address or API symbol to break on.\"}},\"required\":[\"target\"]}");
}

fn schemaDeleteBreakpoint(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"target\":{\"type\":[\"string\",\"integer\"],\"description\":\"Hex address or API symbol of the breakpoint to remove.\"}},\"required\":[\"target\"]}");
}

fn schemaWriteMemToAddress(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Hex address to write to.\"},\"byteString\":{\"type\":\"string\",\"description\":\"Hex bytes to write, e.g. '0F FF 90'.\"}},\"required\":[\"address\",\"byteString\"]}");
}

fn schemaCommentOrLabel(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Hex address.\"},\"value\":{\"type\":\"string\",\"description\":\"The comment or label text.\"},\"mode\":{\"type\":\"string\",\"description\":\"'Comment' or 'Label'.\",\"default\":\"Comment\"}},\"required\":[\"address\",\"value\"]}");
}

fn schemaDisassemble(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Address or expression (default: current IP).\",\"default\":\"cip\"},\"count\":{\"type\":\"integer\",\"description\":\"Number of instructions (default 10, clamped to [1, 100]).\",\"default\":10}},\"required\":[]}");
}

fn schemaEvalExpression(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"expression\":{\"type\":\"string\",\"description\":\"x64dbg expression (e.g. cip, eax+4, kernel32:CreateFileA).\"}},\"required\":[\"expression\"]}");
}

fn schemaSetRegister(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"register\":{\"type\":\"string\",\"description\":\"Register name (e.g. eax, ecx, eip).\"},\"value\":{\"type\":\"string\",\"description\":\"Value to set (hex or decimal).\"}},\"required\":[\"register\",\"value\"]}");
}

fn schemaSwitchThread(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"threadId\":{\"type\":\"integer\",\"description\":\"Thread ID to switch to.\"}},\"required\":[\"threadId\"]}");
}

fn schemaAttachProcess(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"pid\":{\"type\":\"integer\",\"description\":\"Process ID to attach to.\"}},\"required\":[\"pid\"]}");
}

fn schemaAssemble(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Address to assemble at.\"},\"instruction\":{\"type\":\"string\",\"description\":\"Assembly instruction (e.g. nop, mov eax 1, jmp 0x401000).\"}},\"required\":[\"address\",\"instruction\"]}");
}

fn schemaModuleName(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"module\":{\"type\":\"string\",\"description\":\"Module name (e.g. kernel32, ntdll).\"}},\"required\":[\"module\"]}");
}

fn schemaSetHardwareBreakpoint(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Address for the hardware breakpoint.\"},\"type\":{\"type\":\"string\",\"description\":\"Type: r (read), w (write), x (execute, default).\",\"default\":\"x\"},\"size\":{\"type\":\"integer\",\"description\":\"Size: 1, 2, 4, or 8 (default 1).\",\"default\":1}},\"required\":[\"address\"]}");
}

fn schemaSetMemoryBreakpoint(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Address for the memory breakpoint.\"},\"type\":{\"type\":\"string\",\"description\":\"Type: r (read/access), w (write), x (execute). Default: access (any).\"},\"singleshoot\":{\"type\":\"boolean\",\"description\":\"If true, breakpoint is removed after first hit (default false).\",\"default\":false}},\"required\":[\"address\"]}");
}

fn schemaFindPattern(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"pattern\":{\"type\":\"string\",\"description\":\"Hex bytes with ?? wildcards, e.g. 'E8 ?? ?? ?? ?? 85 C0'.\"},\"module\":{\"type\":\"string\",\"description\":\"Module to scan (default: main exe).\"},\"maxResults\":{\"type\":\"integer\",\"description\":\"Max results (default 10).\",\"default\":10}},\"required\":[\"pattern\"]}");
}

fn schemaGetStrings(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"module\":{\"type\":\"string\",\"description\":\"Module to scan (default: main exe).\"},\"minLength\":{\"type\":\"integer\",\"description\":\"Min string length (default 4).\",\"default\":4}},\"required\":[]}");
}

fn schemaGetReferences(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Target address to find references to.\"},\"module\":{\"type\":\"string\",\"description\":\"Module to search in (default: main exe).\"}},\"required\":[\"address\"]}");
}

fn schemaRunToAddress(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Address to run to.\"},\"timeoutMs\":{\"type\":\"integer\",\"description\":\"Timeout ms (default 30000).\",\"default\":30000}},\"required\":[\"address\"]}");
}

fn schemaTraceInto(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"count\":{\"type\":\"integer\",\"description\":\"Instructions to trace (default 10, max 100).\",\"default\":10}},\"required\":[]}");
}

fn schemaSetConditionalBreakpoint(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Breakpoint address.\"},\"condition\":{\"type\":\"string\",\"description\":\"Break condition expression, e.g. 'eax==0'.\"},\"log\":{\"type\":\"string\",\"description\":\"Log format string (optional).\"}},\"required\":[\"address\",\"condition\"]}");
}

fn schemaFollowPointer(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Starting address or expression.\"},\"depth\":{\"type\":\"integer\",\"description\":\"Dereference depth (default 1, max 16).\",\"default\":1}},\"required\":[\"address\"]}");
}

fn schemaWatchExpressions(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"expressions\":{\"type\":\"string\",\"description\":\"Comma-separated x64dbg expressions to evaluate.\"}},\"required\":[\"expressions\"]}");
}

fn schemaGetArguments(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"count\":{\"type\":\"integer\",\"description\":\"Number of args to read (default 4, max 16).\",\"default\":4}},\"required\":[]}");
}

fn schemaDumpMemory(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Start address.\"},\"size\":{\"type\":\"integer\",\"description\":\"Bytes to dump.\"},\"filePath\":{\"type\":\"string\",\"description\":\"Output file path on disk.\"}},\"required\":[\"address\",\"size\",\"filePath\"]}");
}

fn schemaTargetAddr(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Target address or expression.\"}},\"required\":[\"address\"]}");
}

fn schemaAllocateMemory(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"size\":{\"type\":\"integer\",\"description\":\"Number of bytes to allocate.\"},\"protection\":{\"type\":\"string\",\"description\":\"Memory protection: rwx, rw, rx, r (default rw).\",\"default\":\"rw\"}},\"required\":[\"size\"]}");
}

fn schemaFreeMemory(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Base address of the allocated block to free.\"}},\"required\":[\"address\"]}");
}

fn schemaSearchSymbols(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"pattern\":{\"type\":\"string\",\"description\":\"Symbol name pattern to search for (substring match).\"},\"module\":{\"type\":\"string\",\"description\":\"Module to search in (default: all modules).\"}},\"required\":[\"pattern\"]}");
}

fn schemaListSymbols(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"module\":{\"type\":\"string\",\"description\":\"Module name to list symbols from.\"}},\"required\":[\"module\"]}");
}

fn schemaThreadOp(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"threadId\":{\"type\":\"integer\",\"description\":\"Thread ID to operate on.\"}},\"required\":[\"threadId\"]}");
}

fn schemaDumpModule(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"module\":{\"type\":\"string\",\"description\":\"Module name to dump.\"},\"filePath\":{\"type\":\"string\",\"description\":\"Output file path.\"}},\"required\":[\"module\",\"filePath\"]}");
}

fn schemaSetExceptionBreakpoint(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"exceptionCode\":{\"type\":\"string\",\"description\":\"Exception code in hex (e.g. C000001D, 0EEDFADE, E06D7363).\"},\"chance\":{\"type\":\"integer\",\"description\":\"1 = first-chance, 2 = second-chance, 3 = both (default 1).\",\"default\":1},\"action\":{\"type\":\"string\",\"description\":\"break = break into debugger, ignore = pass to application (default break).\",\"default\":\"break\"}},\"required\":[\"exceptionCode\"]}");
}

fn schemaExceptionCode(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"exceptionCode\":{\"type\":\"string\",\"description\":\"Exception code in hex to delete.\"}},\"required\":[\"exceptionCode\"]}");
}

fn schemaAnalyzeCode(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Address or module to analyze. If omitted, analyzes the current module.\"},\"type\":{\"type\":\"string\",\"description\":\"Analysis type: 'function' (analr - analyze single function), 'module' (anal - analyze module), 'controlflow' (cfanal - control flow analysis). Default: module.\",\"default\":\"module\"}},\"required\":[]}");
}

fn schemaSetBreakpointCommand(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Breakpoint address.\"},\"command\":{\"type\":\"string\",\"description\":\"x64dbg command to run on hit (e.g. 'log {x:eax}', 'msg {utf8@[esp+4]}').\"}},\"required\":[\"address\",\"command\"]}");
}

fn schemaBreakpointAddrBool(w: *JsonWriter) void {
    w.raw("{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"string\",\"integer\"],\"description\":\"Breakpoint address.\"},\"enable\":{\"type\":\"boolean\",\"description\":\"true to enable fast resume, false to disable.\",\"default\":true}},\"required\":[\"address\"]}");
}

// ── Tool implementations ────────────────────────────────────────────

fn getParamStr(params: ?std.json.Value, field: []const u8) ?[]const u8 {
    const p = params orelse return null;
    return json.getStringField(p, field);
}

/// Address-style params accept both a JSON string ("0x...", symbol, or
/// expression) and a JSON integer, which is formatted as "0x{X}" into buf.
fn getParamAddr(params: ?std.json.Value, field: []const u8, buf: []u8) ?[]const u8 {
    const p = params orelse return null;
    return json.getAddrField(p, field, buf);
}

fn getParamInt(params: ?std.json.Value, field: []const u8) ?i64 {
    const p = params orelse return null;
    return json.getIntField(p, field);
}

fn getParamBool(params: ?std.json.Value, field: []const u8) ?bool {
    const p = params orelse return null;
    const obj = p.object;
    const val = obj.get(field) orelse return null;
    return switch (val) {
        .bool => |b| b,
        else => null,
    };
}

fn result(out: []u8, text: []const u8) ToolResult {
    const len = @min(text.len, out.len);
    @memcpy(out[0..len], text[0..len]);
    return .{ .text = out[0..len] };
}

fn errResult(out: []u8, text: []const u8) ToolResult {
    const len = @min(text.len, out.len);
    @memcpy(out[0..len], text[0..len]);
    return .{ .text = out[0..len], .is_error = true };
}

fn fmtResult(out: []u8, comptime fmt: []const u8, args: anytype) ToolResult {
    const s = std.fmt.bufPrint(out, fmt, args) catch return result(out[0..0], "");
    return .{ .text = s };
}

fn fmtErr(out: []u8, comptime fmt: []const u8, args: anytype) ToolResult {
    const s = std.fmt.bufPrint(out, fmt, args) catch return errResult(out[0..0], "");
    return .{ .text = s, .is_error = true };
}

// ── PE / memory helpers ────────────────────────────────────────────
fn readU16LE(buf: []const u8) u16 {
    return @as(u16, buf[0]) | (@as(u16, buf[1]) << 8);
}

fn readU32LE(buf: []const u8) u32 {
    return @as(u32, buf[0]) | (@as(u32, buf[1]) << 8) | (@as(u32, buf[2]) << 16) | (@as(u32, buf[3]) << 24);
}

fn readPtrLE(buf: []const u8) usize {
    if (@sizeOf(usize) == 8) {
        return @as(usize, readU32LE(buf[0..4])) | (@as(usize, readU32LE(buf[4..8])) << 32);
    }
    return @as(usize, readU32LE(buf[0..4]));
}

const DataDir = struct { rva: u32, size: u32 };

fn peGetDataDir(base: usize, index: usize) ?DataDir {
    var buf4: [4]u8 = undefined;
    if (!bridge.memRead(base + 0x3C, &buf4)) return null;
    const pe_off: usize = readU32LE(&buf4);
    if (!bridge.memRead(base + pe_off, &buf4)) return null;
    if (!std.mem.eql(u8, &buf4, "PE\x00\x00")) return null;
    var magic: [2]u8 = undefined;
    if (!bridge.memRead(base + pe_off + 24, &magic)) return null;
    const dd_base = base + pe_off + 24 + (if (readU16LE(&magic) == 0x20B) @as(usize, 112) else @as(usize, 96));
    var dd: [8]u8 = undefined;
    if (!bridge.memRead(dd_base + index * 8, &dd)) return null;
    return .{ .rva = readU32LE(dd[0..4]), .size = readU32LE(dd[4..8]) };
}

fn isModulePath(name: []const u8) bool {
    if (name.len < 4) return false;
    var ext: [4]u8 = undefined;
    for (0..4) |i| {
        const c = name[name.len - 4 + i];
        ext[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
    }
    return std.mem.eql(u8, &ext, ".dll") or std.mem.eql(u8, &ext, ".exe") or
        std.mem.eql(u8, &ext, ".drv") or std.mem.eql(u8, &ext, ".sys") or
        std.mem.eql(u8, &ext, ".ocx");
}

fn resolveModBase(module: []const u8) usize {
    var mod_buf: [256]u8 = undefined;
    const mod_z = std.fmt.bufPrint(&mod_buf, "{s}\x00", .{module}) catch return 0;
    _ = mod_z;
    return bridge.DbgModBaseFromName(@ptrCast(mod_buf[0..module.len + 1].ptr));
}

// ── GetEventLog ────────────────────────────────────────────────────
fn getEventLog(params: ?std.json.Value, out: []u8) ToolResult {
    const total = main.getEventCount();
    if (total == 0) return result(out, "No events recorded.");

    var count = total;
    if (getParamInt(params, "count")) |c| {
        count = @intCast(@min(@max(c, 1), @as(i64, @intCast(total))));
    }

    const start_idx = if (total > count) total - count else 0;
    var pos: usize = 0;
    const header = std.fmt.bufPrint(out[pos..], "Events ({d}/{d}):\n", .{ count, total }) catch return result(out[0..0], "");
    pos += header.len;

    var i: usize = start_idx;
    while (i < total) : (i += 1) {
        const room = out.len - pos;
        if (room < 2) break;
        const evt_len = main.copyEvent(i, out[pos .. pos + room - 1]);
        if (evt_len == 0) break;
        pos += @min(evt_len, room - 1);
        out[pos] = '\n';
        pos += 1;
        if (evt_len > room - 1) break;
    }
    return .{ .text = out[0..pos] };
}

// ── ClearEventLog ──────────────────────────────────────────────────
fn clearEventLog(_: ?std.json.Value, out: []u8) ToolResult {
    main.clearEvents();
    return result(out, "Event log cleared.");
}

// ── GetDebugState ───────────────────────────────────────────────────
fn getDebugState(_: ?std.json.Value, out: []u8) ToolResult {
    const debugging = bridge.isDebugging();
    const running = bridge.isRunning();
    const locked = bridge.isRunLocked();

    if (!debugging) {
        return fmtResult(out, "isDebugging: false\nstatus: NO_TARGET\nhint: Use LoadBinary to open an executable first.", .{});
    }

    const pid = bridge.valFromString("$pid");
    const status: []const u8 = if (running) "RUNNING" else if (locked) "LOCKED" else "PAUSED";

    if (running) {
        return fmtResult(out, "isDebugging: true\nisRunning: true\npid: {d}\nstatus: {s}", .{ pid, status });
    }

    const cip = bridge.valFromString("cip");
    const csp = bridge.valFromString("csp");
    var mod_buf: [bridge.MAX_MODULE_SIZE]u8 = undefined;
    const has_mod = bridge.getModuleAt(cip, &mod_buf);
    const mod_name = if (has_mod) bridge.cstrSlice(&mod_buf) else "unknown";

    return fmtResult(out, "isDebugging: true\nisRunning: false\npid: {d}\nstatus: {s}\ncurrentAddress: 0x{X}\ncurrentModule: {s}\nstackPointer: 0x{X}", .{ pid, status, cip, mod_name, csp });
}

// ── GetCurrentAddress ───────────────────────────────────────────────
fn getCurrentAddress(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");

    const cip = bridge.valFromString("cip");
    var mod_buf: [bridge.MAX_MODULE_SIZE]u8 = undefined;
    const has_mod = bridge.getModuleAt(cip, &mod_buf);
    const mod_name = if (has_mod) bridge.cstrSlice(&mod_buf) else "unknown";

    var label_buf: [bridge.MAX_LABEL_SIZE]u8 = undefined;
    const has_label = bridge.getLabelAt(cip, &label_buf);
    const label = if (has_label) bridge.cstrSlice(&label_buf) else "";

    var comment_buf: [bridge.MAX_COMMENT_SIZE]u8 = undefined;
    const has_comment = bridge.getCommentAt(cip, &comment_buf);
    const comment = if (has_comment) bridge.cstrSlice(&comment_buf) else "";

    return fmtResult(out, "address: 0x{X}\nmodule: {s}\nlabel: {s}\ncomment: {s}", .{ cip, mod_name, label, comment });
}

// ── LoadBinary ──────────────────────────────────────────────────────
fn loadBinary(params: ?std.json.Value, out: []u8) ToolResult {
    const path = getParamStr(params, "filePath") orelse
        return errResult(out, "Error: filePath is required.");

    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "init \"{s}\"\x00", .{path}) catch
        return errResult(out, "Error: path too long.");
    _ = bridge.cmdExec(@ptrCast(cmd.ptr));
    Sleep(500);

    if (bridge.isDebugging()) {
        const cip = bridge.valFromString("cip");
        return fmtResult(out, "SUCCESS: Binary loaded. Paused at 0x{X}. Use 'run' to continue.", .{cip});
    }
    return result(out, "Binary init command sent. The debuggee may still be loading.");
}

// ── ExecuteDebuggerCommand ──────────────────────────────────────────
const mcp_tool_names = [_][]const u8{
    "WaitForEvent",     "WaitForPause",      "GetDebugState",     "LoadBinary",
    "StepInto",         "StepOver",          "StepOut",           "SetBreakpoint",
    "DeleteBreakpoint", "GetAllRegisters",   "Disassemble",       "ReadMemory",
    "GetCallStack",     "ListModules",       "ListBreakpoints",   "GetMemoryMap",
    "SetRegister",      "GetThreads",        "GetImports",        "GetExports",
    "FindPattern",      "GetStrings",        "SearchSymbols",     "EvalExpression",
    "AttachProcess",    "PauseDebug",        "StopDebug",         "RestartDebug",
};

fn isMcpToolName(cmd: []const u8) bool {
    for (&mcp_tool_names) |name| {
        if (std.ascii.eqlIgnoreCase(cmd, name)) return true;
    }
    return false;
}

fn executeDebuggerCommand(params: ?std.json.Value, out: []u8) ToolResult {
    const command = getParamStr(params, "command") orelse
        return errResult(out, "Error: command is required.");

    // Intercept MCP tool names passed as x64dbg commands
    const trimmed = std.mem.trim(u8, command, " \t\r\n");
    const first_word = blk: {
        const sp = std.mem.indexOf(u8, trimmed, " ") orelse trimmed.len;
        break :blk trimmed[0..sp];
    };
    if (isMcpToolName(first_word)) {
        return fmtResult(out, "Error: '{s}' is an MCP tool, not an x64dbg command. Call it directly as a tool (tools/call), not through ExecuteDebuggerCommand.", .{first_word});
    }

    const was_paused = !bridge.isRunning();
    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "{s}\x00", .{command}) catch
        return errResult(out, "Error: command too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    Sleep(250);

    // If command resumed execution, block until target pauses again (up to 120s)
    if (ok and was_paused and bridge.isRunning()) {
        const start = @as(i64, @intCast(GetTickCount64()));
        const timeout: i64 = 300000;
        while (@as(i64, @intCast(GetTickCount64())) - start < timeout) {
            if (!bridge.isDebugging())
                return result(out, "Command executed. TARGET_EXITED — debug session ended.");
            if (!bridge.isRunning()) {
                const elapsed = @as(i64, @intCast(GetTickCount64())) - start;
                var pos: usize = 0;
                const hdr = std.fmt.bufPrint(out[pos..], "Command executed. PAUSED after {d}ms.", .{elapsed}) catch return errResult(out, "Error");
                pos += hdr.len;
                appendStepContext(out, &pos);
                return .{ .text = out[0..pos] };
            }
            Sleep(100);
        }
        return result(out, "Command executed. Target still RUNNING after 5 minutes. Call run to keep monitoring — do NOT go idle.");
    }

    var pos: usize = 0;
    const status = if (ok) "Command executed successfully." else "Command execution failed.";
    const hdr = std.fmt.bufPrint(out[pos..], "{s}", .{status}) catch return errResult(out, "Error");
    pos += hdr.len;
    if (!bridge.isRunning() and bridge.isDebugging()) {
        appendStepContext(out, &pos);
    }
    return .{ .text = out[0..pos] };
}

// ── Echo ────────────────────────────────────────────────────────────
fn echo(params: ?std.json.Value, out: []u8) ToolResult {
    const msg = getParamStr(params, "message") orelse return result(out, "");
    return result(out, msg);
}

// ── WaitForEvent ────────────────────────────────────────────────────
fn waitForEvent(params: ?std.json.Value, out: []u8) ToolResult {
    var timeout_ms: i64 = 30000;
    if (getParamInt(params, "timeoutMs")) |t| {
        timeout_ms = @min(@max(t, 100), 120000);
    }

    // If events already queued, return immediately
    if (mcp.pendingHasEvents()) {
        const n = mcp.pendingDrainToBuffer(out);
        return .{ .text = out[0..n] };
    }

    // Long-poll: wait for an event or timeout
    const start = @as(i64, @intCast(GetTickCount64()));
    while (@as(i64, @intCast(GetTickCount64())) - start < timeout_ms) {
        if (mcp.pendingHasEvents()) {
            const n = mcp.pendingDrainToBuffer(out);
            return .{ .text = out[0..n] };
        }
        Sleep(100);
    }

    if (bridge.isRunning()) {
        return result(out, "NO_EVENTS — target still RUNNING. Call WaitForEvent again to keep monitoring.");
    }
    return result(out, "NO_EVENTS — no debugger events within timeout.");
}

// ── ListCommandsByCategory ──────────────────────────────────────────
fn writeToolLine(w: *JsonWriter, t: *const ToolDef) void {
    w.raw("- ");
    w.raw(t.name);
    if (t.debug_only) w.raw(" [debug-only]");
    w.raw(": ");
    w.raw(t.description);
    w.raw("\n");
}

fn listCommandsByCategory(params: ?std.json.Value, out: []u8) ToolResult {
    var w = JsonWriter.init(out);

    // With a category, only the tools of that category are listed.
    if (getParamStr(params, "category")) |wanted| {
        if (wanted.len == 0) {
            w.raw("Error: category must not be empty. Known categories: ");
            for (categories, 0..) |c, i| {
                if (i > 0) w.raw(", ");
                w.raw(c);
            }
            w.raw("\n");
            return .{ .text = w.slice(), .is_error = true };
        }

        var known = false;
        for (categories) |category| {
            if (!std.ascii.eqlIgnoreCase(category, wanted)) continue;
            known = true;
            w.raw(category);
            w.raw(":\n");
            for (&tools) |*t| {
                if (!std.mem.eql(u8, t.category, category)) continue;
                writeToolLine(&w, t);
            }
            w.raw("\n");
        }
        if (!known) {
            w.raw("Unknown category: ");
            w.raw(wanted);
            w.raw("\nKnown categories: ");
            for (categories, 0..) |c, i| {
                if (i > 0) w.raw(", ");
                w.raw(c);
            }
            w.raw("\n");
            return .{ .text = w.slice(), .is_error = true };
        }
        return .{ .text = w.slice() };
    }

    // Without one, the tools are listed grouped by category.
    w.raw("Available tools:\n");
    for (categories) |category| {
        w.raw("\n");
        w.raw(category);
        w.raw(":\n");
        for (&tools) |*t| {
            if (!std.mem.eql(u8, t.category, category)) continue;
            writeToolLine(&w, t);
        }
    }
    return .{ .text = w.slice() };
}

// ── SearchForStrings ────────────────────────────────────────────────
fn searchForStrings(params: ?std.json.Value, out: []u8) ToolResult {
    const text = getParamStr(params, "searchText") orelse
        return errResult(out, "Error: searchText is required.");
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");

    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "findall 0, \"{s}\"\x00", .{text}) catch
        return errResult(out, "Error: search text too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Search command executed. Check the reference view for results." else "Search failed."});
}

// ── ReadMemory ──────────────────────────────────────────────────────
fn readMemory(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");

    var addr_buf: [32]u8 = undefined;
    const addr_str = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    var size: usize = 64;
    if (getParamInt(params, "size")) |s| {
        size = @intCast(@min(@max(s, 1), 4096));
    }

    var expr_buf: [256]u8 = undefined;
    const expr = std.fmt.bufPrint(&expr_buf, "{s}\x00", .{addr_str}) catch
        return errResult(out, "Error: address expression too long.");
    const addr = bridge.valFromString(@ptrCast(expr.ptr));
    if (addr == 0) return fmtErr(out, "Error: Could not resolve address '{s}'.", .{addr_str});

    var mem_buf: [4096]u8 = undefined;
    if (!bridge.memRead(addr, mem_buf[0..size])) {
        return fmtErr(out, "Error: Failed to read {d} bytes at 0x{X}.", .{ size, addr });
    }

    var pos: usize = 0;
    const header = std.fmt.bufPrint(out[pos..], "[ReadMemory] {d} bytes at 0x{X}:\n", .{ size, addr }) catch return result(out[0..pos], "");
    pos += header.len;

    var i: usize = 0;
    while (i < size) : (i += 16) {
        const row_addr = addr + i;
        const count = @min(16, size - i);

        // address
        const addr_s = std.fmt.bufPrint(out[pos..], "  {X:0>8}: ", .{row_addr}) catch break;
        pos += addr_s.len;

        // hex
        for (0..count) |j| {
            const h = std.fmt.bufPrint(out[pos..], "{X:0>2} ", .{mem_buf[i + j]}) catch break;
            pos += h.len;
        }
        // pad
        for (count..16) |_| {
            if (pos + 3 > out.len) break;
            out[pos] = ' ';
            out[pos + 1] = ' ';
            out[pos + 2] = ' ';
            pos += 3;
        }

        // ascii
        for (0..count) |j| {
            if (pos >= out.len) break;
            const b = mem_buf[i + j];
            out[pos] = if (b >= 32 and b <= 126) b else '.';
            pos += 1;
        }
        if (pos < out.len) {
            out[pos] = '\n';
            pos += 1;
        }
    }

    return .{ .text = out[0..pos] };
}

// ── WaitForPause ────────────────────────────────────────────────────
fn waitForPause(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");

    if (!bridge.isRunning()) {
        var pos: usize = 0;
        const hdr = std.fmt.bufPrint(out[pos..], "ALREADY_PAUSED.", .{}) catch return errResult(out, "Error");
        pos += hdr.len;
        appendStepContext(out, &pos);
        return .{ .text = out[0..pos] };
    }

    var timeout_ms: i64 = 30000;
    if (getParamInt(params, "timeoutMs")) |t| {
        timeout_ms = @min(@max(t, 100), 120000);
    }

    const start = @as(i64, @intCast(GetTickCount64()));
    while (@as(i64, @intCast(GetTickCount64())) - start < timeout_ms) {
        if (!bridge.isDebugging())
            return result(out, "TARGET_EXITED. The debug session has ended.");

        if (!bridge.isRunning()) {
            const elapsed = @as(i64, @intCast(GetTickCount64())) - start;
            var pos: usize = 0;
            const hdr = std.fmt.bufPrint(out[pos..], "PAUSED after {d}ms.", .{elapsed}) catch return errResult(out, "Error");
            pos += hdr.len;
            appendStepContext(out, &pos);
            return .{ .text = out[0..pos] };
        }
        Sleep(50);
    }
    return fmtResult(out, "TIMEOUT after {d}ms. Target still running. Use PauseDebug to force a break.", .{timeout_ms});
}

// ── run (F9) ────────────────────────────────────────────────────────
fn runTarget(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    _ = bridge.cmdExec("run");
    Sleep(250);

    if (!bridge.isRunning()) {
        var pos: usize = 0;
        const hdr = std.fmt.bufPrint(out[pos..], "PAUSED immediately (hit breakpoint or system event).", .{}) catch return errResult(out, "Error");
        pos += hdr.len;
        appendStepContext(out, &pos);
        return .{ .text = out[0..pos] };
    }

    // Block until target pauses, exits, or timeout (default 5 min)
    var timeout_ms: i64 = 300000;
    if (getParamInt(params, "timeoutMs")) |t| {
        timeout_ms = @min(@max(t, 1000), 600000);
    }

    const start = @as(i64, @intCast(GetTickCount64()));
    while (@as(i64, @intCast(GetTickCount64())) - start < timeout_ms) {
        if (!bridge.isDebugging())
            return result(out, "TARGET_EXITED. The debug session ended while running.");

        if (!bridge.isRunning()) {
            const elapsed = @as(i64, @intCast(GetTickCount64())) - start;
            var pos: usize = 0;
            const hdr = std.fmt.bufPrint(out[pos..], "PAUSED after {d}ms — breakpoint hit or exception.", .{elapsed}) catch return errResult(out, "Error");
            pos += hdr.len;
            appendStepContext(out, &pos);
            return .{ .text = out[0..pos] };
        }
        Sleep(100);
    }
    return result(out, "TIMEOUT after 5 minutes — target still running. Call run again to keep monitoring — do NOT go idle or ask the user.");
}

// ── Step context helper ─────────────────────────────────────────────
fn appendStepContext(out: []u8, pos: *usize) void {
    if (bridge.isRunning()) {
        const line = std.fmt.bufPrint(out[pos.*..], "\nStatus: RUNNING", .{}) catch return;
        pos.* += line.len;
        return;
    }
    const cip = bridge.valFromString("cip");
    var mod_buf: [bridge.MAX_MODULE_SIZE]u8 = undefined;
    const has_mod = bridge.getModuleAt(cip, &mod_buf);
    const mod_name = if (has_mod) bridge.cstrSlice(&mod_buf) else "unknown";

    var label_buf: [bridge.MAX_LABEL_SIZE]u8 = undefined;
    const has_label = bridge.getLabelAt(cip, &label_buf);
    const label = if (has_label) bridge.cstrSlice(&label_buf) else "";

    const addr_line = std.fmt.bufPrint(out[pos.*..], "\nAddress: 0x{X} ({s})", .{ cip, mod_name }) catch return;
    pos.* += addr_line.len;

    if (label.len > 0) {
        const lbl_line = std.fmt.bufPrint(out[pos.*..], "\nLabel: {s}", .{label}) catch return;
        pos.* += lbl_line.len;
    }

    var text_buf: [256]u8 = std.mem.zeroes([256]u8);
    if (bridge.disasmTextAt(cip, &text_buf)) {
        const instr = bridge.cstrSlice(&text_buf);
        if (instr.len > 0) {
            const dis_line = std.fmt.bufPrint(out[pos.*..], "\nInstruction: {s}", .{instr}) catch return;
            pos.* += dis_line.len;
        }
    }

    var next_buf: [64]u8 = undefined;
    const next_expr = std.fmt.bufPrint(&next_buf, "dis.next(0x{X})\x00", .{cip}) catch return;
    const next_addr = bridge.valFromString(@ptrCast(next_expr.ptr));
    if (next_addr != 0 and next_addr != cip) {
        var text_buf2: [256]u8 = std.mem.zeroes([256]u8);
        if (bridge.disasmTextAt(next_addr, &text_buf2)) {
            const next_instr = bridge.cstrSlice(&text_buf2);
            if (next_instr.len > 0) {
                const next_line = std.fmt.bufPrint(out[pos.*..], "\nNext: 0x{X}  {s}", .{ next_addr, next_instr }) catch return;
                pos.* += next_line.len;
            }
        }
    }
}

// ── StepInto (F7) ───────────────────────────────────────────────────
fn stepInto(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    _ = bridge.cmdExec("sti");
    Sleep(100);
    var pos: usize = 0;
    const hdr = std.fmt.bufPrint(out[pos..], "Stepped into.", .{}) catch return errResult(out, "Error");
    pos += hdr.len;
    appendStepContext(out, &pos);
    return .{ .text = out[0..pos] };
}

// ── StepOver (F8) ───────────────────────────────────────────────────
fn stepOver(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    _ = bridge.cmdExec("sto");
    Sleep(100);
    var pos: usize = 0;
    const hdr = std.fmt.bufPrint(out[pos..], "Stepped over.", .{}) catch return errResult(out, "Error");
    pos += hdr.len;
    appendStepContext(out, &pos);
    return .{ .text = out[0..pos] };
}

// ── StepOut (Ctrl+F9) ───────────────────────────────────────────────
fn stepOut(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    _ = bridge.cmdExec("rtr");
    Sleep(150);
    var pos: usize = 0;
    const hdr = std.fmt.bufPrint(out[pos..], "Stepped out.", .{}) catch return errResult(out, "Error");
    pos += hdr.len;
    appendStepContext(out, &pos);
    return .{ .text = out[0..pos] };
}

// ── PauseDebug ──────────────────────────────────────────────────────
fn pauseDebug(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (!bridge.isRunning()) return result(out, "Target is already paused.");
    _ = bridge.cmdExec("pause");
    Sleep(200);
    return result(out, if (!bridge.isRunning()) "Success: Target paused." else "Pause command sent, target may still be running.");
}

// ── StopDebug ───────────────────────────────────────────────────────
fn stopDebug(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    _ = bridge.cmdExec("stop");
    Sleep(500);
    return result(out, if (!bridge.isDebugging()) "Debug session terminated." else "Stop command sent.");
}

// ── RestartDebug ────────────────────────────────────────────────────
fn restartDebug(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging())
        return errResult(out, "Error: No active debug session.");

    var path_buf: [1024]u8 = undefined;
    const path_len = main.copyCurrentDebuggeePath(&path_buf);
    if (path_len == 0)
        return errResult(out, "Error: Current debuggee path is unknown.");
    const path = path_buf[0..path_len];

    const old_pid = bridge.valFromString("$pid");

    var cmd_buf: [1024]u8 = undefined;
    const cmd = std.fmt.bufPrint(
        &cmd_buf,
        "init \"{s}\"\x00",
        .{path},
    ) catch return errResult(out, "Error: debuggee path too long.");

    if (!bridge.cmdExec(@ptrCast(cmd.ptr)))
        return errResult(out, "Error: Failed to submit restart command.");

    // A successful restart must result in a different process ID.
    // Allow up to 5 seconds for the old debuggee to terminate and the
    // replacement process to reach its initial debug break.
    var waited: u32 = 0;
    while (waited < 5000) : (waited += 100) {
        Sleep(100);

        if (bridge.isDebugging()) {
            const new_pid = bridge.valFromString("$pid");
            if (new_pid != 0 and new_pid != old_pid) {
                return fmtResult(
                    out,
                    "Debug session restarted successfully. PID {d} -> {d}.",
                    .{ old_pid, new_pid },
                );
            }
        }
    }

    if (!bridge.isDebugging())
        return errResult(
            out,
            "Error: Restart command was submitted, but no new debug session became active.",
        );

    const current_pid = bridge.valFromString("$pid");
    return fmtErr(
        out,
        "Error: Restart command was submitted, but PID did not change (still {d}).",
        .{current_pid},
    );
}

// ── SetBreakpoint ───────────────────────────────────────────────────
fn setBreakpoint(params: ?std.json.Value, out: []u8) ToolResult {
    var target_buf: [32]u8 = undefined;
    const target = getParamAddr(params, "target", &target_buf) orelse
        return errResult(out, "Error: target is required.");
    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "bp {s}\x00", .{target}) catch
        return errResult(out, "Error: target too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Breakpoint set." else "Failed to set breakpoint."});
}

// ── DeleteBreakpoint ────────────────────────────────────────────────
fn deleteBreakpoint(params: ?std.json.Value, out: []u8) ToolResult {
    var target_buf: [32]u8 = undefined;
    const target = getParamAddr(params, "target", &target_buf) orelse
        return errResult(out, "Error: target is required.");
    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "bc {s}\x00", .{target}) catch
        return errResult(out, "Error: target too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Breakpoint deleted." else "Failed to delete breakpoint."});
}

// ── GetAllRegisters ─────────────────────────────────────────────────
fn getAllRegisters(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");

    const regs_64 = [_][]const u8{ "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "rflags" };
    const regs_32 = [_][]const u8{ "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags" };
    const is64 = @sizeOf(usize) == 8;
    const regs: []const []const u8 = if (is64) &regs_64 else &regs_32;

    var pos: usize = 0;
    for (regs) |reg| {
        var expr_buf: [32]u8 = undefined;
        const expr = std.fmt.bufPrint(&expr_buf, "{s}\x00", .{reg}) catch continue;
        const val = bridge.valFromString(@ptrCast(expr.ptr));
        const line = std.fmt.bufPrint(out[pos..], "{s}: 0x{X}\n", .{ reg, val }) catch break;
        pos += line.len;
    }
    if (pos == 0) return errResult(out, "Failed to read registers.");
    return .{ .text = out[0..pos] };
}

// ── GetCallStack ────────────────────────────────────────────────────
fn getCallStack(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");

    const is64 = @sizeOf(usize) == 8;
    const cip = bridge.valFromString("cip");
    var bp = bridge.valFromString(if (is64) "rbp" else "ebp");
    const ptr_size: usize = if (is64) 8 else 4;

    var pos: usize = 0;

    // Frame 0: current location
    pos += fmtFrame(out[pos..], 0, cip);

    // Walk frame pointer chain
    var frame: usize = 1;
    while (frame < 50) : (frame += 1) {
        if (bp < 0x10000) break;
        var buf: [8]u8 = undefined;
        if (!bridge.memRead(bp + ptr_size, buf[0..ptr_size])) break;
        const ret_addr = readPtrLE(buf[0..ptr_size]);
        if (ret_addr == 0 or ret_addr < 0x10000) break;

        pos += fmtFrame(out[pos..], frame, ret_addr);

        if (!bridge.memRead(bp, buf[0..ptr_size])) break;
        const saved_bp = readPtrLE(buf[0..ptr_size]);
        if (saved_bp <= bp) break;
        bp = saved_bp;
    }

    if (pos == 0) return errResult(out, "Error: Could not walk call stack.");
    return .{ .text = out[0..pos] };
}

fn fmtFrame(out: []u8, frame: usize, addr: usize) usize {
    var mod_buf: [bridge.MAX_MODULE_SIZE]u8 = undefined;
    const has_mod = bridge.getModuleAt(addr, &mod_buf);
    const mod = if (has_mod) bridge.cstrSlice(&mod_buf) else "";
    var lbl_buf: [bridge.MAX_LABEL_SIZE]u8 = undefined;
    const has_lbl = bridge.getLabelAt(addr, &lbl_buf);
    const lbl = if (has_lbl) bridge.cstrSlice(&lbl_buf) else "";

    if (lbl.len > 0) {
        const s = std.fmt.bufPrint(out, "#{d}  0x{X} {s}.{s}\n", .{ frame, addr, mod, lbl }) catch return 0;
        return s.len;
    } else if (mod.len > 0) {
        const s = std.fmt.bufPrint(out, "#{d}  0x{X} {s}\n", .{ frame, addr, mod }) catch return 0;
        return s.len;
    } else {
        const s = std.fmt.bufPrint(out, "#{d}  0x{X}\n", .{ frame, addr }) catch return 0;
        return s.len;
    }
}

// ── WriteMemToAddress ───────────────────────────────────────────────
fn writeMemToAddress(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");

    var addr_buf: [32]u8 = undefined;
    const addr_str = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    const byte_str = getParamStr(params, "byteString") orelse
        return errResult(out, "Error: byteString is required.");

    var expr_buf: [256]u8 = undefined;
    const expr = std.fmt.bufPrint(&expr_buf, "{s}\x00", .{addr_str}) catch
        return errResult(out, "Error: address too long.");
    const addr = bridge.valFromString(@ptrCast(expr.ptr));
    if (addr == 0) return fmtErr(out, "Error: Could not resolve address '{s}'.", .{addr_str});

    // Parse hex bytes
    var bytes: [512]u8 = undefined;
    var byte_count: usize = 0;
    var it = std.mem.tokenizeAny(u8, byte_str, " ,");
    while (it.next()) |tok| {
        if (byte_count >= bytes.len) break;
        bytes[byte_count] = std.fmt.parseInt(u8, tok, 16) catch
            return fmtErr(out, "Error: Invalid hex byte '{s}'.", .{tok});
        byte_count += 1;
    }

    if (byte_count == 0) return errResult(out, "Error: No bytes to write.");

    if (!bridge.memWrite(addr, bytes[0..byte_count])) {
        return fmtErr(out, "Error: Failed to write {d} bytes at 0x{X}.", .{ byte_count, addr });
    }
    return fmtResult(out, "Success: Wrote {d} bytes to 0x{X}.", .{ byte_count, addr });
}

// ── CommentOrLabelAtAddress ─────────────────────────────────────────
fn commentOrLabelAtAddress(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");

    var addr_buf: [32]u8 = undefined;
    const addr_str = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    const value = getParamStr(params, "value") orelse
        return errResult(out, "Error: value is required.");
    const mode = getParamStr(params, "mode") orelse "Comment";

    var expr_buf: [256]u8 = undefined;
    const expr = std.fmt.bufPrint(&expr_buf, "{s}\x00", .{addr_str}) catch
        return errResult(out, "Error: address too long.");
    const addr = bridge.valFromString(@ptrCast(expr.ptr));
    if (addr == 0) return fmtErr(out, "Error: Could not resolve address '{s}'.", .{addr_str});

    var val_buf: [512]u8 = undefined;
    const val_z = std.fmt.bufPrint(&val_buf, "{s}\x00", .{value}) catch
        return errResult(out, "Error: value too long.");

    if (std.mem.eql(u8, mode, "Label")) {
        const ok = bridge.DbgSetLabelAt(addr, @ptrCast(val_z.ptr)) != 0;
        return fmtResult(out, "{s}", .{if (ok) "Label set." else "Failed to set label."});
    } else {
        const ok = bridge.DbgSetCommentAt(addr, @ptrCast(val_z.ptr)) != 0;
        return fmtResult(out, "{s}", .{if (ok) "Comment set." else "Failed to set comment."});
    }
}

// ── Disassemble ────────────────────────────────────────────────────
fn disassemble(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");

    var addr_buf: [32]u8 = undefined;
    const addr_str = getParamAddr(params, "address", &addr_buf) orelse "cip";
    var count: usize = 10;
    if (getParamInt(params, "count")) |c| {
        count = @intCast(@min(@max(c, 1), 100));
    }

    var expr_buf: [256]u8 = undefined;
    const expr = std.fmt.bufPrint(&expr_buf, "{s}\x00", .{addr_str}) catch
        return errResult(out, "Error: address too long.");
    var addr = bridge.valFromString(@ptrCast(expr.ptr));
    if (addr == 0 and !std.mem.eql(u8, addr_str, "0"))
        return fmtErr(out, "Error: Could not resolve '{s}'.", .{addr_str});

    var pos: usize = 0;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        var next_expr_buf: [64]u8 = undefined;
        const next_expr = std.fmt.bufPrint(&next_expr_buf, "dis.next(0x{X})\x00", .{addr}) catch break;
        const next_addr = bridge.valFromString(@ptrCast(next_expr.ptr));
        if (next_addr == 0 or next_addr == addr) break;

        const inst_len = next_addr - addr;
        const read_len = @min(inst_len, 16);

        var bytes: [16]u8 = undefined;
        var hex_buf: [48]u8 = undefined;
        var bpos: usize = 0;
        if (bridge.memRead(addr, bytes[0..read_len])) {
            for (0..read_len) |j| {
                const h = std.fmt.bufPrint(hex_buf[bpos..], "{X:0>2} ", .{bytes[j]}) catch break;
                bpos += h.len;
            }
        }

        var text_buf: [256]u8 = std.mem.zeroes([256]u8);
        var instr_text: []const u8 = "";
        if (bridge.disasmTextAt(addr, &text_buf)) {
            instr_text = bridge.cstrSlice(&text_buf);
        }

        if (instr_text.len > 0) {
            const line = std.fmt.bufPrint(out[pos..], "0x{X}: {s}| {s}\n", .{ addr, hex_buf[0..bpos], instr_text }) catch break;
            pos += line.len;
        } else {
            const line = std.fmt.bufPrint(out[pos..], "0x{X}: {s}\n", .{ addr, hex_buf[0..bpos] }) catch break;
            pos += line.len;
        }
        addr = next_addr;
    }
    if (pos == 0) return errResult(out, "Error: Failed to disassemble.");
    return .{ .text = out[0..pos] };
}

// ── ListModules ────────────────────────────────────────────────────
fn listModules(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    const f = bridge.DbgMemMap orelse return errResult(out, "Error: Memory map not available.");

    var memmap: bridge.MEMMAP = undefined;
    if ((@as(u32, @bitCast(f(&memmap))) & 0xFF) == 0) return errResult(out, "Error: Failed to get memory map.");
    defer {
        if (memmap.count > 0) {
            if (bridge.BridgeFree) |free| free(@ptrCast(memmap.page));
        }
    }

    var pos: usize = 0;
    var last_base: bridge.duint = 0;
    const count: usize = @intCast(memmap.count);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const page = &memmap.page[i];
        const mod_name = bridge.cstrSlice(&page.info);
        if (mod_name.len == 0) continue;
        if (!isModulePath(mod_name)) continue;
        if (page.mbi_AllocationBase == last_base) continue;
        last_base = page.mbi_AllocationBase;
        var total_size: bridge.duint = page.mbi_RegionSize;
        var j: usize = i + 1;
        while (j < count) : (j += 1) {
            if (memmap.page[j].mbi_AllocationBase == last_base) {
                total_size += memmap.page[j].mbi_RegionSize;
            } else break;
        }
        const line = std.fmt.bufPrint(out[pos..], "0x{X} | 0x{X} | {s}\n", .{ last_base, total_size, mod_name }) catch break;
        pos += line.len;
    }
    if (pos == 0) return result(out, "No modules loaded.");
    return .{ .text = out[0..pos] };
}

// ── ListBreakpoints ────────────────────────────────────────────────
fn listBreakpoints(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    const f = bridge.DbgGetBpList orelse return errResult(out, "Error: Breakpoint list not available.");

    var pos: usize = 0;
    formatBps(f, 1, "Normal", out, &pos);
    formatBps(f, 2, "Hardware", out, &pos);
    formatBps(f, 4, "Memory", out, &pos);
    if (pos == 0) return result(out, "No breakpoints set.");
    return .{ .text = out[0..pos] };
}

fn formatBps(f: anytype, bptype: c_int, type_name: []const u8, out: []u8, pos: *usize) void {
    var bpmap: bridge.BPMAP = undefined;
    if (f(bptype, &bpmap) != 0 and bpmap.count > 0) {
        defer if (bridge.BridgeFree) |free| free(@ptrCast(bpmap.bp));
        const count: usize = @intCast(bpmap.count);
        var i: usize = 0;
        while (i < count) : (i += 1) {
            const bp = &bpmap.bp[i];
            const bp_name = bridge.cstrSlice(&bp.name);
            const bp_mod = bridge.cstrSlice(&bp.mod);
            const enabled: []const u8 = if (bp.enabled != 0) "enabled" else "disabled";
            const line = std.fmt.bufPrint(out[pos.*..], "[{s}] 0x{X} {s}!{s} ({s})\n", .{ type_name, bp.addr, bp_mod, bp_name, enabled }) catch return;
            pos.* += line.len;
        }
    }
}

// ── GetMemoryMap ───────────────────────────────────────────────────
fn getMemoryMap(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    const f = bridge.DbgMemMap orelse return errResult(out, "Error: Memory map not available.");

    var memmap: bridge.MEMMAP = undefined;
    if (f(&memmap) == 0) return errResult(out, "Error: Failed to get memory map.");
    defer {
        if (memmap.count > 0) {
            if (bridge.BridgeFree) |free| free(@ptrCast(memmap.page));
        }
    }

    var pos: usize = 0;
    const count: usize = @intCast(memmap.count);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const page = &memmap.page[i];
        const mod_name = bridge.cstrSlice(&page.info);
        const prot = protectStr(page.mbi_Protect);
        if (mod_name.len > 0) {
            const line = std.fmt.bufPrint(out[pos..], "0x{X} | 0x{X} | {s} | {s}\n", .{ page.mbi_BaseAddress, page.mbi_RegionSize, prot, mod_name }) catch break;
            pos += line.len;
        } else {
            const line = std.fmt.bufPrint(out[pos..], "0x{X} | 0x{X} | {s}\n", .{ page.mbi_BaseAddress, page.mbi_RegionSize, prot }) catch break;
            pos += line.len;
        }
    }
    if (pos == 0) return result(out, "No memory regions.");
    return .{ .text = out[0..pos] };
}

fn protectStr(protect: u32) []const u8 {
    return switch (protect & 0xFF) {
        0x02 => "R--",
        0x04 => "RW-",
        0x08 => "RC-",
        0x10 => "--X",
        0x20 => "R-X",
        0x40 => "RWX",
        0x80 => "RCX",
        else => "---",
    };
}

// ── EvalExpression ─────────────────────────────────────────────────
fn evalExpression(params: ?std.json.Value, out: []u8) ToolResult {
    const expr_str = getParamStr(params, "expression") orelse
        return errResult(out, "Error: expression is required.");
    var expr_buf: [256]u8 = undefined;
    const expr = std.fmt.bufPrint(&expr_buf, "{s}\x00", .{expr_str}) catch
        return errResult(out, "Error: expression too long.");
    const val = bridge.valFromString(@ptrCast(expr.ptr));
    return fmtResult(out, "0x{X} ({d})", .{ val, val });
}

// ── SetRegister ────────────────────────────────────────────────────
fn setRegister(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    const reg = getParamStr(params, "register") orelse
        return errResult(out, "Error: register is required.");
    const val = getParamStr(params, "value") orelse
        return errResult(out, "Error: value is required.");
    var cmd_buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "mov {s}, {s}\x00", .{ reg, val }) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Register set." else "Failed to set register."});
}

// ── GetThreads ─────────────────────────────────────────────────────
fn getThreads(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");

    const f = bridge.DbgGetThreadList orelse {
        const tid = bridge.valFromString("tid()");
        const cip = bridge.valFromString("cip");
        return fmtResult(out, "TID={d} CIP=0x{X} <-- current\n", .{ tid, cip });
    };

    var threadlist: bridge.THREADLIST = undefined;
    f(&threadlist);
    if (threadlist.count <= 0) {
        const tid = bridge.valFromString("tid()");
        const cip = bridge.valFromString("cip");
        return fmtResult(out, "TID={d} CIP=0x{X} <-- current\n", .{ tid, cip });
    }
    defer if (bridge.BridgeFree) |free| free(@ptrCast(threadlist.list));

    var pos: usize = 0;
    const count: usize = @intCast(threadlist.count);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const t = &threadlist.list[i];
        const name = bridge.cstrSlice(&t.BasicInfo.threadName);
        var is_current = false;
        if (threadlist.CurrentThread >= 0) {
            is_current = (@as(usize, @intCast(threadlist.CurrentThread)) == i);
        }
        const cur: []const u8 = if (is_current) " <-- current" else "";
        if (name.len > 0) {
            const line = std.fmt.bufPrint(out[pos..], "#{d} TID={d} CIP=0x{X} \"{s}\"{s}\n", .{ t.BasicInfo.ThreadNumber, t.BasicInfo.ThreadId, t.Cip, name, cur }) catch break;
            pos += line.len;
        } else {
            const line = std.fmt.bufPrint(out[pos..], "#{d} TID={d} CIP=0x{X}{s}\n", .{ t.BasicInfo.ThreadNumber, t.BasicInfo.ThreadId, t.Cip, cur }) catch break;
            pos += line.len;
        }
    }
    if (pos == 0) return result(out, "No threads.");
    return .{ .text = out[0..pos] };
}

// ── SwitchThread ───────────────────────────────────────────────────
fn switchThread(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    const tid = getParamInt(params, "threadId") orelse
        return errResult(out, "Error: threadId is required.");
    var cmd_buf: [64]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "switchthread .{d}\x00", .{tid}) catch
        return errResult(out, "Error: invalid threadId.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Thread switched." else "Failed to switch thread."});
}

// ── AttachProcess ──────────────────────────────────────────────────
fn attachProcess(params: ?std.json.Value, out: []u8) ToolResult {
    const pid = getParamInt(params, "pid") orelse
        return errResult(out, "Error: pid is required.");
    var cmd_buf: [64]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "attach .{d}\x00", .{pid}) catch
        return errResult(out, "Error: invalid pid.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    Sleep(500);
    return fmtResult(out, "{s}", .{if (ok) "Attach command sent." else "Failed to attach."});
}

// ── Assemble ───────────────────────────────────────────────────────
fn assemble(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    var addr_buf: [32]u8 = undefined;
    const addr_str = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    const instr = getParamStr(params, "instruction") orelse
        return errResult(out, "Error: instruction is required.");
    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "asm {s}, {s}\x00", .{ addr_str, instr }) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Assembled successfully." else "Assembly failed."});
}

// ── GetImports ─────────────────────────────────────────────────────
fn getImports(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    const module = getParamStr(params, "module") orelse
        return errResult(out, "Error: module is required.");

    const base = resolveModBase(module);
    if (base == 0) return fmtErr(out, "Error: Module '{s}' not found.", .{module});

    const imp = peGetDataDir(base, 1) orelse
        return errResult(out, "Error: Could not read PE headers.");
    if (imp.rva == 0) return result(out, "No imports.");

    const ptr_size: usize = if (@sizeOf(usize) == 8) 8 else 4;
    const ord_flag: usize = @as(usize, 1) << (@as(u6, @intCast(ptr_size * 8 - 1)));
    var pos: usize = 0;
    var desc_addr = base + imp.rva;

    while (true) {
        var desc: [20]u8 = undefined;
        if (!bridge.memRead(desc_addr, &desc)) break;
        const name_rva = readU32LE(desc[12..16]);
        if (name_rva == 0) break;

        var dll_name: [128]u8 = undefined;
        if (!bridge.memRead(base + name_rva, &dll_name)) break;
        const dll = bridge.cstrSlice(&dll_name);
        const hdr = std.fmt.bufPrint(out[pos..], "\n[{s}]\n", .{dll}) catch break;
        pos += hdr.len;

        const oft_rva = readU32LE(desc[0..4]);
        const ft_rva = readU32LE(desc[16..20]);
        const thunk_rva = if (oft_rva != 0) oft_rva else ft_rva;
        var thunk_addr = base + thunk_rva;
        var iat_addr = base + ft_rva;

        var fn_count: usize = 0;
        while (fn_count < 500) : (fn_count += 1) {
            var tb: [8]u8 = undefined;
            if (!bridge.memRead(thunk_addr, tb[0..ptr_size])) break;
            const tv = readPtrLE(tb[0..ptr_size]);
            if (tv == 0) break;

            var ib: [8]u8 = undefined;
            var resolved: usize = 0;
            if (bridge.memRead(iat_addr, ib[0..ptr_size])) {
                resolved = readPtrLE(ib[0..ptr_size]);
            }

            if ((tv & ord_flag) != 0) {
                const line = std.fmt.bufPrint(out[pos..], "  #{d} -> 0x{X}\n", .{ tv & 0xFFFF, resolved }) catch break;
                pos += line.len;
            } else {
                var fname: [128]u8 = undefined;
                if (bridge.memRead(base + @as(usize, @intCast(tv & 0x7FFFFFFF)) + 2, &fname)) {
                    const name = bridge.cstrSlice(&fname);
                    const line = std.fmt.bufPrint(out[pos..], "  {s} -> 0x{X}\n", .{ name, resolved }) catch break;
                    pos += line.len;
                }
            }
            thunk_addr += ptr_size;
            iat_addr += ptr_size;
        }
        desc_addr += 20;
    }
    if (pos == 0) return result(out, "No imports found.");
    return .{ .text = out[0..pos] };
}

// ── GetExports ─────────────────────────────────────────────────────
fn getExports(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    const module = getParamStr(params, "module") orelse
        return errResult(out, "Error: module is required.");

    const base = resolveModBase(module);
    if (base == 0) return fmtErr(out, "Error: Module '{s}' not found.", .{module});

    const exp = peGetDataDir(base, 0) orelse
        return errResult(out, "Error: Could not read PE headers.");
    if (exp.rva == 0) return result(out, "No exports.");

    var ed: [40]u8 = undefined;
    if (!bridge.memRead(base + exp.rva, &ed))
        return errResult(out, "Error: Could not read export directory.");

    const num_names = readU32LE(ed[24..28]);
    const addr_funcs = readU32LE(ed[28..32]);
    const addr_names = readU32LE(ed[32..36]);
    const addr_ords = readU32LE(ed[36..40]);
    const ord_base = readU32LE(ed[16..20]);

    var pos: usize = 0;
    const hdr = std.fmt.bufPrint(out[pos..], "{d} named exports:\n", .{num_names}) catch return result(out[0..0], "");
    pos += hdr.len;

    const limit = @min(num_names, 1000);
    var i: u32 = 0;
    while (i < limit) : (i += 1) {
        var nrb: [4]u8 = undefined;
        if (!bridge.memRead(base + addr_names + i * 4, &nrb)) break;
        var ob: [2]u8 = undefined;
        if (!bridge.memRead(base + addr_ords + i * 2, &ob)) break;
        const ordinal = readU16LE(&ob);
        var frb: [4]u8 = undefined;
        if (!bridge.memRead(base + addr_funcs + @as(u32, ordinal) * 4, &frb)) break;
        const func_rva = readU32LE(&frb);

        var nbuf: [128]u8 = undefined;
        if (!bridge.memRead(base + readU32LE(&nrb), &nbuf)) break;
        const name = bridge.cstrSlice(&nbuf);

        const line = std.fmt.bufPrint(out[pos..], "  #{d} 0x{X} {s}\n", .{ @as(u32, ordinal) + ord_base, base + func_rva, name }) catch break;
        pos += line.len;
    }
    if (pos == 0) return result(out, "No exports found.");
    return .{ .text = out[0..pos] };
}

// ── SetHardwareBreakpoint ──────────────────────────────────────────
fn setHardwareBreakpoint(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    var addr_buf: [32]u8 = undefined;
    const addr_str = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    const bp_type = getParamStr(params, "type") orelse "x";
    const size = getParamInt(params, "size") orelse 1;
    var cmd_buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "bphws {s}, {s}, {d}\x00", .{ addr_str, bp_type, size }) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Hardware breakpoint set." else "Failed to set hardware breakpoint."});
}

// ── SetMemoryBreakpoint ────────────────────────────────────────────
fn setMemoryBreakpoint(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    var addr_buf: [32]u8 = undefined;
    const addr_str = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    const bp_type = getParamStr(params, "type") orelse "";
    const singleshoot = getParamBool(params, "singleshoot") orelse false;

    var cmd_buf: [256]u8 = undefined;
    const cmd = if (bp_type.len > 0)
        std.fmt.bufPrint(&cmd_buf, "bpm {s}, 0, {s}\x00", .{ addr_str, bp_type }) catch
            return errResult(out, "Error: input too long.")
    else
        std.fmt.bufPrint(&cmd_buf, "bpm {s}\x00", .{addr_str}) catch
            return errResult(out, "Error: input too long.");

    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    if (ok and singleshoot) {
        var ss_buf: [256]u8 = undefined;
        const ss_cmd = std.fmt.bufPrint(&ss_buf, "SetBreakpointSingleshoot {s}\x00", .{addr_str}) catch "";
        if (ss_cmd.len > 0) _ = bridge.cmdExec(@ptrCast(ss_cmd.ptr));
    }
    return fmtResult(out, "{s}", .{if (ok) "Memory breakpoint set." else "Failed to set memory breakpoint."});
}

// ── GetPatches ─────────────────────────────────────────────────────
fn getPatches(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    const ok = bridge.cmdExec("patchlist\x00");
    return fmtResult(out, "{s}", .{if (ok) "Patch list displayed in x64dbg Patches window." else "Command failed."});
}

// ── Helpers (new tools) ───────────────────────────────────────────

fn getModSize(base: usize) usize {
    var buf4: [4]u8 = undefined;
    if (!bridge.memRead(base + 0x3C, &buf4)) return 0;
    const pe_off: usize = readU32LE(&buf4);
    if (!bridge.memRead(base + pe_off + 80, &buf4)) return 0;
    return readU32LE(&buf4);
}

const CodeSection = struct { start: usize, size: usize };
fn getCodeSection(base: usize) CodeSection {
    var buf4: [4]u8 = undefined;
    var buf2: [2]u8 = undefined;
    if (!bridge.memRead(base + 0x3C, &buf4)) return .{ .start = base, .size = 0 };
    const pe_off: usize = readU32LE(&buf4);
    if (!bridge.memRead(base + pe_off + 6, &buf2)) return .{ .start = base, .size = 0 };
    const num_sec = readU16LE(&buf2);
    if (!bridge.memRead(base + pe_off + 20, &buf2)) return .{ .start = base, .size = 0 };
    const opt_sz: usize = readU16LE(&buf2);
    const first_sec = base + pe_off + 24 + opt_sz;
    var i: usize = 0;
    while (i < num_sec and i < 64) : (i += 1) {
        var sec: [40]u8 = undefined;
        if (!bridge.memRead(first_sec + i * 40, &sec)) break;
        const chars = readU32LE(sec[36..40]);
        if (chars & 0x20000000 != 0) {
            return .{ .start = base + @as(usize, readU32LE(sec[12..16])), .size = readU32LE(sec[8..12]) };
        }
    }
    return .{ .start = base, .size = 0 };
}

fn resolveAddr(addr_str: []const u8) usize {
    var buf: [256]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{s}\x00", .{addr_str}) catch return 0;
    return bridge.valFromString(@ptrCast(&buf));
}

// ── FindPattern ───────────────────────────────────────────────────
fn findPattern(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    const pattern_str = getParamStr(params, "pattern") orelse
        return errResult(out, "Error: pattern is required.");

    var pat: [256]u8 = undefined;
    var mask: [256]u8 = undefined;
    var pat_len: usize = 0;
    var it = std.mem.tokenizeAny(u8, pattern_str, " ");
    while (it.next()) |tok| {
        if (pat_len >= 256) break;
        if (tok[0] == '?') {
            pat[pat_len] = 0;
            mask[pat_len] = 0;
        } else {
            pat[pat_len] = std.fmt.parseInt(u8, tok, 16) catch
                return fmtErr(out, "Error: Invalid hex '{s}'.", .{tok});
            mask[pat_len] = 1;
        }
        pat_len += 1;
    }
    if (pat_len == 0) return errResult(out, "Error: Empty pattern.");

    var base: usize = 0;
    var scan_size: usize = 0;
    if (getParamStr(params, "module")) |mod| {
        base = resolveModBase(mod);
        if (base == 0) return fmtErr(out, "Error: Module '{s}' not found.", .{mod});
    } else {
        base = bridge.valFromString("mod.main()\x00");
        if (base == 0) {
            const cip = bridge.valFromString("cip\x00");
            if (cip != 0) {
                var mod_buf: [bridge.MAX_MODULE_SIZE]u8 = undefined;
                if (bridge.getModuleAt(cip, &mod_buf)) {
                    base = resolveModBase(bridge.cstrSlice(&mod_buf));
                }
            }
        }
    }
    if (base == 0) return errResult(out, "Error: No module to scan.");
    scan_size = getModSize(base);
    if (scan_size == 0) scan_size = 0x100000;

    var max_res: usize = 10;
    if (getParamInt(params, "maxResults")) |m| {
        max_res = @intCast(@min(@max(m, 1), 100));
    }

    var pos: usize = 0;
    var found: usize = 0;
    const CHUNK = 4096;
    var chunk: [CHUNK + 256]u8 = undefined;
    var addr = base;
    const end = base +| scan_size;

    while (addr < end and found < max_res) {
        const remain = end - addr;
        const rlen = @min(CHUNK + pat_len - 1, remain);
        if (!bridge.memRead(addr, chunk[0..rlen])) {
            addr +|= CHUNK;
            continue;
        }
        const search_end = if (rlen >= pat_len) rlen - pat_len + 1 else 0;
        var i: usize = 0;
        while (i < search_end) : (i += 1) {
            var ok = true;
            for (0..pat_len) |j| {
                if (mask[j] != 0 and chunk[i + j] != pat[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                const line = std.fmt.bufPrint(out[pos..], "0x{X}\n", .{addr + i}) catch break;
                pos += line.len;
                found += 1;
                if (found >= max_res) break;
            }
        }
        addr +|= CHUNK;
    }

    if (found == 0) return result(out, "No matches found.");
    const f = std.fmt.bufPrint(out[pos..], "{d} match(es).", .{found}) catch return .{ .text = out[0..pos] };
    pos += f.len;
    return .{ .text = out[0..pos] };
}

// ── GetStrings ────────────────────────────────────────────────────
fn getStrings(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");

    var base: usize = 0;
    if (getParamStr(params, "module")) |mod| {
        base = resolveModBase(mod);
        if (base == 0) return fmtErr(out, "Error: Module '{s}' not found.", .{mod});
    } else {
        base = bridge.valFromString("mod.main()\x00");
        if (base == 0) {
            const cip = bridge.valFromString("cip\x00");
            if (cip != 0) {
                var mod_buf: [bridge.MAX_MODULE_SIZE]u8 = undefined;
                if (bridge.getModuleAt(cip, &mod_buf))
                    base = resolveModBase(bridge.cstrSlice(&mod_buf));
            }
        }
    }
    if (base == 0) return errResult(out, "Error: No module to scan.");
    const size = getModSize(base);
    if (size == 0) return errResult(out, "Error: Could not determine module size.");

    var min_len: usize = 4;
    if (getParamInt(params, "minLength")) |m| {
        min_len = @intCast(@min(@max(m, 2), 64));
    }

    var pos: usize = 0;
    var found: usize = 0;
    const CHUNK = 4096;
    var chunk: [CHUNK]u8 = undefined;
    var addr = base;
    const end = base +| size;
    var str_start: usize = 0;
    var str_len: usize = 0;
    var in_string = false;

    while (addr < end and found < 500 and pos + 300 < out.len) {
        const rlen = @min(CHUNK, end - addr);
        if (!bridge.memRead(addr, chunk[0..rlen])) {
            in_string = false;
            str_len = 0;
            addr +|= CHUNK;
            continue;
        }

        for (0..rlen) |i| {
            const c = chunk[i];
            if (c >= 0x20 and c <= 0x7E) {
                if (!in_string) {
                    str_start = addr + i;
                    str_len = 0;
                    in_string = true;
                }
                str_len += 1;
            } else {
                if (in_string and c == 0 and str_len >= min_len) {
                    var sbuf: [256]u8 = undefined;
                    const slen = @min(str_len, 255);
                    if (bridge.memRead(str_start, sbuf[0..slen])) {
                        const line = std.fmt.bufPrint(out[pos..], "0x{X}: \"{s}\"\n", .{ str_start, sbuf[0..slen] }) catch break;
                        pos += line.len;
                        found += 1;
                    }
                }
                in_string = false;
                str_len = 0;
            }
        }
        addr +|= CHUNK;
    }

    if (found == 0) return result(out, "No strings found.");
    const f = std.fmt.bufPrint(out[pos..], "\n{d} string(s).", .{found}) catch return .{ .text = out[0..pos] };
    pos += f.len;
    return .{ .text = out[0..pos] };
}

// ── GetReferences ─────────────────────────────────────────────────
fn getReferences(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    var addr_buf: [32]u8 = undefined;
    const addr_str = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    const target = resolveAddr(addr_str);
    if (target == 0) return fmtErr(out, "Error: Could not resolve '{s}'.", .{addr_str});

    var base: usize = 0;
    if (getParamStr(params, "module")) |mod| {
        base = resolveModBase(mod);
    }
    if (base == 0) {
        base = bridge.valFromString("mod.main()\x00");
        if (base == 0) {
            var mod_buf: [bridge.MAX_MODULE_SIZE]u8 = undefined;
            if (bridge.getModuleAt(target, &mod_buf))
                base = resolveModBase(bridge.cstrSlice(&mod_buf));
        }
    }
    if (base == 0) return errResult(out, "Error: No module to scan.");
    const size = getModSize(base);
    if (size == 0) return errResult(out, "Error: Could not determine module size.");

    var pos: usize = 0;
    var found: usize = 0;
    const CHUNK = 4096;
    var chunk: [CHUNK + 4]u8 = undefined;
    var addr = base;
    const end_addr = base +| size;

    while (addr < end_addr and found < 200 and pos + 100 < out.len) {
        const remain = end_addr - addr;
        const rlen = @min(CHUNK + 4, remain);
        if (!bridge.memRead(addr, chunk[0..rlen])) {
            addr +|= CHUNK;
            continue;
        }
        if (rlen < 5) break;
        const scan_end = @min(rlen - 4, CHUNK);

        var i: usize = 0;
        while (i < scan_end) : (i += 1) {
            if (chunk[i] == 0xE8 or chunk[i] == 0xE9) {
                const offset: i32 = @bitCast(readU32LE(chunk[i + 1 .. i + 5]));
                const src = addr + i;
                const tgt_i64 = @as(i64, @intCast(src)) + 5 + @as(i64, offset);
                if (tgt_i64 >= 0) {
                    const tgt: usize = @intCast(tgt_i64);
                    if (tgt == target) {
                        const kind: []const u8 = if (chunk[i] == 0xE8) "CALL" else "JMP";
                        var lbl_buf: [bridge.MAX_LABEL_SIZE]u8 = undefined;
                        const has_lbl = bridge.getLabelAt(src, &lbl_buf);
                        const label = if (has_lbl) bridge.cstrSlice(&lbl_buf) else "";
                        if (label.len > 0) {
                            const line = std.fmt.bufPrint(out[pos..], "0x{X} {s} (in {s})\n", .{ src, kind, label }) catch break;
                            pos += line.len;
                        } else {
                            const line = std.fmt.bufPrint(out[pos..], "0x{X} {s}\n", .{ src, kind }) catch break;
                            pos += line.len;
                        }
                        found += 1;
                        if (found >= 200) break;
                    }
                }
            }
        }
        addr +|= CHUNK;
    }

    if (found == 0) return fmtResult(out, "No CALL/JMP references to 0x{X} found.", .{target});
    const f = std.fmt.bufPrint(out[pos..], "\n{d} reference(s) to 0x{X}.", .{ found, target }) catch return .{ .text = out[0..pos] };
    pos += f.len;
    return .{ .text = out[0..pos] };
}

// ── GetFunctions ──────────────────────────────────────────────────
fn getFunctions(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    const module = getParamStr(params, "module") orelse
        return errResult(out, "Error: module is required.");

    const base = resolveModBase(module);
    if (base == 0) return fmtErr(out, "Error: Module '{s}' not found.", .{module});

    // Find all executable sections in the PE
    var buf4: [4]u8 = undefined;
    var buf2: [2]u8 = undefined;
    if (!bridge.memRead(base + 0x3C, &buf4)) return errResult(out, "Error: Cannot read PE header.");
    const pe_off: usize = readU32LE(&buf4);

    // Get entry point
    var ep_addr: usize = 0;
    if (bridge.memRead(base + pe_off + 40, &buf4)) {
        const ep_rva = readU32LE(&buf4);
        if (ep_rva != 0) ep_addr = base + ep_rva;
    }

    // Collect executable sections
    if (!bridge.memRead(base + pe_off + 6, &buf2)) return errResult(out, "Error: Cannot read section count.");
    const num_sec = readU16LE(&buf2);
    if (!bridge.memRead(base + pe_off + 20, &buf2)) return errResult(out, "Error: Cannot read optional header size.");
    const opt_sz: usize = readU16LE(&buf2);
    const first_sec = base + pe_off + 24 + opt_sz;

    const ExeSec = struct { start: usize, size: usize };
    var sections: [32]ExeSec = undefined;
    var nsec: usize = 0;
    var si: usize = 0;
    while (si < num_sec and si < 32) : (si += 1) {
        var sec: [40]u8 = undefined;
        if (!bridge.memRead(first_sec + si * 40, &sec)) break;
        const chars = readU32LE(sec[36..40]);
        if (chars & 0x20000000 != 0) {
            sections[nsec] = .{
                .start = base + @as(usize, readU32LE(sec[12..16])),
                .size = readU32LE(sec[8..12]),
            };
            nsec += 1;
        }
    }
    if (nsec == 0) return errResult(out, "Error: No executable sections found.");

    // Scan executable sections for function prologues
    var pos: usize = 0;
    var count: usize = 0;
    const deadline = GetTickCount64() + 8000;
    const CHUNK = 4096;
    var chunk: [CHUNK]u8 = undefined;

    var sec_i: usize = 0;
    while (sec_i < nsec) : (sec_i += 1) {
        const sec_start = sections[sec_i].start;
        const sec_size = sections[sec_i].size;
        const sec_end = sec_start +| sec_size;
        var addr = sec_start;

        while (addr + CHUNK <= sec_end and count < 500 and pos + 100 < out.len) {
            if (GetTickCount64() > deadline) break;
            if (!bridge.memRead(addr, &chunk)) {
                addr += CHUNK;
                continue;
            }

            var j: usize = 0;
            while (j + 3 < CHUNK and count < 500 and pos + 100 < out.len) {
                // push ebp; mov ebp, esp (55 8B EC)
                const is_prologue = (chunk[j] == 0x55 and chunk[j + 1] == 0x8B and chunk[j + 2] == 0xEC) or
                    // mov edi,edi; push ebp; mov ebp,esp (8B FF 55 8B EC) — hotpatch
                    (j + 4 < CHUNK and chunk[j] == 0x8B and chunk[j + 1] == 0xFF and chunk[j + 2] == 0x55 and chunk[j + 3] == 0x8B and chunk[j + 4] == 0xEC);

                if (is_prologue) {
                    const func_addr = addr + j;
                    var lbl: [bridge.MAX_LABEL_SIZE]u8 = undefined;
                    const has_lbl = bridge.getLabelAt(func_addr, &lbl);
                    const label = if (has_lbl) bridge.cstrSlice(&lbl) else "";
                    if (label.len > 0) {
                        const line = std.fmt.bufPrint(out[pos..], "0x{X} | {s}\n", .{ func_addr, label }) catch break;
                        pos += line.len;
                    } else {
                        const line = std.fmt.bufPrint(out[pos..], "0x{X}\n", .{func_addr}) catch break;
                        pos += line.len;
                    }
                    count += 1;
                    j += 3;
                } else {
                    j += 1;
                }
            }
            addr += CHUNK;
        }
        if (GetTickCount64() > deadline) break;
    }

    // Append EP if not already found
    if (ep_addr != 0) {
        var found_ep = false;
        const ep_str_len = std.fmt.count("0x{X}", .{ep_addr});
        var search_pos: usize = 0;
        while (search_pos + ep_str_len <= pos) : (search_pos += 1) {
            var match_buf: [20]u8 = undefined;
            const ep_str = std.fmt.bufPrint(&match_buf, "0x{X}", .{ep_addr}) catch break;
            if (std.mem.startsWith(u8, out[search_pos..], ep_str)) {
                found_ep = true;
                break;
            }
        }
        if (!found_ep and count < 500 and pos + 100 < out.len) {
            var lbl: [bridge.MAX_LABEL_SIZE]u8 = undefined;
            const has_lbl = bridge.getLabelAt(ep_addr, &lbl);
            const label = if (has_lbl) bridge.cstrSlice(&lbl) else "EntryPoint";
            const line = std.fmt.bufPrint(out[pos..], "0x{X} | {s}\n", .{ ep_addr, label }) catch
                return .{ .text = out[0..pos] };
            pos += line.len;
            count += 1;
        }
    }

    if (count == 0) return result(out, "No functions found in executable sections.");
    const f = std.fmt.bufPrint(out[pos..], "\n{d} function(s) found.", .{count}) catch return .{ .text = out[0..pos] };
    pos += f.len;
    return .{ .text = out[0..pos] };
}

// ── RunToAddress ──────────────────────────────────────────────────
fn runToAddress(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    var addr_buf: [32]u8 = undefined;
    const addr_str = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");

    var cmd_buf: [512]u8 = undefined;
    const cmd1 = std.fmt.bufPrint(&cmd_buf, "bp {s}\x00", .{addr_str}) catch
        return errResult(out, "Error: address too long.");
    _ = bridge.cmdExec(@ptrCast(cmd1.ptr));
    _ = bridge.cmdExec("run\x00");

    var timeout: i64 = 30000;
    if (getParamInt(params, "timeoutMs")) |t| {
        timeout = @min(@max(t, 100), 120000);
    }

    const start_tick = @as(i64, @intCast(GetTickCount64()));
    while (@as(i64, @intCast(GetTickCount64())) - start_tick < timeout) {
        if (!bridge.isDebugging()) {
            const cmd_del = std.fmt.bufPrint(&cmd_buf, "bc {s}\x00", .{addr_str}) catch break;
            _ = bridge.cmdExec(@ptrCast(cmd_del.ptr));
            return result(out, "Target exited.");
        }
        if (!bridge.isRunning()) {
            const cip = bridge.valFromString("cip\x00");
            const cmd_del = std.fmt.bufPrint(&cmd_buf, "bc {s}\x00", .{addr_str}) catch break;
            _ = bridge.cmdExec(@ptrCast(cmd_del.ptr));
            return fmtResult(out, "Paused at 0x{X}.", .{cip});
        }
        Sleep(50);
    }
    const cmd_del = std.fmt.bufPrint(&cmd_buf, "bc {s}\x00", .{addr_str}) catch
        return errResult(out, "Timeout. Breakpoint may still be set.");
    _ = bridge.cmdExec(@ptrCast(cmd_del.ptr));
    return fmtResult(out, "Timeout after {d}ms. Target still running.", .{timeout});
}

// ── TraceInto ─────────────────────────────────────────────────────
fn traceInto(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");

    var count: usize = 10;
    if (getParamInt(params, "count")) |c| {
        count = @intCast(@min(@max(c, 1), 100));
    }

    var pos: usize = 0;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const cip = bridge.valFromString("cip\x00");
        var text_buf: [256]u8 = std.mem.zeroes([256]u8);
        var instr: []const u8 = "";
        if (bridge.disasmTextAt(cip, &text_buf)) {
            instr = bridge.cstrSlice(&text_buf);
        }
        const line = std.fmt.bufPrint(out[pos..], "0x{X}: {s}\n", .{ cip, instr }) catch break;
        pos += line.len;
        _ = bridge.cmdExec("sti\x00");
        Sleep(10);
        var wait: usize = 0;
        while (bridge.isRunning() and wait < 200) : (wait += 1) Sleep(5);
    }

    if (pos == 0) return errResult(out, "Error: Failed to trace.");
    return .{ .text = out[0..pos] };
}

// ── SetConditionalBreakpoint ──────────────────────────────────────
fn setConditionalBreakpoint(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    var addr_buf: [32]u8 = undefined;
    const addr_str = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    const condition = getParamStr(params, "condition") orelse
        return errResult(out, "Error: condition is required.");

    var cmd_buf: [512]u8 = undefined;
    const cmd_bp = std.fmt.bufPrint(&cmd_buf, "bp {s}\x00", .{addr_str}) catch
        return errResult(out, "Error: input too long.");
    if (!bridge.cmdExec(@ptrCast(cmd_bp.ptr)))
        return errResult(out, "Error: Failed to set breakpoint.");

    var cmd2_buf: [512]u8 = undefined;
    const cmd_cnd = std.fmt.bufPrint(&cmd2_buf, "bpcnd {s}, \"{s}\"\x00", .{ addr_str, condition }) catch
        return errResult(out, "Error: condition too long.");
    _ = bridge.cmdExec(@ptrCast(cmd_cnd.ptr));

    if (getParamStr(params, "log")) |log_text| {
        var cmd3_buf: [512]u8 = undefined;
        _ = std.fmt.bufPrint(&cmd3_buf, "bplog {s}, \"{s}\"\x00", .{ addr_str, log_text }) catch return fmtResult(out, "Breakpoint set, but log text too long.", .{});
        _ = bridge.cmdExec(@ptrCast(cmd3_buf[0..].ptr));
    }

    return fmtResult(out, "Conditional breakpoint set at {s} with condition: {s}", .{ addr_str, condition });
}

// ── FollowPointer ─────────────────────────────────────────────────
fn followPointer(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    var addr_buf: [32]u8 = undefined;
    const addr_str = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    var addr = resolveAddr(addr_str);
    if (addr == 0) return fmtErr(out, "Error: Could not resolve '{s}'.", .{addr_str});

    var depth: usize = 1;
    if (getParamInt(params, "depth")) |d| {
        depth = @intCast(@min(@max(d, 1), 16));
    }

    const ptr_size: usize = if (@sizeOf(usize) == 8) 8 else 4;
    var pos: usize = 0;
    const hdr = std.fmt.bufPrint(out[pos..], "[0] 0x{X}\n", .{addr}) catch return errResult(out, "Buffer overflow.");
    pos += hdr.len;

    var i: usize = 0;
    while (i < depth) : (i += 1) {
        var buf: [8]u8 = undefined;
        if (!bridge.memRead(addr, buf[0..ptr_size])) {
            const line = std.fmt.bufPrint(out[pos..], "[{d}] -> UNREADABLE\n", .{i + 1}) catch break;
            pos += line.len;
            break;
        }
        addr = readPtrLE(buf[0..ptr_size]);
        if (addr == 0) {
            const line = std.fmt.bufPrint(out[pos..], "[{d}] -> NULL\n", .{i + 1}) catch break;
            pos += line.len;
            break;
        }
        var mod_buf: [bridge.MAX_MODULE_SIZE]u8 = undefined;
        const has_mod = bridge.getModuleAt(addr, &mod_buf);
        const mod_name = if (has_mod) bridge.cstrSlice(&mod_buf) else "";
        if (mod_name.len > 0) {
            const line = std.fmt.bufPrint(out[pos..], "[{d}] -> 0x{X} ({s})\n", .{ i + 1, addr, mod_name }) catch break;
            pos += line.len;
        } else {
            const line = std.fmt.bufPrint(out[pos..], "[{d}] -> 0x{X}\n", .{ i + 1, addr }) catch break;
            pos += line.len;
        }
    }
    return .{ .text = out[0..pos] };
}

// ── WatchExpressions ──────────────────────────────────────────────
fn watchExpressions(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    const exprs_str = getParamStr(params, "expressions") orelse
        return errResult(out, "Error: expressions is required.");

    var pos: usize = 0;
    var expr_it = std.mem.tokenizeAny(u8, exprs_str, ",");
    while (expr_it.next()) |expr_raw| {
        const trimmed = std.mem.trim(u8, expr_raw, " ");
        if (trimmed.len == 0) continue;
        var expr_buf: [256]u8 = undefined;
        _ = std.fmt.bufPrint(&expr_buf, "{s}\x00", .{trimmed}) catch continue;
        const val = bridge.valFromString(@ptrCast(&expr_buf));
        const line = std.fmt.bufPrint(out[pos..], "{s} = 0x{X} ({d})\n", .{ trimmed, val, val }) catch break;
        pos += line.len;
    }
    if (pos == 0) return errResult(out, "Error: No valid expressions.");
    return .{ .text = out[0..pos] };
}

// ── GetSEHChain ───────────────────────────────────────────────────
fn getSEHChain(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    if (@sizeOf(usize) == 8) return errResult(out, "Error: SEH chain walking is x32 only. Use GetExceptions on x64.");

    const teb = bridge.valFromString("teb()\x00");
    if (teb == 0) return errResult(out, "Error: Could not get TEB address.");
    var teb_buf: [4]u8 = undefined;
    if (!bridge.memRead(teb, &teb_buf)) return errResult(out, "Error: Could not read TEB.");
    var seh_ptr: usize = readU32LE(&teb_buf);

    var pos: usize = 0;
    var depth: usize = 0;
    while (depth < 64 and seh_ptr != 0 and seh_ptr != 0xFFFFFFFF) : (depth += 1) {
        var rec: [8]u8 = undefined;
        if (!bridge.memRead(seh_ptr, &rec)) break;
        const next = readU32LE(rec[0..4]);
        const handler = readU32LE(rec[4..8]);

        var mod_buf: [bridge.MAX_MODULE_SIZE]u8 = undefined;
        const has_mod = bridge.getModuleAt(handler, &mod_buf);
        const mod_name = if (has_mod) bridge.cstrSlice(&mod_buf) else "";
        var lbl_buf: [bridge.MAX_LABEL_SIZE]u8 = undefined;
        const has_lbl = bridge.getLabelAt(handler, &lbl_buf);
        const label = if (has_lbl) bridge.cstrSlice(&lbl_buf) else "";

        if (label.len > 0) {
            const line = std.fmt.bufPrint(out[pos..], "#{d} Frame=0x{X} Handler=0x{X} {s}.{s}\n", .{ depth, seh_ptr, handler, mod_name, label }) catch break;
            pos += line.len;
        } else if (mod_name.len > 0) {
            const line = std.fmt.bufPrint(out[pos..], "#{d} Frame=0x{X} Handler=0x{X} ({s})\n", .{ depth, seh_ptr, handler, mod_name }) catch break;
            pos += line.len;
        } else {
            const line = std.fmt.bufPrint(out[pos..], "#{d} Frame=0x{X} Handler=0x{X}\n", .{ depth, seh_ptr, handler }) catch break;
            pos += line.len;
        }
        seh_ptr = next;
    }

    if (pos == 0) return result(out, "No SEH chain found.");
    return .{ .text = out[0..pos] };
}

// ── GetPEB ────────────────────────────────────────────────────────
fn getPEB(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");

    const peb = bridge.valFromString("peb()\x00");
    if (peb == 0) return errResult(out, "Error: Could not get PEB address.");

    const is64 = @sizeOf(usize) == 8;
    const ptr_size: usize = if (is64) 8 else 4;
    var pos: usize = 0;

    const hdr = std.fmt.bufPrint(out[pos..], "PEB at 0x{X}\n", .{peb}) catch return errResult(out, "Buffer overflow.");
    pos += hdr.len;

    var byte1: [1]u8 = undefined;
    if (bridge.memRead(peb + 2, &byte1)) {
        const line = std.fmt.bufPrint(out[pos..], "BeingDebugged: {d}\n", .{byte1[0]}) catch return .{ .text = out[0..pos] };
        pos += line.len;
    }

    var ptr_buf: [8]u8 = undefined;
    const img_off: usize = if (is64) 0x10 else 0x08;
    if (bridge.memRead(peb + img_off, ptr_buf[0..ptr_size])) {
        const line = std.fmt.bufPrint(out[pos..], "ImageBase: 0x{X}\n", .{readPtrLE(ptr_buf[0..ptr_size])}) catch return .{ .text = out[0..pos] };
        pos += line.len;
    }

    const heap_off: usize = if (is64) 0x30 else 0x18;
    if (bridge.memRead(peb + heap_off, ptr_buf[0..ptr_size])) {
        const line = std.fmt.bufPrint(out[pos..], "ProcessHeap: 0x{X}\n", .{readPtrLE(ptr_buf[0..ptr_size])}) catch return .{ .text = out[0..pos] };
        pos += line.len;
    }

    var dw_buf: [4]u8 = undefined;
    const nproc_off: usize = if (is64) 0xB8 else 0x64;
    if (bridge.memRead(peb + nproc_off, &dw_buf)) {
        const line = std.fmt.bufPrint(out[pos..], "NumberOfProcessors: {d}\n", .{readU32LE(&dw_buf)}) catch return .{ .text = out[0..pos] };
        pos += line.len;
    }

    const gflag_off: usize = if (is64) 0xBC else 0x68;
    if (bridge.memRead(peb + gflag_off, &dw_buf)) {
        const line = std.fmt.bufPrint(out[pos..], "NtGlobalFlag: 0x{X}\n", .{readU32LE(&dw_buf)}) catch return .{ .text = out[0..pos] };
        pos += line.len;
    }

    const pp_off: usize = if (is64) 0x20 else 0x10;
    if (bridge.memRead(peb + pp_off, ptr_buf[0..ptr_size])) {
        const pp = readPtrLE(ptr_buf[0..ptr_size]);
        if (pp != 0) {
            const us_buf_off: usize = if (is64) 8 else 4;
            const us_size: usize = if (is64) 16 else 8;
            var us_buf: [16]u8 = undefined;

            const imgpath_off: usize = if (is64) 0x60 else 0x38;
            if (bridge.memRead(pp + imgpath_off, us_buf[0..us_size])) {
                const us_len = readU16LE(us_buf[0..2]);
                const us_ptr = readPtrLE(us_buf[us_buf_off .. us_buf_off + ptr_size]);
                if (us_ptr != 0 and us_len > 0) {
                    var wbuf: [520]u8 = undefined;
                    const rlen = @min(us_len, 520);
                    if (bridge.memRead(us_ptr, wbuf[0..rlen])) {
                        var abuf: [260]u8 = undefined;
                        const alen = @min(rlen / 2, 260);
                        for (0..alen) |j| abuf[j] = wbuf[j * 2];
                        const line = std.fmt.bufPrint(out[pos..], "ImagePath: {s}\n", .{abuf[0..alen]}) catch return .{ .text = out[0..pos] };
                        pos += line.len;
                    }
                }
            }

            const cmdline_off: usize = if (is64) 0x70 else 0x40;
            if (bridge.memRead(pp + cmdline_off, us_buf[0..us_size])) {
                const us_len = readU16LE(us_buf[0..2]);
                const us_ptr = readPtrLE(us_buf[us_buf_off .. us_buf_off + ptr_size]);
                if (us_ptr != 0 and us_len > 0) {
                    var wbuf: [520]u8 = undefined;
                    const rlen = @min(us_len, 520);
                    if (bridge.memRead(us_ptr, wbuf[0..rlen])) {
                        var abuf: [260]u8 = undefined;
                        const alen = @min(rlen / 2, 260);
                        for (0..alen) |j| abuf[j] = wbuf[j * 2];
                        const line = std.fmt.bufPrint(out[pos..], "CommandLine: {s}\n", .{abuf[0..alen]}) catch return .{ .text = out[0..pos] };
                        pos += line.len;
                    }
                }
            }
        }
    }

    return .{ .text = out[0..pos] };
}

// ── GetArguments ──────────────────────────────────────────────────
fn getArguments(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");

    var count: usize = 4;
    if (getParamInt(params, "count")) |c| {
        count = @intCast(@min(@max(c, 1), 16));
    }

    const is64 = @sizeOf(usize) == 8;
    const ptr_size: usize = if (is64) 8 else 4;
    var pos: usize = 0;

    if (is64) {
        const reg_names = [_]struct { name: [*:0]const u8, display: []const u8 }{
            .{ .name = "rcx\x00", .display = "rcx" },
            .{ .name = "rdx\x00", .display = "rdx" },
            .{ .name = "r8\x00", .display = "r8" },
            .{ .name = "r9\x00", .display = "r9" },
        };
        for (reg_names, 0..) |reg, idx| {
            if (idx >= count) break;
            const val = bridge.valFromString(reg.name);
            const line = std.fmt.bufPrint(out[pos..], "arg{d} ({s}): 0x{X}\n", .{ idx + 1, reg.display, val }) catch break;
            pos += line.len;
        }
        if (count > 4) {
            const rsp = bridge.valFromString("rsp\x00");
            var j: usize = 4;
            while (j < count) : (j += 1) {
                var buf: [8]u8 = undefined;
                const stack_off = 0x28 + (j - 4) * 8;
                if (!bridge.memRead(rsp + stack_off, &buf)) break;
                const val = readPtrLE(&buf);
                const line = std.fmt.bufPrint(out[pos..], "arg{d} ([rsp+0x{X}]): 0x{X}\n", .{ j + 1, stack_off, val }) catch break;
                pos += line.len;
            }
        }
    } else {
        const esp = bridge.valFromString("esp\x00");
        var j: usize = 0;
        while (j < count) : (j += 1) {
            var buf: [4]u8 = undefined;
            const off = (j + 1) * ptr_size;
            if (!bridge.memRead(esp + off, &buf)) break;
            const val = readU32LE(&buf);
            const line = std.fmt.bufPrint(out[pos..], "arg{d} ([esp+0x{X}]): 0x{X} ({d})\n", .{ j + 1, off, val, val }) catch break;
            pos += line.len;
        }
    }

    if (pos == 0) return errResult(out, "Error: Could not read arguments.");
    return .{ .text = out[0..pos] };
}

// ── DumpMemory ────────────────────────────────────────────────────
fn dumpMemory(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    var addr_buf: [32]u8 = undefined;
    const addr_str = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    const size = getParamInt(params, "size") orelse
        return errResult(out, "Error: size is required.");
    const file_path = getParamStr(params, "filePath") orelse
        return errResult(out, "Error: filePath is required.");

    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "savedata \"{s}\", {s}, {d}\x00", .{ file_path, addr_str, size }) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Memory dumped to file." else "Failed to dump memory."});
}

// ── AllocateMemory ────────────────────────────────────────────────
fn allocateMemory(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    const size = getParamInt(params, "size") orelse
        return errResult(out, "Error: size is required.");
    if (size <= 0 or size > 0x10000000) return errResult(out, "Error: Invalid size (1 to 256MB).");
    const prot_str = getParamStr(params, "protection") orelse "rw";
    var cmd_buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "alloc {d}\x00", .{size}) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExecDirect(@ptrCast(cmd.ptr));
    if (!ok) return errResult(out, "Error: alloc command failed.");
    const result_val = bridge.valFromString("$result\x00");
    if (result_val == 0) return errResult(out, "Error: Allocation returned null.");
    return fmtResult(out, "Allocated {d} bytes at 0x{X} (protection: {s})", .{ size, result_val, prot_str });
}

// ── FreeMemory ────────────────────────────────────────────────────
fn freeMemory(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    var addr_buf: [32]u8 = undefined;
    const addr_str = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    var cmd_buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "free {s}\x00", .{addr_str}) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExecDirect(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Memory freed." else "Error: Failed to free memory."});
}

// ── EnableBreakpoint ──────────────────────────────────────────────
fn enableBreakpoint(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    var addr_buf: [32]u8 = undefined;
    const addr = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    var cmd_buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "bpe {s}\x00", .{addr}) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Breakpoint enabled." else "Error: Failed to enable breakpoint."});
}

// ── DisableBreakpoint ─────────────────────────────────────────────
fn disableBreakpoint(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    var addr_buf: [32]u8 = undefined;
    const addr = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    var cmd_buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "bpd {s}\x00", .{addr}) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Breakpoint disabled." else "Error: Failed to disable breakpoint."});
}

// ── ToggleBreakpoint ──────────────────────────────────────────────
fn toggleBreakpoint(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    var addr_buf: [32]u8 = undefined;
    const addr = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    var cmd_buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "bp {s}, toggle\x00", .{addr}) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Breakpoint toggled." else "Error: Failed to toggle breakpoint."});
}

// ── DeleteAllBreakpoints ──────────────────────────────────────────
fn deleteAllBreakpoints(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    _ = bridge.cmdExec("bpc\x00");
    _ = bridge.cmdExec("bphc *\x00");
    _ = bridge.cmdExec("bpmc *\x00");
    return result(out, "All breakpoints deleted (normal, hardware, memory).");
}

// ── ResetHitCount ─────────────────────────────────────────────────
fn resetHitCount(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    var addr_buf: [32]u8 = undefined;
    const addr = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    var cmd_buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "ResetBreakpointHitCount {s}\x00", .{addr}) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Hit count reset." else "Error: Failed to reset hit count."});
}

// ── DisassembleFunction ───────────────────────────────────────────
fn disassembleFunction(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    var addr_buf: [32]u8 = undefined;
    const addr_str = getParamAddr(params, "address", &addr_buf) orelse "cip";

    var start_buf: [64]u8 = undefined;
    const start_expr = std.fmt.bufPrint(&start_buf, "func.start({s})\x00", .{addr_str}) catch
        return errResult(out, "Error: expression too long.");
    const func_start = bridge.valFromString(@ptrCast(start_expr.ptr));

    var end_buf: [64]u8 = undefined;
    const end_expr = std.fmt.bufPrint(&end_buf, "func.end({s})\x00", .{addr_str}) catch
        return errResult(out, "Error: expression too long.");
    const func_end = bridge.valFromString(@ptrCast(end_expr.ptr));

    if (func_start == 0 or func_end == 0 or func_end <= func_start)
        return errResult(out, "Error: No function boundaries found. Run analysis first (analr command).");

    var pos: usize = 0;
    var label_buf: [bridge.MAX_LABEL_SIZE]u8 = undefined;
    if (bridge.getLabelAt(func_start, &label_buf)) {
        const lbl = bridge.cstrSlice(&label_buf);
        const hdr = std.fmt.bufPrint(out[pos..], "Function: {s} (0x{X} - 0x{X})\n\n", .{ lbl, func_start, func_end }) catch "";
        pos += hdr.len;
    } else {
        const hdr = std.fmt.bufPrint(out[pos..], "Function: 0x{X} - 0x{X}\n\n", .{ func_start, func_end }) catch "";
        pos += hdr.len;
    }

    var current = func_start;
    var count: usize = 0;
    while (current <= func_end and count < 500) : (count += 1) {
        var next_buf: [64]u8 = undefined;
        const next_expr = std.fmt.bufPrint(&next_buf, "dis.next(0x{X})\x00", .{current}) catch break;
        const next_addr = bridge.valFromString(@ptrCast(next_expr.ptr));
        if (next_addr == 0 or next_addr == current) break;

        var text_buf: [256]u8 = std.mem.zeroes([256]u8);
        var instr_text: []const u8 = "";
        if (bridge.disasmTextAt(current, &text_buf)) {
            instr_text = bridge.cstrSlice(&text_buf);
        }

        if (instr_text.len > 0) {
            const line = std.fmt.bufPrint(out[pos..], "0x{X}  {s}\n", .{ current, instr_text }) catch break;
            pos += line.len;
        } else {
            const line = std.fmt.bufPrint(out[pos..], "0x{X}\n", .{current}) catch break;
            pos += line.len;
        }
        current = next_addr;
    }

    if (pos == 0) return errResult(out, "Error: Could not disassemble function.");
    return .{ .text = out[0..pos] };
}

// ── SearchSymbols ─────────────────────────────────────────────────
fn searchSymbols(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    const pattern = getParamStr(params, "pattern") orelse
        return errResult(out, "Error: pattern is required.");
    const module_filter = getParamStr(params, "module");

    const f = bridge.DbgMemMap orelse return errResult(out, "Error: Memory map not available.");
    var memmap: bridge.MEMMAP = undefined;
    if (f(&memmap) == 0) return errResult(out, "Error: Failed to get memory map.");
    defer {
        if (memmap.count > 0) {
            if (bridge.BridgeFree) |free| free(@ptrCast(memmap.page));
        }
    }

    var pos: usize = 0;
    const hdr = std.fmt.bufPrint(out[pos..], "Symbols matching \"{s}\":\n\n", .{pattern}) catch "";
    pos += hdr.len;

    var count: usize = 0;
    var last_base: bridge.duint = 0;
    const page_count: usize = @intCast(memmap.count);
    var pi: usize = 0;
    while (pi < page_count and count < 200) : (pi += 1) {
        const page = &memmap.page[pi];
        const mod_path = bridge.cstrSlice(&page.info);
        if (mod_path.len == 0) continue;
        if (!isModulePath(mod_path)) continue;
        if (page.mbi_AllocationBase == last_base) continue;
        last_base = page.mbi_AllocationBase;

        const base = page.mbi_AllocationBase;
        var mod_buf: [bridge.MAX_MODULE_SIZE]u8 = undefined;
        if (!bridge.getModuleAt(base, &mod_buf)) continue;
        const mod_name = bridge.cstrSlice(&mod_buf);

        if (module_filter) |mf| {
            if (!asciiContains(mod_name, mf)) continue;
        }

        const exp_dir = peGetDataDir(base, 0) orelse continue;
        if (exp_dir.rva == 0) continue;
        var ed: [40]u8 = undefined;
        if (!bridge.memRead(base + exp_dir.rva, &ed)) continue;
        const num_names = readU32LE(ed[24..28]);
        const addr_funcs = readU32LE(ed[28..32]);
        const addr_names = readU32LE(ed[32..36]);
        const addr_ords = readU32LE(ed[36..40]);

        const limit = @min(num_names, 1000);
        var ei: u32 = 0;
        while (ei < limit and count < 200) : (ei += 1) {
            var nrb: [4]u8 = undefined;
            if (!bridge.memRead(base + addr_names + ei * 4, &nrb)) break;
            var nbuf: [128]u8 = undefined;
            if (!bridge.memRead(base + readU32LE(&nrb), &nbuf)) break;
            const name = bridge.cstrSlice(&nbuf);
            if (asciiContains(name, pattern)) {
                var ob: [2]u8 = undefined;
                if (!bridge.memRead(base + addr_ords + ei * 2, &ob)) break;
                const ordinal = readU16LE(&ob);
                var frb: [4]u8 = undefined;
                if (!bridge.memRead(base + addr_funcs + @as(u32, ordinal) * 4, &frb)) break;
                const func_rva = readU32LE(&frb);
                const line = std.fmt.bufPrint(out[pos..], "0x{X}  {s}!{s}\n", .{ base + func_rva, mod_name, name }) catch break;
                pos += line.len;
                count += 1;
            }
        }
    }

    if (count == 0) return fmtResult(out, "No symbols found matching \"{s}\".", .{pattern});
    return .{ .text = out[0..pos] };
}

fn asciiContains(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    if (needle.len == 0) return true;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var match = true;
        for (needle, 0..) |nc, j| {
            const hc = haystack[i + j];
            const nl = if (nc >= 'A' and nc <= 'Z') nc + 32 else nc;
            const hl = if (hc >= 'A' and hc <= 'Z') hc + 32 else hc;
            if (nl != hl) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

// ── ListSymbols ───────────────────────────────────────────────────
fn listSymbols(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    const mod_name_param = getParamStr(params, "module") orelse
        return errResult(out, "Error: module is required.");

    const base = resolveModBase(mod_name_param);
    if (base == 0) return fmtErr(out, "Error: Module \"{s}\" not found.", .{mod_name_param});

    const exp_dir = peGetDataDir(base, 0) orelse
        return errResult(out, "Error: Could not read PE headers.");
    if (exp_dir.rva == 0) return result(out, "No exports.");

    var ed: [40]u8 = undefined;
    if (!bridge.memRead(base + exp_dir.rva, &ed))
        return errResult(out, "Error: Could not read export directory.");

    const num_names = readU32LE(ed[24..28]);
    const addr_funcs = readU32LE(ed[28..32]);
    const addr_names = readU32LE(ed[32..36]);
    const addr_ords = readU32LE(ed[36..40]);
    const ord_base = readU32LE(ed[16..20]);

    var pos: usize = 0;
    const hdr = std.fmt.bufPrint(out[pos..], "Exports from {s} ({d} symbols):\n\n", .{ mod_name_param, num_names }) catch "";
    pos += hdr.len;

    const limit = @min(num_names, 500);
    var i: u32 = 0;
    while (i < limit) : (i += 1) {
        var nrb: [4]u8 = undefined;
        if (!bridge.memRead(base + addr_names + i * 4, &nrb)) break;
        var ob: [2]u8 = undefined;
        if (!bridge.memRead(base + addr_ords + i * 2, &ob)) break;
        const ordinal = readU16LE(&ob);
        var frb: [4]u8 = undefined;
        if (!bridge.memRead(base + addr_funcs + @as(u32, ordinal) * 4, &frb)) break;
        const func_rva = readU32LE(&frb);
        var nbuf: [128]u8 = undefined;
        if (!bridge.memRead(base + readU32LE(&nrb), &nbuf)) break;
        const name = bridge.cstrSlice(&nbuf);
        const line = std.fmt.bufPrint(out[pos..], "  #{d} 0x{X} {s}\n", .{ @as(u32, ordinal) + ord_base, base + func_rva, name }) catch break;
        pos += line.len;
    }
    if (pos == 0) return result(out, "No exports found.");
    return .{ .text = out[0..pos] };
}

// ── SuspendThread ─────────────────────────────────────────────────
fn suspendThread(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    const tid = getParamInt(params, "threadId") orelse
        return errResult(out, "Error: threadId is required.");
    var cmd_buf: [64]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "suspendthread {d}\x00", .{tid}) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Thread suspended." else "Error: Failed to suspend thread."});
}

// ── ResumeThread ──────────────────────────────────────────────────
fn resumeThread(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    const tid = getParamInt(params, "threadId") orelse
        return errResult(out, "Error: threadId is required.");
    var cmd_buf: [64]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "resumethread {d}\x00", .{tid}) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Thread resumed." else "Error: Failed to resume thread."});
}

// ── SetBookmark ───────────────────────────────────────────────────
fn setBookmark(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    var addr_buf: [32]u8 = undefined;
    const addr = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    var cmd_buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "bookmarkadd {s}\x00", .{addr}) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Bookmark set." else "Error: Failed to set bookmark."});
}

// ── DeleteBookmark ────────────────────────────────────────────────
fn deleteBookmark(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    var addr_buf: [32]u8 = undefined;
    const addr = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    var cmd_buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "bookmarkdel {s}\x00", .{addr}) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Bookmark deleted." else "Error: Failed to delete bookmark."});
}

// ── ListBookmarks ─────────────────────────────────────────────────
fn listBookmarks(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    const ok = bridge.cmdExecDirect("bookmarklist\x00");
    if (!ok) return errResult(out, "Error: Failed to list bookmarks.");
    return result(out, "Bookmarks listed in the x64dbg log. Use GetEventLog to see results.");
}

// ── DumpModule ────────────────────────────────────────────────────
fn dumpModule(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    const mod_name = getParamStr(params, "module") orelse
        return errResult(out, "Error: module is required.");
    const file_path = getParamStr(params, "filePath") orelse
        return errResult(out, "Error: filePath is required.");

    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "modexport {s}, \"{s}\"\x00", .{ mod_name, file_path }) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExecDirect(@ptrCast(cmd.ptr));
    if (!ok) {
        var base_buf: [128]u8 = undefined;
        const base_expr = std.fmt.bufPrint(&base_buf, "{s}:0\x00", .{mod_name}) catch return errResult(out, "Error: expression too long.");
        const mod_base = bridge.valFromString(@ptrCast(base_expr.ptr));
        if (mod_base == 0) return fmtErr(out, "Error: Module \"{s}\" not found.", .{mod_name});
        const mod_size_expr = std.fmt.bufPrint(&cmd_buf, "mod.size({s}:0)\x00", .{mod_name}) catch return errResult(out, "Error: expression too long.");
        const mod_size = bridge.valFromString(@ptrCast(mod_size_expr.ptr));
        if (mod_size == 0) return fmtErr(out, "Error: Could not determine size of \"{s}\".", .{mod_name});
        var save_buf: [512]u8 = undefined;
        const save_cmd = std.fmt.bufPrint(&save_buf, "savedata \"{s}\", 0x{X}, 0x{X}\x00", .{ file_path, mod_base, mod_size }) catch
            return errResult(out, "Error: path too long.");
        const save_ok = bridge.cmdExec(@ptrCast(save_cmd.ptr));
        return fmtResult(out, "{s}", .{if (save_ok) "Module dumped to file." else "Error: Failed to dump module."});
    }
    return fmtResult(out, "Module \"{s}\" dumped to \"{s}\".", .{ mod_name, file_path });
}

// ── AnalyzeModule ─────────────────────────────────────────────────
fn analyzeModule(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    const mod_name = getParamStr(params, "module") orelse
        return errResult(out, "Error: module is required.");

    var expr_buf: [128]u8 = undefined;
    const base_expr = std.fmt.bufPrint(&expr_buf, "{s}:0\x00", .{mod_name}) catch
        return errResult(out, "Error: expression too long.");
    const base = bridge.valFromString(@ptrCast(base_expr.ptr));
    if (base == 0) return fmtErr(out, "Error: Module \"{s}\" not found.", .{mod_name});

    var pe_hdr: [4]u8 = undefined;
    if (!bridge.memRead(base + 0x3C, &pe_hdr)) return errResult(out, "Error: Cannot read PE header.");
    const pe_off: usize = readU32LE(&pe_hdr);

    var sig: [4]u8 = undefined;
    if (!bridge.memRead(base + pe_off, &sig)) return errResult(out, "Error: Cannot read PE signature.");
    if (!std.mem.eql(u8, &sig, "PE\x00\x00")) return errResult(out, "Error: Invalid PE signature.");

    var coff: [20]u8 = undefined;
    if (!bridge.memRead(base + pe_off + 4, &coff)) return errResult(out, "Error: Cannot read COFF header.");
    const num_sections = readU16LE(coff[2..4]);
    const optional_size = readU16LE(coff[16..18]);
    const characteristics = readU16LE(coff[18..20]);

    var opt: [4]u8 = undefined;
    if (!bridge.memRead(base + pe_off + 24, &opt)) return errResult(out, "Error: Cannot read optional header.");
    const magic = readU16LE(opt[0..2]);
    const is_pe32_plus = (magic == 0x20b);

    const ep_off: usize = 16;
    var ep_buf: [4]u8 = undefined;
    if (!bridge.memRead(base + pe_off + 24 + ep_off, &ep_buf)) return errResult(out, "Error: Cannot read EP.");
    const ep_rva = readU32LE(&ep_buf);

    const size_off: usize = if (is_pe32_plus) 56 else 56;
    var size_buf: [4]u8 = undefined;
    if (!bridge.memRead(base + pe_off + 24 + size_off, &size_buf))
        return errResult(out, "Error: Cannot read image size.");
    const image_size = readU32LE(&size_buf);

    var pos: usize = 0;
    const hdr_info = std.fmt.bufPrint(out[pos..], "Module: {s}\nBase: 0x{X}\nFormat: {s}\nEntry Point: 0x{X} (RVA 0x{X})\nImage Size: 0x{X} ({d} KB)\nCharacteristics: 0x{X}\nSections: {d}\n\n", .{
        mod_name, base, if (is_pe32_plus) "PE32+" else "PE32", base + ep_rva, ep_rva, image_size, image_size / 1024, characteristics, num_sections,
    }) catch return errResult(out, "Error: Output too long.");
    pos += hdr_info.len;

    const section_base = pe_off + 24 + optional_size;
    var si: usize = 0;
    while (si < num_sections and si < 64) : (si += 1) {
        var sec: [40]u8 = undefined;
        if (!bridge.memRead(base + section_base + si * 40, &sec)) break;
        const sec_name = std.mem.sliceTo(sec[0..8], 0);
        const vsize = readU32LE(sec[8..12]);
        const vrva = readU32LE(sec[12..16]);
        const raw_size = readU32LE(sec[16..20]);
        const sec_chars = readU32LE(sec[36..40]);
        var flags_buf: [32]u8 = undefined;
        var fi: usize = 0;
        if (sec_chars & 0x20000000 != 0) {
            flags_buf[fi] = 'X';
            fi += 1;
        }
        if (sec_chars & 0x40000000 != 0) {
            flags_buf[fi] = 'R';
            fi += 1;
        }
        if (sec_chars & 0x80000000 != 0) {
            flags_buf[fi] = 'W';
            fi += 1;
        }
        const line = std.fmt.bufPrint(out[pos..], "  {s: <8}  VA=0x{X}  VSize=0x{X}  RawSize=0x{X}  [{s}]\n", .{
            sec_name, vrva, vsize, raw_size, flags_buf[0..fi],
        }) catch break;
        pos += line.len;
    }

    if (pos == 0) return errResult(out, "Error: Could not analyze module.");
    return .{ .text = out[0..pos] };
}

// ── DetectOEP ─────────────────────────────────────────────────────
fn detectOEP(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");
    const mod_name = getParamStr(params, "module") orelse
        return errResult(out, "Error: module is required.");

    var expr_buf: [128]u8 = undefined;
    const base_expr = std.fmt.bufPrint(&expr_buf, "{s}:0\x00", .{mod_name}) catch
        return errResult(out, "Error: expression too long.");
    const base = bridge.valFromString(@ptrCast(base_expr.ptr));
    if (base == 0) return fmtErr(out, "Error: Module \"{s}\" not found.", .{mod_name});

    var pe_hdr: [4]u8 = undefined;
    if (!bridge.memRead(base + 0x3C, &pe_hdr)) return errResult(out, "Error: Cannot read PE header.");
    const pe_off: usize = readU32LE(&pe_hdr);

    var coff: [20]u8 = undefined;
    if (!bridge.memRead(base + pe_off + 4, &coff)) return errResult(out, "Error: Cannot read COFF header.");
    const num_sections = readU16LE(coff[2..4]);
    const optional_size = readU16LE(coff[16..18]);

    var opt: [4]u8 = undefined;
    if (!bridge.memRead(base + pe_off + 24, &opt)) return errResult(out, "Error: Cannot read optional header.");
    const magic = readU16LE(opt[0..2]);
    const is_pe32_plus = (magic == 0x20b);
    _ = is_pe32_plus;

    var ep_buf: [4]u8 = undefined;
    if (!bridge.memRead(base + pe_off + 24 + 16, &ep_buf)) return errResult(out, "Error: Cannot read EP.");
    const ep_rva = readU32LE(&ep_buf);

    const section_base = pe_off + 24 + optional_size;
    var pos: usize = 0;

    const hdr = std.fmt.bufPrint(out[pos..], "OEP Detection for {s}\nStated Entry Point: 0x{X} (RVA 0x{X})\n\n", .{ mod_name, base + ep_rva, ep_rva }) catch "";
    pos += hdr.len;

    var ep_in_section = false;
    var suspicious = false;
    var si: usize = 0;
    while (si < num_sections and si < 64) : (si += 1) {
        var sec: [40]u8 = undefined;
        if (!bridge.memRead(base + section_base + si * 40, &sec)) break;
        const sec_name = std.mem.sliceTo(sec[0..8], 0);
        const vsize = readU32LE(sec[8..12]);
        const vrva = readU32LE(sec[12..16]);
        const raw_size = readU32LE(sec[16..20]);
        const sec_chars = readU32LE(sec[36..40]);

        if (ep_rva >= vrva and ep_rva < vrva + vsize) {
            ep_in_section = true;
            const line = std.fmt.bufPrint(out[pos..], "EP is in section \"{s}\" (RVA 0x{X}, size 0x{X})\n", .{ sec_name, vrva, vsize }) catch break;
            pos += line.len;
            if (sec_chars & 0x80000000 != 0 and sec_chars & 0x20000000 != 0) {
                const warn = std.fmt.bufPrint(out[pos..], "  WARNING: Section is RWX - typical of packers!\n", .{}) catch break;
                pos += warn.len;
                suspicious = true;
            }
        }

        if (raw_size == 0 and vsize > 0) {
            const line = std.fmt.bufPrint(out[pos..], "Section \"{s}\" has raw_size=0 but vsize=0x{X} (unpacked data area)\n", .{ sec_name, vsize }) catch break;
            pos += line.len;
            suspicious = true;
        }

        if (sec_chars & 0x80000000 != 0 and sec_chars & 0x20000000 != 0) {
            if (ep_rva < vrva or ep_rva >= vrva + vsize) {
                const line = std.fmt.bufPrint(out[pos..], "Section \"{s}\" is RWX (potential unpack target)\n", .{sec_name}) catch break;
                pos += line.len;
            }
        }
    }

    if (!ep_in_section) {
        const warn = std.fmt.bufPrint(out[pos..], "WARNING: EP not in any section - highly suspicious!\n", .{}) catch "";
        pos += warn.len;
        suspicious = true;
    }

    if (suspicious) {
        const tip = std.fmt.bufPrint(out[pos..], "\nPossibly packed. Set a hardware breakpoint on ESP at EP and run to find OEP.\n", .{}) catch "";
        pos += tip.len;
    } else {
        const tip = std.fmt.bufPrint(out[pos..], "\nNo packing indicators detected. EP likely is OEP.\n", .{}) catch "";
        pos += tip.len;
    }

    return .{ .text = out[0..pos] };
}

// ── GetDumpableRegions ────────────────────────────────────────────
fn getDumpableRegions(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target is running. Pause first.");

    const f = bridge.DbgMemMap orelse return errResult(out, "Error: Memory map not available.");
    var memmap: bridge.MEMMAP = undefined;
    if (f(&memmap) == 0) return errResult(out, "Error: Failed to get memory map.");
    defer {
        if (memmap.count > 0) {
            if (bridge.BridgeFree) |free| free(@ptrCast(memmap.page));
        }
    }

    var pos: usize = 0;
    const hdr = std.fmt.bufPrint(out[pos..], "Dumpable Memory Regions:\n\n", .{}) catch "";
    pos += hdr.len;

    const page_count: usize = @intCast(memmap.count);
    var count: usize = 0;
    var pi: usize = 0;
    while (pi < page_count and count < 200) : (pi += 1) {
        const page = &memmap.page[pi];
        const state = page.mbi_State;
        const protect = page.mbi_Protect;
        if (state != 0x1000) continue;
        if (protect & 0x100 != 0) continue;

        const base_addr = page.mbi_BaseAddress;
        const region_size = page.mbi_RegionSize;
        const info_str = bridge.cstrSlice(&page.info);

        const prot = protectStr(protect);

        const line = std.fmt.bufPrint(out[pos..], "0x{X}  Size=0x{X} ({d} KB)  {s}  {s}\n", .{
            base_addr, region_size, region_size / 1024, prot, info_str,
        }) catch break;
        pos += line.len;
        count += 1;
    }

    if (count == 0) return errResult(out, "Error: No dumpable regions found.");
    const footer = std.fmt.bufPrint(out[pos..], "\nTotal: {d} dumpable regions\n", .{count}) catch "";
    pos += footer.len;
    return .{ .text = out[0..pos] };
}

// ── RestorePatches ────────────────────────────────────────────────
fn restorePatches(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    const ok = bridge.cmdExec("patchrestore\x00");
    return fmtResult(out, "{s}", .{if (ok) "All patches restored to original bytes." else "Error: Failed to restore patches."});
}

// ── SetExceptionBreakpoint ───────────────────────────────────────
fn setExceptionBreakpoint(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    const code = getParamStr(params, "exceptionCode") orelse
        return errResult(out, "Error: exceptionCode is required.");
    const chance = getParamInt(params, "chance") orelse 1;
    const action = getParamStr(params, "action") orelse "break";
    const is_ignore = std.mem.eql(u8, action, "ignore");
    var cmd_buf: [256]u8 = undefined;
    if (is_ignore) {
        const cmd = std.fmt.bufPrint(&cmd_buf, "DisableExceptionBPX {s}\x00", .{code}) catch
            return errResult(out, "Error: input too long.");
        _ = bridge.cmdExec(@ptrCast(cmd.ptr));
        return fmtResult(out, "Exception {s} set to pass to application (ignore).", .{code});
    } else {
        const cmd = std.fmt.bufPrint(&cmd_buf, "SetExceptionBPX {s}, {d}\x00", .{ code, chance }) catch
            return errResult(out, "Error: input too long.");
        const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
        return fmtResult(out, "{s}", .{if (ok) "Exception breakpoint set." else "Failed to set exception breakpoint."});
    }
}

// ── DeleteExceptionBreakpoint ────────────────────────────────────
fn deleteExceptionBreakpoint(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    const code = getParamStr(params, "exceptionCode") orelse
        return errResult(out, "Error: exceptionCode is required.");
    var cmd_buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "DeleteExceptionBPX {s}\x00", .{code}) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Exception breakpoint deleted." else "Failed to delete exception breakpoint."});
}

// ── AnalyzeCode ──────────────────────────────────────────────────
fn analyzeCode(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    var addr_buf: [32]u8 = undefined;
    const addr = getParamAddr(params, "address", &addr_buf) orelse "";
    const atype = getParamStr(params, "type") orelse "module";

    var cmd_buf: [256]u8 = undefined;
    if (std.mem.eql(u8, atype, "function")) {
        if (addr.len > 0) {
            const cmd = std.fmt.bufPrint(&cmd_buf, "analr {s}\x00", .{addr}) catch
                return errResult(out, "Error: input too long.");
            const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
            return fmtResult(out, "{s}", .{if (ok) "Function analysis completed." else "Analysis failed."});
        } else {
            const ok = bridge.cmdExec("analr cip\x00");
            return fmtResult(out, "{s}", .{if (ok) "Function analysis at CIP completed." else "Analysis failed."});
        }
    } else if (std.mem.eql(u8, atype, "controlflow")) {
        const ok = bridge.cmdExec("cfanal\x00");
        return fmtResult(out, "{s}", .{if (ok) "Control flow analysis completed." else "Analysis failed."});
    } else {
        if (addr.len > 0) {
            const cmd = std.fmt.bufPrint(&cmd_buf, "anal {s}\x00", .{addr}) catch
                return errResult(out, "Error: input too long.");
            const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
            return fmtResult(out, "{s}", .{if (ok) "Module analysis completed. GetFunctions and GetReferences now available." else "Analysis failed."});
        } else {
            const ok = bridge.cmdExec("anal\x00");
            return fmtResult(out, "{s}", .{if (ok) "Module analysis completed. GetFunctions and GetReferences now available." else "Analysis failed."});
        }
    }
}

// ── TraceOver ────────────────────────────────────────────────────
fn traceOver(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    if (bridge.isRunning()) return errResult(out, "Error: Target must be PAUSED.");

    var count: i64 = 10;
    if (getParamInt(params, "count")) |c| count = @min(@max(c, 1), 100);

    var pos: usize = 0;
    var i: i64 = 0;
    while (i < count) : (i += 1) {
        if (bridge.isRunning()) break;
        _ = bridge.cmdExec("sto\x00");
        Sleep(50);
        while (bridge.isRunning()) Sleep(10);

        const cip = bridge.valFromString("cip");
        var dis_buf: [256]u8 = undefined;
        const has_dis = bridge.disasmTextAt(cip, &dis_buf);
        const dis_text = if (has_dis) bridge.cstrSlice(&dis_buf) else "???";
        const line = std.fmt.bufPrint(out[pos..], "0x{X}: {s}\n", .{ cip, dis_text }) catch break;
        pos += line.len;
    }
    if (pos == 0) return errResult(out, "Error: Could not trace.");
    return .{ .text = out[0..pos] };
}

// ── SetBreakpointCommand ─────────────────────────────────────────
fn setBreakpointCommand(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    var addr_buf: [32]u8 = undefined;
    const addr = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    const command = getParamStr(params, "command") orelse
        return errResult(out, "Error: command is required.");
    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "SetBreakpointCommand {s}, {s}\x00", .{ addr, command }) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Breakpoint command set." else "Failed to set breakpoint command."});
}

// ── SetBreakpointFastResume ──────────────────────────────────────
fn setBreakpointFastResume(params: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    var addr_buf: [32]u8 = undefined;
    const addr = getParamAddr(params, "address", &addr_buf) orelse
        return errResult(out, "Error: address is required.");
    const enable = getParamBool(params, "enable") orelse true;
    var cmd_buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "SetBreakpointFastResume {s}, {d}\x00", .{ addr, @as(u8, if (enable) 1 else 0) }) catch
        return errResult(out, "Error: input too long.");
    const ok = bridge.cmdExec(@ptrCast(cmd.ptr));
    return fmtResult(out, "{s}", .{if (ok) "Breakpoint fast resume set." else "Failed to set fast resume."});
}

// ── SaveDatabase ─────────────────────────────────────────────────
fn saveDatabase(_: ?std.json.Value, out: []u8) ToolResult {
    if (!bridge.isDebugging()) return errResult(out, "Error: No active debug session.");
    const ok = bridge.cmdExec("dbsave\x00");
    return fmtResult(out, "{s}", .{if (ok) "Database saved." else "Failed to save database."});
}

// ── Tests ───────────────────────────────────────────────────────────

test "every tool belongs to a known category" {
    for (tools) |t| {
        var known = false;
        for (categories) |c| {
            if (std.mem.eql(u8, t.category, c)) {
                known = true;
                break;
            }
        }
        try std.testing.expect(known);
    }
}

test "ListCommandsByCategory groups the tools by category" {
    var buf: [65536]u8 = undefined;
    const r = listCommandsByCategory(null, &buf);
    try std.testing.expect(!r.is_error);
    for (categories) |c| {
        try std.testing.expect(std.mem.indexOf(u8, r.text, c) != null);
    }
    for (tools) |t| {
        try std.testing.expect(std.mem.indexOf(u8, r.text, t.name) != null);
    }
}

test "ListCommandsByCategory filters by category" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"category":"Memory"}
    , .{});
    defer parsed.deinit();

    var buf: [65536]u8 = undefined;
    const r = listCommandsByCategory(parsed.value, &buf);
    try std.testing.expect(!r.is_error);
    try std.testing.expect(std.mem.indexOf(u8, r.text, "Memory:") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.text, "ReadMemory") != null);
    // A tool of another category is not listed.
    try std.testing.expect(std.mem.indexOf(u8, r.text, "SuspendThread") == null);
}

test "ListCommandsByCategory reports an unknown category" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"category":"Nonexistent"}
    , .{});
    defer parsed.deinit();

    var buf: [65536]u8 = undefined;
    const r = listCommandsByCategory(parsed.value, &buf);
    try std.testing.expect(r.is_error);
    try std.testing.expect(std.mem.indexOf(u8, r.text, "Unknown category") != null);
}
