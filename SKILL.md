# x64dbg Reverse Engineering — MCP Workflow Guide

You are controlling x64dbg through MCP tools.

**Transport matters:**
- **SSE clients** receive push notifications for debugger events (breakpoints, exceptions, state changes) in real time.
- **HTTP clients** must poll — call `WaitForEvent` to long-poll for events, or read the `[state]` and `[event:*]` lines included in every tool response.

Treat every assumption about debugger state as stale until verified by a tool response.

---

## Rule 1: Always Know Your State

**Before every action**, call `GetDebugState`. No exceptions.

- `NO_TARGET` — nothing loaded. Use `LoadBinary` or `AttachProcess` first.
- `PAUSED` — target is stopped. You can read memory, disassemble, inspect registers.
- `RUNNING` — target is executing. You CANNOT read memory, disassemble, or inspect anything. Call `WaitForPause` or `PauseDebug` first.

Every tool response includes a `[state]` line at the end showing the current debugger status — PAUSED with address/module/instruction, RUNNING, or NO_TARGET. Always read it. This is your primary state awareness mechanism.

Every tool response may also include `[event:*]` lines — queued debugger events (breakpoints hit, exceptions, DLL loads) that occurred since your last call. Always read these too.

If the user says "paused", "hit breakpoint", "stopped", or "debugger is paused" — immediately call `GetDebugState` to see where you are. Do not guess.

---

## Rule 2: Never Assume State Between Calls

MCP is request/response. Between your tool calls, anything can happen — breakpoints can hit, exceptions can fire, the user can interact with the debugger. Every time you are about to act, verify first.

Bad:
```
SetBreakpoint → run → Disassemble  (wrong: run blocks but verify anyway)
```

Good:
```
GetDebugState → SetBreakpoint → run → GetDebugState → Disassemble
```

---

## Rule 3: Core Workflows

### Load and analyze a binary
```
GetDebugState
LoadBinary (path)
WaitForPause            — target pauses at system breakpoint
GetDebugState           — confirm PAUSED, note the address
GetAllRegisters         — see initial state
ListModules             — see what's loaded
Disassemble             — look at current code
```

### Set breakpoint and run to it
```
GetDebugState           — must be PAUSED
SetBreakpoint (target)  — set the BP
run                     — blocks until target pauses (5-min timeout)
GetDebugState           — confirm PAUSED, check address
Disassemble             — see where we landed
GetAllRegisters         — inspect state
```

### Step through code
```
GetDebugState           — must be PAUSED
StepOver                — response includes new address + disassembly
                        — read the response carefully before next step
StepOver                — keep stepping, reading each response
GetAllRegisters         — check registers when needed
GetCallStack            — check call context when needed
```

### Find and hook an API call
```
SearchSymbols (pattern) — find the API across all modules
SetBreakpoint (address) — break on it
run                     — blocks until BP hits
GetDebugState
GetArguments            — read function arguments
GetCallStack            — see who called it
```

### Trace execution
```
GetDebugState           — must be PAUSED
TraceInto (count)       — step N instructions, get address + disasm log
GetDebugState           — see where we ended up
```

### Unpack a binary
```
LoadBinary → WaitForPause → GetDebugState
AnalyzeModule           — check sections, EP, image size
DetectOEP               — look for packing indicators (RWX sections, zero raw sizes)
SetHardwareBreakpoint   — on suspected OEP or after unpacking stub
run → GetDebugState     — run blocks until pause
DumpModule              — dump the unpacked module
```

### Patch memory
```
GetDebugState           — must be PAUSED
Disassemble (address)   — see current bytes
WriteMemToAddress       — patch with new bytes
Disassemble (address)   — verify the patch
GetPatches              — see all active patches
```

### Monitor while user interacts with GUI (HTTP only)
```
WaitForEvent (timeoutMs: 120000)  — long-poll up to 2 minutes
                                  — returns any events that fired
GetDebugState                     — check where we are now
WaitForEvent (timeoutMs: 120000)  — keep watching
```

---

## Rule 4: All 80 Tools Reference

Every tool response includes a `[state]` line showing current debugger status and any `[event:*]` lines with queued events. You always know where you are.

### State & Control (always available)
| Tool | Parameters | Description |
|------|-----------|-------------|
| `GetDebugState` | — | Current state (NO_TARGET/RUNNING/PAUSED), PID, address, module |
| `LoadBinary` | `filePath` | Load an executable into the debugger |
| `AttachProcess` | `pid` | Attach to a running process by PID |
| `run` | `timeoutMs?` (default 300000) | Resume execution (F9). Blocks until target pauses or timeout |
| `PauseDebug` | — | Pause the target (F12) |
| `WaitForPause` | `timeoutMs?` (default 30000) | Block until target pauses (breakpoint/exception) |
| `StopDebug` | — | Terminate debug session |
| `RestartDebug` | — | Restart debug session |
| `ExecuteDebuggerCommand` | `command` | Run any x64dbg command string. Blocks if target becomes RUNNING |
| `EvalExpression` | `expression` | Evaluate expression (address, register, symbol, arithmetic) |
| `Echo` | `message` | Echo input back (connectivity test) |
| `ListCommandsByCategory` | `category?` | List the MCP tools, grouped by category |
| `SearchForStrings` | `searchText` | Search process memory for text |
| `GetEventLog` | `count?` (default: all) | Last N debugger events |
| `ClearEventLog` | — | Clear the event log |
| `WaitForEvent` | `timeoutMs?` (default 30000) | Long-poll for debugger events. For HTTP clients to watch state changes |

### Stepping (requires PAUSED)
| Tool | Parameters | Description |
|------|-----------|-------------|
| `StepInto` | — | Single-step into calls (F7). Returns new address + disassembly |
| `StepOver` | — | Step over calls (F8). Returns new address + disassembly |
| `StepOut` | — | Run until return (Ctrl+F9). Returns new address + disassembly |
| `RunToAddress` | `address` | Run until hitting a specific address |
| `TraceInto` | `count` | Step N instructions recording address + disassembly for each |
| `TraceOver` | `count` | Trace N instructions stepping OVER calls |

### Breakpoints (requires debug session)
| Tool | Parameters | Description |
|------|-----------|-------------|
| `SetBreakpoint` | `target` (address or symbol) | Set INT3 breakpoint |
| `SetHardwareBreakpoint` | `address`, `type` (r/w/x), `size?` | Set hardware BP (DR0-DR3) |
| `SetConditionalBreakpoint` | `address`, `condition`, `log?` | Set BP with condition expression |
| `SetMemoryBreakpoint` | `address`, `type` (r/w/x), `singleshoot?` | Set memory breakpoint |
| `SetExceptionBreakpoint` | `exceptionCode`, `chance` (1/2/3), `action` | Configure exception BP (break/ignore) |
| `DeleteExceptionBreakpoint` | `exceptionCode` | Delete an exception breakpoint |
| `EnableBreakpoint` | `address` | Enable a breakpoint |
| `DisableBreakpoint` | `address` | Disable without deleting |
| `ToggleBreakpoint` | `address` | Toggle enabled/disabled |
| `DeleteBreakpoint` | `target` | Remove a breakpoint |
| `DeleteAllBreakpoints` | — | Remove all BPs (normal, hardware, memory) |
| `ResetHitCount` | `address` | Reset a BP's hit counter to zero |
| `ListBreakpoints` | — | List all active breakpoints |
| `SetBreakpointCommand` | `address`, `command` | Run x64dbg command on BP hit |
| `SetBreakpointFastResume` | `address`, `enable` | Auto-resume on BP hit |

### Disassembly & Code (requires PAUSED)
| Tool | Parameters | Description |
|------|-----------|-------------|
| `Disassemble` | `address?`, `count?` (default 10) | Disassemble N instructions |
| `DisassembleFunction` | `address?` | Disassemble entire function (needs analysis first) |
| `GetCurrentAddress` | — | Current EIP/RIP with label and comment |
| `GetFunctions` | `module?` | List analyzed functions with addresses |
| `GetReferences` | `address` | Find CALL/JMP xrefs to target address |
| `Assemble` | `address`, `instruction` | Assemble an instruction at address |

### Registers & Stack (requires PAUSED)
| Tool | Parameters | Description |
|------|-----------|-------------|
| `GetAllRegisters` | — | Dump all general-purpose registers |
| `SetRegister` | `register`, `value` | Set a CPU register value |
| `GetCallStack` | — | Current thread call stack |
| `GetArguments` | `count?` | Read function arguments from stack/registers |
| `WatchExpressions` | `expressions` (array) | Evaluate multiple expressions in one call |
| `FollowPointer` | `address`, `depth?` | Dereference pointer chain N levels deep |

### Memory (requires debug session)
| Tool | Parameters | Description |
|------|-----------|-------------|
| `ReadMemory` | `address`, `size?` (default 64) | Hex dump of process memory |
| `WriteMemToAddress` | `address`, `byteString` (hex) | Patch memory with hex bytes |
| `AllocateMemory` | `size` | Allocate memory in target process |
| `FreeMemory` | `address` | Free allocated memory |
| `GetMemoryMap` | — | Memory regions with addresses, sizes, protection |
| `GetDumpableRegions` | — | List committed, readable memory regions |
| `FindPattern` | `pattern`, `module?` | Scan for byte pattern with ?? wildcards |
| `GetPatches` | — | List all memory patches |
| `RestorePatches` | — | Restore all patches to original bytes |
| `DumpMemory` | `address`, `size`, `filePath` | Save memory region to file |

### Modules & Symbols (requires debug session)
| Tool | Parameters | Description |
|------|-----------|-------------|
| `ListModules` | — | List loaded modules with base addresses and sizes |
| `GetImports` | `module?` | Show module import table |
| `GetExports` | `module?` | Show module export table |
| `SearchSymbols` | `pattern` | Search for symbols matching pattern across all modules |
| `ListSymbols` | `module` | List exported symbols of a specific module |
| `GetStrings` | `module?` | Extract ASCII strings from module memory |

### Analysis (requires debug session)
| Tool | Parameters | Description |
|------|-----------|-------------|
| `AnalyzeModule` | `module?` | PE structure: sections, EP, image size, characteristics |
| `AnalyzeCode` | `address?`, `type` (function/module/controlflow) | Run code analysis |
| `DetectOEP` | `module?` | Detect Original Entry Point for packed executables |
| `DumpModule` | `module`, `filePath` | Dump entire module to file |
| `GetPEB` | — | Read Process Environment Block fields |
| `GetSEHChain` | — | Walk Structured Exception Handler chain (x32) |
| `SaveDatabase` | — | Save the x64dbg database (.dd64/.dd32) |

### Bookmarks & Comments (requires debug session)
| Tool | Parameters | Description |
|------|-----------|-------------|
| `CommentOrLabelAtAddress` | `address`, `value`, `mode` (Comment/Label) | Add comment/label in disassembly |
| `SetBookmark` | `address` | Set a bookmark |
| `DeleteBookmark` | `address` | Delete a bookmark |
| `ListBookmarks` | — | List all bookmarks |

### Threads (requires debug session)
| Tool | Parameters | Description |
|------|-----------|-------------|
| `GetThreads` | — | List all threads with IDs and instruction pointers |
| `SwitchThread` | `threadId` | Switch active thread context |
| `SuspendThread` | `threadId` | Suspend a thread |
| `ResumeThread` | `threadId` | Resume a suspended thread |

---

## Rule 5: Common Mistakes

| Mistake | Fix |
|---------|-----|
| Disassemble while target is RUNNING | `WaitForPause` or `PauseDebug` first |
| Assume breakpoint was hit after `run` | `run` blocks now, but still `GetDebugState` after |
| Forget to check state after user says "paused" | Immediately `GetDebugState` |
| Read memory at wrong address | `EvalExpression` to resolve symbols first |
| Use `DisassembleFunction` without analysis | `AnalyzeCode` with type=function first, or `ExecuteDebuggerCommand` with `analr <address>` |
| Set breakpoint on symbol without resolving | `SearchSymbols` or `EvalExpression` to get actual address |
| Lose track of which binary is loaded | `GetDebugState` tells you, `ListModules` for full list |
| Pass MCP tool name to `ExecuteDebuggerCommand` | Call the tool directly — `ExecuteDebuggerCommand` rejects MCP tool names |
| Use `erun` to blindly pass all exceptions | Use `SetExceptionBreakpoint` for selective exception handling |
| Go idle while user interacts with GUI | Call `WaitForEvent` with longer timeout (60-120s) to watch for events |

---

## Rule 6: Expression Evaluation

Use `EvalExpression` to resolve anything:
- Symbols: `kernel32:CreateFileA`, `ntdll:NtAllocateVirtualMemory`
- Registers: `cip`, `rax`, `esp+4`, `[rsp+0x28]`
- Arithmetic: `rax+0x10`, `modulebase+0x1000`
- Labels: any label set with `CommentOrLabelAtAddress`

---

## Rule 7: Explain What You See

When analyzing code, always tell the user:
- What address and module you're looking at
- What the instructions do in plain language
- What the registers/stack suggest about arguments and state
- What the call stack context means

Reference concrete addresses and module names — never say "the current function" without saying which one.

---

## Rule 8: Debugging GUI / Message Loop Apps

When the target is RUNNING in a message loop (waiting for user input, showing a dialog, sitting at a UI screen), `run` will time out because no breakpoint is being hit. Do NOT fall back to static file analysis — use the debugger properly.

Strategies:
- **PauseDebug** — pause the target at any time, inspect state, then resume. The app freezes briefly but you get full debugger access.
- **Set API breakpoints before resuming** — breakpoint on APIs the app will call when the user interacts (e.g. `GetMessageA`, `SendMessageA`, `CreateFileA`, `ReadFile`, button handlers). The target pauses when the user triggers that code path.
- **WaitForEvent with long timeout** — if the user is about to interact with the GUI, call `WaitForEvent(timeoutMs: 120000)` to watch for breakpoint hits or exceptions while they click around.
- **SetBreakpointFastResume + SetBreakpointCommand** — for logging without pausing: set a BP with a log command and fast resume. The target keeps running while you collect data.
- **Hardware breakpoints on data** — if you know which memory the app reads/writes when the user acts, set a hardware BP on it. The target pauses when that memory is accessed.

Never give up and read the binary file from disk. The debugger can always pause, inspect, and resume.
