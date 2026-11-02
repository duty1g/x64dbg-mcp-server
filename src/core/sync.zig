// Threading primitives.
//
// The plugin runs inside x64dbg.  The HTTP server thread and one thread
// per connection run concurrently with x64dbg's debugger callbacks, so
// every structure the two sides share needs a lock.
//
// std.Thread.Mutex was removed in Zig 0.17 and is not part of the 0.14
// API the plugin is also built with, so the lock is a thin wrapper around
// the Win32 SRWLOCK: it exists in every Windows version the plugin
// supports, needs no dynamic initialisation, and behaves identically
// under both Zig releases.

extern "kernel32" fn InitializeSRWLock(psrwlock: *SRWLOCK) callconv(.winapi) void;
extern "kernel32" fn AcquireSRWLockExclusive(psrwlock: *SRWLOCK) callconv(.winapi) void;
extern "kernel32" fn ReleaseSRWLockExclusive(psrwlock: *SRWLOCK) callconv(.winapi) void;

/// struct _SRWLOCK { PVOID Ptr; }
pub const SRWLOCK = extern struct {
    ptr: ?*anyopaque,
};

pub const SRWLOCK_INIT = SRWLOCK{ .ptr = null };

/// An exclusive, non-recursive lock.
pub const Mutex = struct {
    srw: SRWLOCK = SRWLOCK_INIT,

    /// Initialise the lock.  A lock that was never initialised is
    /// already in SRWLOCK_INIT state, so this only matters when a lock
    /// is re-used after it was torn down.
    pub fn init(self: *Mutex) void {
        InitializeSRWLock(&self.srw);
    }

    pub fn lock(self: *Mutex) void {
        AcquireSRWLockExclusive(&self.srw);
    }

    pub fn unlock(self: *Mutex) void {
        ReleaseSRWLockExclusive(&self.srw);
    }
};
