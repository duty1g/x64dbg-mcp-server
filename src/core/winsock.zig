// Minimal Winsock 2 declarations.
//
// The Zig standard library moved its Winsock bindings between releases:
// 0.14 exposes them as std.os.windows.ws2_32, 0.17 dropped them from the
// standard library altogether.  The plugin only needs a handful of entry
// points, so it declares them itself — the ABI is fixed by Windows, not by
// the Zig version, and this keeps one source building under both.

pub const SOCKET = usize; // UINT_PTR
pub const INVALID_SOCKET: SOCKET = @bitCast(@as(isize, -1));

pub const WSADATA = extern struct {
    version: u16,
    high_version: u16,
    max_sockets: u16,
    max_udp_dg: u16,
    reserved: [4]u8,
};

pub const AF_INET: u16 = 2;
pub const SOCK_STREAM: i32 = 1;
pub const SOL_SOCKET: i32 = 0xffff;
pub const SO_REUSEADDR: i32 = 4;

/// struct sockaddr_in — 16 bytes, little-endian.
pub const SOCKADDR_IN = extern struct {
    family: u16,
    port: u16, // network byte order
    addr: u32, // network byte order
    zero: [8]u8 = @splat(0),
};

pub extern "ws2_32" fn WSAStartup(version: u16, data: *WSADATA) callconv(.winapi) i32;
pub extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;
pub extern "ws2_32" fn socket(af: i32, sock_type: i32, protocol: i32) callconv(.winapi) SOCKET;
pub extern "ws2_32" fn bind(sock: SOCKET, addr: *const SOCKADDR_IN, name_len: c_int) callconv(.winapi) i32;
pub extern "ws2_32" fn listen(sock: SOCKET, backlog: i32) callconv(.winapi) i32;
pub extern "ws2_32" fn accept(sock: SOCKET, addr: ?*anyopaque, addr_len: ?*u32) callconv(.winapi) SOCKET;
pub extern "ws2_32" fn closesocket(sock: SOCKET) callconv(.winapi) i32;
pub extern "ws2_32" fn send(sock: SOCKET, buf: [*]const u8, len: i32, flags: i32) callconv(.winapi) i32;
pub extern "ws2_32" fn recv(sock: SOCKET, buf: [*]u8, len: i32, flags: i32) callconv(.winapi) i32;
pub extern "ws2_32" fn setsockopt(sock: SOCKET, level: i32, opt_name: i32, opt_val: *const anyopaque, opt_len: c_int) callconv(.winapi) i32;
pub extern "ws2_32" fn htons(value: u16) callconv(.winapi) u16;
