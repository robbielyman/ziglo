/// partial Zig interface to liblo's OSC implementation
/// full C API is available via `c`.
pub const c = @import("c.zig").c;
const std = @import("std");
const assert = std.debug.assert;

// FIXME: more refined errors would be nice
pub const Err = error{LibloFailure};

pub const LoType = enum { infinity, nil };

/// if you have a server, it is likely preferable / faster to call its `send` method
pub fn sendMessage(target: *Address, path: [*:0]const u8, msg: *Message) Err!void {
    try unwrap(c.lo_send_message(@ptrCast(target), path, @ptrCast(msg)));
}

/// returns `true` on a match
pub fn patternMatch(string: [*:0]const u8, against: [*:0]const u8) bool {
    return c.lo_pattern_match(string, against) != 0;
}

inline fn unwrap(err: c_int) Err!void {
    if (err < 0) return error.LibloFailure;
}

pub const Message = opaque {
    /// creates a new message; destroy with `free`.
    pub fn new() ?*Message {
        return @ptrCast(c.lo_message_new());
    }

    /// adds one to the reference count of this message
    /// decrement with `free`.
    pub fn incRef(self: *Message) void {
        c.lo_message_incref(@ptrCast(self));
    }

    /// deserialise a message from a slice of bytes
    /// destroy the returned message with `free`.
    pub fn deserialise(bytes: []u8) Err!*Message {
        const ptr = c.lo_message_deserialise(bytes.ptr, bytes.len, null) orelse return error.LibloFailure;
        return @ptrCast(ptr);
    }

    /// allocate an appropriately-sized buffer and serialize the message into it
    pub fn serialiseAlloc(self: *Message, path: [*:0]const u8, allocator: std.mem.Allocator) (error{OutOfMemory} || Err)![]u8 {
        const len = self.length(path);
        const bytes = try allocator.alloc(u8, len);
        errdefer allocator.free(bytes);
        _ = c.lo_message_serialise(@ptrCast(self), path, bytes.ptr, null) orelse return error.LibloFailure;
        return bytes;
    }

    /// serialize message into a buffer
    /// returns a slice from `buf` representing the message
    pub fn serialise(self: *Message, path: [*:0]const u8, buf: []u8) Err![]u8 {
        var size = buf.len;
        const ptr: [*]u8 = @ptrCast(c.lo_message_serialise(@ptrCast(self), path, buf.ptr, &size) orelse return error.LibloFailure);
        return ptr[0..size];
    }

    /// destroys a message created with `new`.
    pub fn free(self: *Message) void {
        c.lo_message_free(@ptrCast(self));
    }

    /// clones a message from an old one; destroy with `free`.
    pub fn clone(other: *Message) ?*Message {
        return @ptrCast(c.lo_message_clone(@ptrCast(other)));
    }

    /// add a slice of one or more arguments to the message
    pub fn addSlice(self: *Message, comptime T: type, args: []const T) Err!void {
        for (0..args.len) |i| {
            switch (T) {
                i32 => try unwrap(c.lo_message_add_int32(@ptrCast(self), args[i])),
                i64 => try unwrap(c.lo_message_add_int64(@ptrCast(self), args[i])),
                f32 => try unwrap(c.lo_message_add_float(@ptrCast(self), args[i])),
                f64 => try unwrap(c.lo_message_add_double(@ptrCast(self), args[i])),
                [:0]u8, [:0]const u8 => try unwrap(c.lo_message_add_string(@ptrCast(self), args[i].ptr)),
                [*:0]u8, [*:0]const u8 => try unwrap(c.lo_message_add_string(@ptrCast(self), args[i])),
                Blob => try unwrap(c.lo_message_add_blob(@ptrCast(self), args[i])),
                u8 => try unwrap(c.lo_message_add_char(@ptrCast(self), args[i])),
                bool => if (args[i]) try unwrap(c.lo_message_add_true(@ptrCast(self))) else try unwrap(c.lo_message_add_false(@ptrCast(self))),
                [4]u8 => try unwrap(c.lo_message_add_midi(@ptrCast(self), &args[i])),
                LoType => switch (args[i]) {
                    .infinity => try unwrap(c.lo_message_add_infinitum(@ptrCast(self))),
                    .nil => try unwrap(c.lo_message_add_nil(@ptrCast(self))),
                },
                @TypeOf(null) => try unwrap(c.lo_message_add_nil(@ptrCast(self))),
                comptime_int => {
                    const as_i32: i32 = @intCast(args[i]);
                    try unwrap(c.lo_message_add_int32(@ptrCast(self), as_i32));
                },
                comptime_float => {
                    const as_f32: f32 = @floatCast(args[i]);
                    try unwrap(c.lo_message_add_float(@ptrCast(self), as_f32));
                },
                @TypeOf(.enum_literal) => {
                    if (args[i] == .infinity) try unwrap(c.lo_message_add_infinitum(@ptrCast(self)));
                    if (args[i] == .nil) try unwrap(c.lo_message_add_nil(@ptrCast(self)));
                    if (args[i] != .infinity and args[i] != .nil) @compileError("Message.add called with unexpected enum literal: " ++ @tagName(args[i]) ++ "!");
                },
                else => @compileError("Message.add called with unsupported type: '" ++ @typeName(T) ++ "'!"),
            }
        }
    }

    /// add a tuple of one or more arguments to the message
    /// will attempt to add integer and float literals as i32 and f32, respectively
    pub fn add(self: *Message, args: anytype) Err!void {
        const info = @typeInfo(@TypeOf(args));
        comptime {
            assert(info == .Struct);
            assert(info.Struct.is_tuple);
            assert(info.Struct.fields.len > 0);
        }
        inline for (info.Struct.fields, 0..) |arg, i| {
            const arg_info = @typeInfo(@TypeOf(args[i]));
            if (arg_info == .Pointer) {
                const child = @typeInfo(arg_info.Pointer.child);
                if (child == .Array and child.Array.child == u8) {
                    const slice: [:0]const u8 = args[i];
                    try unwrap(c.lo_message_add_string(@ptrCast(self), slice.ptr));
                    continue;
                }
            }
            switch (arg.type) {
                i32 => try unwrap(c.lo_message_add_int32(@ptrCast(self), args[i])),
                i64 => try unwrap(c.lo_message_add_int64(@ptrCast(self), args[i])),
                f32 => try unwrap(c.lo_message_add_float(@ptrCast(self), args[i])),
                f64 => try unwrap(c.lo_message_add_double(@ptrCast(self), args[i])),
                [:0]u8, [:0]const u8 => try unwrap(c.lo_message_add_string(@ptrCast(self), args[i].ptr)),
                [*:0]u8, [*:0]const u8 => try unwrap(c.lo_message_add_string(@ptrCast(self), args[i])),
                Blob => try unwrap(c.lo_message_add_blob(@ptrCast(self), args[i])),
                u8 => try unwrap(c.lo_message_add_char(@ptrCast(self), args[i])),
                bool => if (args[i]) try unwrap(c.lo_message_add_true(@ptrCast(self))) else try unwrap(c.lo_message_add_false(@ptrCast(self))),
                [4]u8 => try unwrap(c.lo_message_add_midi(@ptrCast(self), &args[i])),
                LoType => switch (args[i]) {
                    .infinity => try unwrap(c.lo_message_add_infinitum(@ptrCast(self))),
                    .nil => try unwrap(c.lo_message_add_nil(@ptrCast(self))),
                },
                @TypeOf(null) => try unwrap(c.lo_message_add_nil(@ptrCast(self))),
                comptime_int => {
                    const as_i32: i32 = @intCast(args[i]);
                    try unwrap(c.lo_message_add_int32(@ptrCast(self), as_i32));
                },
                comptime_float => {
                    const as_f32: f32 = @floatCast(args[i]);
                    try unwrap(c.lo_message_add_float(@ptrCast(self), as_f32));
                },
                @TypeOf(.enum_literal) => {
                    if (args[i] == .infinity) try unwrap(c.lo_message_add_infinitum(@ptrCast(self)));
                    if (args[i] == .nil) try unwrap(c.lo_message_add_nil(@ptrCast(self)));
                    if (args[i] != .infinity and args[i] != .nil) @compileError("Message.add called with unexpected enum literal: " ++ @tagName(args[i]) ++ "!");
                },
                else => @compileError("Message.add called with unsupported type: '" ++ @typeName(arg.type) ++ "'!"),
            }
        }
    }

    pub const GetArgErr = Err || error{ BadType, OutOfBounds };
    pub fn getArg(self: *Message, comptime T: type, index: usize) GetArgErr!T {
        const len = self.argCount();
        if (index >= len) return error.OutOfBounds;
        const msg_types = self.types() orelse return error.LibloFailure;
        const args = self.argValues() orelse return error.LibloFailure;
        const kind = msg_types[index];
        switch (T) {
            i32 => {
                const arg = args[index] orelse return error.LibloFailure;
                if (kind != 'i') return error.BadType;
                return arg.i;
            },
            i64 => {
                const arg = args[index] orelse return error.LibloFailure;
                if (kind != 'h') {
                    if (kind != 'i') return error.BadType;
                    return arg.i;
                }
                return arg.h;
            },
            f32 => {
                const arg = args[index] orelse return error.LibloFailure;
                if (kind != 'f') {
                    if (kind != 'd') return error.BadType;
                    return @floatCast(arg.d);
                }
                return arg.f;
            },
            f64 => {
                const arg = args[index] orelse return error.LibloFailure;
                if (kind != 'd') {
                    if (kind != 'f') return error.BadType;
                    return @floatCast(arg.f);
                }
                return arg.d;
            },
            [*:0]const u8, [*]const u8 => {
                const arg = args[index] orelse return error.LibloFailure;
                if (kind != 's') {
                    if (kind != 'S') return error.BadType;
                    return @ptrCast(&arg.S);
                }
                return @ptrCast(&arg.s);
            },
            [:0]const u8 => {
                const arg = args[index] orelse return error.LibloFailure;
                if (kind != 's') {
                    if (kind != 'S') return error.BadType;
                    const ptr: [*:0]const u8 = @ptrCast(&arg.S);
                    return std.mem.sliceTo(ptr, 0);
                }
                const ptr: [*:0]const u8 = @ptrCast(&arg.s);
                return std.mem.sliceTo(ptr, 0);
            },
            []const u8 => {
                const arg = args[index] orelse return error.LibloFailure;
                if (kind != 's' and kind != 'S') {
                    if (kind != 'b') return error.BadType;
                    const blob: *Blob = @ptrCast(&arg.blob);
                    return blob.data() orelse return error.LibloFailure;
                } else {
                    const ptr: [*:0]const u8 = @ptrCast(if (kind == 'S') &arg.S else &arg.s);
                    return std.mem.sliceTo(ptr, 0);
                }
            },
            [4]u8 => {
                const arg = args[index] orelse return error.LibloFailure;
                if (kind != 'm') return error.BadType;
                return arg.m;
            },
            u8 => {
                const arg = args[index] orelse return error.LibloFailure;
                if (kind != 'c') return error.BadType;
                return arg.c;
            },
            LoType => {
                if (kind != 'N') {
                    if (kind != 'I') return error.BadType;
                    return @as(LoType, .infinity);
                }
                return @as(LoType, .nil);
            },
            bool => {
                if (kind == 'T') return true;
                if (kind == 'F') return false;
                return error.BadType;
            },
            else => @compileError("Message.getArg called with unsupported type: '" ++ @typeName(T) ++ "'"),
        }
    }

    /// caller does not own memory
    /// if the message is outgoing, source will be `null`.
    pub fn source(self: *Message) ?*Address {
        return @ptrCast(c.lo_message_get_source(@ptrCast(self)));
    }

    /// invalidated by calls to `add`.
    pub fn types(self: *Message) ?[*:0]const u8 {
        return c.lo_message_get_types(@ptrCast(self));
    }

    pub fn argCount(self: *Message) usize {
        return @intCast(c.lo_message_get_argc(@ptrCast(self)));
    }

    /// invalidated by calls to `add`.
    /// caller does not own memory
    pub fn argValues(self: *Message) ?[*]?*c.lo_arg {
        return c.lo_message_get_argv(@ptrCast(self));
    }

    /// byte length of a message
    pub fn length(self: *Message, path: [*:0]const u8) usize {
        return c.lo_message_length(@ptrCast(self), path);
    }

    test Message {
        std.testing.refAllDecls(Message);
    }
};

// TODO: add more of the low-level networking stuff?
pub const Address = opaque {
    /// creates a new address, to be destroyed with `free`
    pub fn new(host: [*:0]const u8, port_number: [*:0]const u8) ?*Address {
        return @ptrCast(c.lo_address_new(host, port_number));
    }

    /// destroys an address created with `free`
    pub fn free(self: *Address) void {
        c.lo_address_free(@ptrCast(self));
    }

    /// caller does not own returned memory
    /// value will be a dotted quad, colon'd IPV6 address or resolvable name
    pub fn getHostname(self: *Address) ?[*:0]const u8 {
        return c.lo_address_get_hostname(@ptrCast(self));
    }

    /// caller does not own returned memory
    /// returned value will be a service name or ASCII representation of port number
    pub fn getPort(self: *Address) ?[*:0]const u8 {
        return c.lo_address_get_port(@ptrCast(self));
    }

    test Address {
        const addr = Address.new("localhost", "0001").?;
        defer addr.free();
        try std.testing.expectEqualStrings("localhost", std.mem.sliceTo(addr.getHostname().?, 0));
        try std.testing.expectEqualStrings("0001", std.mem.sliceTo(addr.getPort().?, 0));
    }
};

pub const CErrHandler = fn (c_int, [*c]const u8, [*c]const u8) callconv(.C) void;
pub const ErrHandler = fn (num: i32, msg: ?[*:0]const u8, path: ?[*:0]const u8) void;

pub const CMethodHandler = fn (path: [*c]const u8, types: [*c]const u8, argv: [*c][*c]c.lo_arg, argc: c_int, msg: c.lo_message, user_data: ?*anyopaque) callconv(.C) c_int;
pub const MethodHandler = fn (path: [:0]const u8, typespec: []const u8, msg: *Message, ctx: ?*anyopaque) bool;

pub fn wrap(comptime function: anytype) WrapType(@TypeOf(function)) {
    return switch (@TypeOf(function)) {
        ErrHandler => wrapErrHandler(function),
        MethodHandler => wrapMethodHandler(function),
        else => @compileError("unsupported type " ++ @typeName(@TypeOf(function))),
    };
}

fn wrapErrHandler(comptime function: ErrHandler) CErrHandler {
    return struct {
        fn f(num: c_int, msg: [*c]const u8, path: [*c]const u8) callconv(.C) void {
            @call(.always_inline, function, .{ @as(i32, @intCast(num)), msg, path });
        }
    }.f;
}

fn wrapMethodHandler(comptime function: MethodHandler) CMethodHandler {
    return struct {
        fn f(
            path: [*c]const u8,
            types: [*c]const u8,
            _: [*c][*c]c.lo_arg,
            argc: c_int,
            msg: c.lo_message,
            user_data: ?*anyopaque,
        ) callconv(.C) c_int {
            const path_ptr: [*:0]const u8 = path.?;
            const types_ptr: [*:0]const u8 = types.?;
            const count: usize = @intCast(argc);
            return if (@call(.always_inline, function, .{
                std.mem.sliceTo(path_ptr, 0),
                types_ptr[0..count],
                @as(*Message, @ptrCast(msg.?)),
                user_data,
            })) 1 else 0;
        }
    }.f;
}

pub fn WrapType(comptime F: type) type {
    return switch (F) {
        ErrHandler => CErrHandler,
        MethodHandler => CMethodHandler,
        else => @compileError("unsupported type " ++ @typeName(F)),
    };
}

pub const Server = opaque {
    /// creates a new server instance
    /// passing `null` for the port means the server will choose an unused UDP port
    /// pass `null` for error handler if you do not want error handling
    pub fn new(port: ?[*:0]const u8, err_handler: ?*const CErrHandler) ?*Server {
        return @ptrCast(c.lo_server_new(port, err_handler));
    }

    /// frees up memory
    pub fn free(self: *Server) void {
        c.lo_server_free(@ptrCast(self));
    }

    /// enables or disables type coercion during message dispatch
    /// returns the previous value
    pub fn toggleCoercion(self: *Server, enable: bool) bool {
        return c.lo_server_enable_coercion(@ptrCast(self), if (enable) 1 else 0) != 0;
    }

    /// wait for an OSC message to be received
    /// the return value indicates whether there is a message waiting
    pub fn wait(self: *Server, timeout_ms: u32) bool {
        return c.lo_server_wait(@ptrCast(self), @intCast(timeout_ms)) > 0;
    }

    /// block, waiting for an OSC message to be received
    /// the return value is the message size in bytes
    /// the message will be dispatched to a matching method if one is found
    pub fn receive(self: *Server) Err!usize {
        const err = c.lo_server_recv(@ptrCast(self));
        try unwrap(err);
        return @intCast(err);
    }

    /// sends a message to the specified address with the given path
    pub fn send(self: *Server, target: *Address, path: [*:0]const u8, msg: *Message) Err!void {
        try unwrap(c.lo_send_message_from(@ptrCast(target), @ptrCast(self), path, @ptrCast(msg)));
    }

    /// adds an OSC method to the server
    /// `path`: an OSC path or `null` to match all paths
    /// `typespec`: the method accepts; incoming messages will be coerced to the typespec given here
    /// `h`: the handler function that will be called if a matching message is received
    /// `user_data`: a value passed to the callback function
    /// returns an opaque pointer identifying the method; caller does not own this pointer
    pub fn addMethod(self: *Server, path: ?[*:0]const u8, typespec: ?[*:0]const u8, h: ?*const CMethodHandler, userdata: ?*anyopaque) ?*Method {
        return @ptrCast(c.lo_server_add_method(@ptrCast(self), path, typespec, h, userdata));
    }

    /// deletes all OSC methods which have the given path and typespec from the server
    /// `path`: an OSC path or `null` to match the generic handler
    /// `typespec`: the typespec to match on or `null` to leave unspecified
    pub fn deleteMethodMatching(self: *Server, path: ?[*:0]const u8, typespec: ?[*:0]const u8) void {
        c.lo_server_del_method(@ptrCast(self), path, typespec);
    }

    /// deletes a specific method from the server.
    /// returns false if the method was not found
    pub fn deleteMethod(self: *Server, method: *Method) bool {
        return c.lo_server_del_lo_method(@ptrCast(self), @ptrCast(method)) == 0;
    }

    /// returns the port number of the server.
    pub fn getPort(self: *Server) Err!u32 {
        const port = c.lo_server_get_port(@ptrCast(self));
        try unwrap(port);
        return @intCast(port);
    }

    /// pushes a byte buffer representing a message to the server as if it had received it
    pub fn dispatchData(self: *Server, data: []u8) Err!void {
        try unwrap(c.lo_server_dispatch_data(@ptrCast(self), data.ptr, data.len));
    }

    test Server {
        std.testing.refAllDecls(Server);
        const server = Server.new(null, null).?;
        _ = try server.getPort();
        defer server.free();
        const inner = struct {
            fn setTo13(_: [:0]const u8, _: []const u8, _: *Message, data: ?*anyopaque) bool {
                const ptr: *usize = @ptrCast(@alignCast(data orelse return true));
                ptr.* = 13;
                return false;
            }
        };
        var test_val: usize = 0;
        const method = server.addMethod(null, null, wrap(inner.setTo13), &test_val).?;
        const msg = Message.new().?;
        defer msg.free();
        const bytes = try msg.serialiseAlloc("/test/path", std.testing.allocator);
        defer std.testing.allocator.free(bytes);
        try server.dispatchData(bytes);
        try std.testing.expectEqual(13, test_val);
        try std.testing.expect(server.deleteMethod(method));
    }
};

pub const Method = opaque {};

pub const Blob = opaque {
    /// creates a new blob from the specified bytes
    /// destroy with `free`
    pub fn new(bytes: []const u8) ?*Blob {
        return @ptrCast(c.lo_blob_new(@intCast(bytes.len), bytes.ptr));
    }

    /// destroys a blob
    pub fn free(self: *Blob) void {
        c.lo_blob_free(@ptrCast(self));
    }

    /// returns the valid data represented by the blob
    /// caller does not own returned memory
    pub fn data(self: *Blob) ?[]u8 {
        const ptr: [*]u8 = @ptrCast(c.lo_blob_dataptr(@ptrCast(self)) orelse return null);
        const len: usize = c.lo_blob_datasize(@ptrCast(self));
        return ptr[0..len];
    }

    test Blob {
        const blob = Blob.new("467").?;
        defer blob.free();
        try std.testing.expectEqualStrings("467", blob.data().?);
    }
};

test "message new" {
    const msg = Message.new().?;
    defer msg.free();
    try msg.add(.{ 4, 4.5, "hey, hi, hello!", .infinity, .nil, null, false, true });
    try std.testing.expectEqualStrings("ifsINNFT", std.mem.sliceTo(msg.types().?, 0));
    try std.testing.expectEqual(8, msg.argCount());
    _ = msg.argValues().?;
    _ = msg.length("/bogus/path");
    try std.testing.expectEqual(4, try msg.getArg(i32, 0));
    try std.testing.expectEqual(4.5, try msg.getArg(f32, 1));
    try std.testing.expectEqual(.infinity, try msg.getArg(LoType, 3));
    try std.testing.expectEqual(.nil, try msg.getArg(LoType, 4));
    try std.testing.expectEqual(.nil, try msg.getArg(LoType, 5));
    try std.testing.expectEqual(false, try msg.getArg(bool, 6));
    try std.testing.expectEqual(true, try msg.getArg(bool, 7));
}

test "ref" {
    std.testing.refAllDecls(@This());
}
