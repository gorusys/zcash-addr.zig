const std = @import("std");
const base58 = @import("base58.zig");

pub const Network = enum { mainnet, testnet };
pub const AddrType = enum { p2pkh, p2sh };

pub const TransparentError = error{
    InvalidLength,
    InvalidVersion,
    BufferTooSmall,
    InvalidChar,
    InvalidChecksum,
    InputTooShort,
};

fn versionBytes(network: Network, addr_type: AddrType) [2]u8 {
    return switch (network) {
        .mainnet => switch (addr_type) {
            .p2pkh => .{ 0x1C, 0xB8 },
            .p2sh => .{ 0x1C, 0xBD },
        },
        .testnet => switch (addr_type) {
            .p2pkh => .{ 0x1D, 0x25 },
            .p2sh => .{ 0x1C, 0xBA },
        },
    };
}

fn parseVersion(v0: u8, v1: u8) ?struct { network: Network, addr_type: AddrType } {
    if (v0 == 0x1C and v1 == 0xB8) return .{ .network = .mainnet, .addr_type = .p2pkh };
    if (v0 == 0x1C and v1 == 0xBD) return .{ .network = .mainnet, .addr_type = .p2sh };
    if (v0 == 0x1D and v1 == 0x25) return .{ .network = .testnet, .addr_type = .p2pkh };
    if (v0 == 0x1C and v1 == 0xBA) return .{ .network = .testnet, .addr_type = .p2sh };
    return null;
}

pub const TransparentAddress = struct {
    network: Network,
    addr_type: AddrType,
    payload: [20]u8,

    pub fn encode(self: TransparentAddress, out: []u8) TransparentError!usize {
        var raw: [22]u8 = undefined;
        const version = versionBytes(self.network, self.addr_type);
        raw[0] = version[0];
        raw[1] = version[1];
        @memcpy(raw[2..22], self.payload[0..]);
        return base58.encodeCheck(raw[0..], out) catch |err| switch (err) {
            error.BufferTooSmall => error.BufferTooSmall,
        };
    }

    pub fn decode(input: []const u8) TransparentError!TransparentAddress {
        var raw: [64]u8 = undefined;
        const n = base58.decodeCheck(input, raw[0..]) catch |err| switch (err) {
            error.InvalidChar => return error.InvalidChar,
            error.InvalidChecksum => return error.InvalidChecksum,
            error.BufferTooSmall => return error.BufferTooSmall,
            error.InputTooShort => return error.InputTooShort,
        };
        if (n != 22) return error.InvalidLength;
        const parsed = parseVersion(raw[0], raw[1]) orelse return error.InvalidVersion;
        var payload: [20]u8 = undefined;
        @memcpy(payload[0..], raw[2..22]);
        return .{
            .network = parsed.network,
            .addr_type = parsed.addr_type,
            .payload = payload,
        };
    }
};

test "known mainnet transparent p2pkh" {
    const s = "t1KzZ5n2TPEGYXTZ3WYGL1AYEumEQaRoHaL";
    const addr = try TransparentAddress.decode(s);
    try std.testing.expectEqual(Network.mainnet, addr.network);
    try std.testing.expectEqual(AddrType.p2pkh, addr.addr_type);
    var out: [128]u8 = undefined;
    const n = try addr.encode(out[0..]);
    try std.testing.expectEqualSlices(u8, s, out[0..n]);
}

test "known mainnet transparent p2sh" {
    const s = "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ";
    const addr = try TransparentAddress.decode(s);
    try std.testing.expectEqual(Network.mainnet, addr.network);
    try std.testing.expectEqual(AddrType.p2sh, addr.addr_type);
    var out: [128]u8 = undefined;
    const n = try addr.encode(out[0..]);
    try std.testing.expectEqualSlices(u8, s, out[0..n]);
}

test "round trip both networks and types" {
    const inputs = [_]TransparentAddress{
        .{ .network = .mainnet, .addr_type = .p2pkh, .payload = [_]u8{0x11} ** 20 },
        .{ .network = .mainnet, .addr_type = .p2sh, .payload = [_]u8{0x22} ** 20 },
        .{ .network = .testnet, .addr_type = .p2pkh, .payload = [_]u8{0x33} ** 20 },
        .{ .network = .testnet, .addr_type = .p2sh, .payload = [_]u8{0x44} ** 20 },
    };
    for (inputs) |addr| {
        var out: [128]u8 = undefined;
        const n = try addr.encode(out[0..]);
        const parsed = try TransparentAddress.decode(out[0..n]);
        try std.testing.expectEqual(addr.network, parsed.network);
        try std.testing.expectEqual(addr.addr_type, parsed.addr_type);
        try std.testing.expectEqualSlices(u8, addr.payload[0..], parsed.payload[0..]);
    }
}

test "wrong version bytes returns InvalidVersion" {
    var raw: [22]u8 = [_]u8{0} ** 22;
    raw[0] = 0x12;
    raw[1] = 0x34;
    var enc: [128]u8 = undefined;
    const n = try base58.encodeCheck(raw[0..], enc[0..]);
    try std.testing.expectError(error.InvalidVersion, TransparentAddress.decode(enc[0..n]));
}
