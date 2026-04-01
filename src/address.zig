const std = @import("std");
const transparent = @import("transparent.zig");
const sapling = @import("sapling.zig");
const unified = @import("unified.zig");

pub const Network = enum { mainnet, testnet };

pub const AddressError = error{
    UnknownAddressType,
    BufferTooSmall,
    InvalidAddress,
};

pub const Address = union(enum) {
    transparent_p2pkh: transparent.TransparentAddress,
    transparent_p2sh: transparent.TransparentAddress,
    sapling: sapling.SaplingAddress,
    unified: unified.UnifiedAddress,

    pub fn decode(allocator: std.mem.Allocator, input: []const u8) !Address {
        if (std.mem.startsWith(u8, input, "u1") or std.mem.startsWith(u8, input, "utest")) {
            const ua = try unified.UnifiedAddress.decode(allocator, input);
            return .{ .unified = ua };
        }
        if (std.mem.startsWith(u8, input, "zs") or std.mem.startsWith(u8, input, "ztestsapling")) {
            return .{ .sapling = try sapling.SaplingAddress.decode(input) };
        }
        if (std.mem.startsWith(u8, input, "t")) {
            const t = try transparent.TransparentAddress.decode(input);
            return switch (t.addr_type) {
                .p2pkh => .{ .transparent_p2pkh = t },
                .p2sh => .{ .transparent_p2sh = t },
            };
        }
        return error.UnknownAddressType;
    }

    pub fn encode(self: Address, allocator: std.mem.Allocator, out: []u8) !usize {
        return switch (self) {
            .transparent_p2pkh => |t| t.encode(out),
            .transparent_p2sh => |t| t.encode(out),
            .sapling => |s| s.encode(out),
            .unified => |u| u.encode(allocator, out),
        };
    }

    pub fn network(self: Address) Network {
        return switch (self) {
            .transparent_p2pkh => |t| @enumFromInt(@intFromEnum(t.network)),
            .transparent_p2sh => |t| @enumFromInt(@intFromEnum(t.network)),
            .sapling => |s| @enumFromInt(@intFromEnum(s.network)),
            .unified => |u| @enumFromInt(@intFromEnum(u.network)),
        };
    }

    pub fn typeName(self: Address) []const u8 {
        return switch (self) {
            .transparent_p2pkh => "transparent_p2pkh",
            .transparent_p2sh => "transparent_p2sh",
            .sapling => "sapling",
            .unified => "unified",
        };
    }
};

test "decode one of each type and check tag" {
    const T1 = "t1KzZ5n2TPEGYXTZ3WYGL1AYEumEQaRoHaL";
    const ZS = "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9slya";
    var rs = std.BoundedArrayAligned(unified.Receiver, 4, unified.MAX_RECEIVERS){};
    try rs.append(.{ .sapling = [_]u8{0x11} ** 43 });
    const ua_obj = unified.UnifiedAddress{ .network = .mainnet, .receivers = rs };
    var ua_buf: [600]u8 = undefined;
    const ua_len = try ua_obj.encode(std.testing.allocator, ua_buf[0..]);
    const a1 = try Address.decode(std.testing.allocator, T1);
    const a2 = try Address.decode(std.testing.allocator, ZS);
    const a3 = try Address.decode(std.testing.allocator, ua_buf[0..ua_len]);
    try std.testing.expectEqualStrings("transparent_p2pkh", a1.typeName());
    try std.testing.expectEqualStrings("sapling", a2.typeName());
    try std.testing.expectEqualStrings("unified", a3.typeName());
}

test "network returns correct value" {
    const T1 = "t1KzZ5n2TPEGYXTZ3WYGL1AYEumEQaRoHaL";
    const ZS = "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9slya";
    var rs = std.BoundedArrayAligned(unified.Receiver, 4, unified.MAX_RECEIVERS){};
    try rs.append(.{ .sapling = [_]u8{0x22} ** 43 });
    const ua_obj = unified.UnifiedAddress{ .network = .testnet, .receivers = rs };
    var ua_buf: [600]u8 = undefined;
    const ua_len = try ua_obj.encode(std.testing.allocator, ua_buf[0..]);
    const a1 = try Address.decode(std.testing.allocator, T1);
    const a2 = try Address.decode(std.testing.allocator, ZS);
    const a3 = try Address.decode(std.testing.allocator, ua_buf[0..ua_len]);
    try std.testing.expectEqual(Network.mainnet, a1.network());
    try std.testing.expectEqual(Network.mainnet, a2.network());
    try std.testing.expectEqual(Network.testnet, a3.network());
}

test "unknown prefix returns error" {
    try std.testing.expectError(error.UnknownAddressType, Address.decode(std.testing.allocator, "xyz123"));
}
