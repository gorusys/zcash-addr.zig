const std = @import("std");
const address = @import("address.zig");

const T_P2PKH = "t1KzZ5n2TPEGYXTZ3WYGL1AYEumEQaRoHaL";
const T_P2SH = "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ";
const ZS_1 = "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9slya";
/// From zcash-test-vectors `test-vectors/json/unified_address.json` (account 0, diversifier index 0).
const UA_1 = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";
/// Valid `utest` UA produced by this library (Sapling-only receiver).
const UA_TESTNET = "utest15t0mmwzmc3jzl2hms7nem630wkm397tft82afwsl30zzxdxcrnjj9rg4e0uf2rusk0r9jjh00gtkxs7amcz385qqhe6c44rlqyhmwhme";
test "integration vectors decode encode network typename" {
    const vectors = [_]struct {
        s: []const u8,
        network: address.Network,
        kind: []const u8,
    }{
        .{ .s = T_P2PKH, .network = .mainnet, .kind = "transparent_p2pkh" },
        .{ .s = T_P2SH, .network = .mainnet, .kind = "transparent_p2sh" },
        .{ .s = ZS_1, .network = .mainnet, .kind = "sapling" },
        .{ .s = UA_1, .network = .mainnet, .kind = "unified" },
        .{ .s = UA_TESTNET, .network = .testnet, .kind = "unified" },
    };

    for (vectors) |v| {
        const a = try address.Address.decode(std.testing.allocator, v.s);
        var out: [800]u8 = undefined;
        const n = try a.encode(std.testing.allocator, out[0..]);
        try std.testing.expectEqualSlices(u8, v.s, out[0..n]);
        try std.testing.expectEqual(v.network, a.network());
        try std.testing.expectEqualStrings(v.kind, a.typeName());
    }
}
