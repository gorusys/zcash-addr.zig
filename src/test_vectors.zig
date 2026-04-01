const std = @import("std");
const address = @import("address.zig");

const T_P2PKH = "t1KzZ5n2TPEGYXTZ3WYGL1AYEumEQaRoHaL";
const T_P2SH = "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ";
const ZS_1 = "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9slya";
const UA_1 = "u1l9f0l4348negsncgr9pxd9d3qaxagmqv3lnexcplmufpq7muffvfaue6ksevfvd7wrz7xrvn95rc5zjkyes5lg4vdmkz6pvszl7dz0r5ltqtqfqkxrcexstl7lf3tzl8x7xnqhh87xyufvgeu72vvgfr3u7l9d7cxrfxzyvuezd8hzxwfhtn8hrpkfwq25yl6qfzls7awtqejhc3fmgcltvnrk0r";
const UA_TESTNET = "utest10ne56d9j9rf8j0a7cq8uyfgxhywhthfegz6qkml7c9yxhm785fxv8fwnppfuaujnxglz7lq9";
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
