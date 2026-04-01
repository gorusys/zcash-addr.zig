const std = @import("std");
const zcash = @import("zcash_addr");

pub fn main() !void {
    const inputs = [_][]const u8{
        "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ",
        "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9slya",
        "u1l9f0l4348negsncgr9pxd9d3qaxagmqv3lnexcplmufpq7muffvfaue6ksevfvd7wrz7xrvn95rc5zjkyes5lg4vdmkz6pvszl7dz0r5ltqtqfqkxrcexstl7lf3tzl8x7xnqhh87xyufvgeu72vvgfr3u7l9d7cxrfxzyvuezd8hzxwfhtn8hrpkfwq25yl6qfzls7awtqejhc3fmgcltvnrk0r",
    };

    const stdout = std.io.getStdOut().writer();
    for (inputs) |input| {
        const a = try zcash.Address.decode(std.heap.page_allocator, input);
        var out: [900]u8 = undefined;
        const n = try a.encode(std.heap.page_allocator, out[0..]);
        try stdout.print("input: {s}\n", .{input});
        try stdout.print("  type   : {s}\n", .{a.typeName()});
        try stdout.print("  network: {s}\n", .{if (a.network() == .mainnet) "mainnet" else "testnet"});
        try stdout.print("  output : {s}\n\n", .{out[0..n]});
    }
}
