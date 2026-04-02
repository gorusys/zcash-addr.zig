const std = @import("std");
const zcash = @import("zcash_addr");

pub fn main() !void {
    const inputs = [_][]const u8{
        "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ",
        "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9slya",
        "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf",
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
