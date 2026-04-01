const std = @import("std");
const zcash = @import("zcash_addr");

pub fn main() !void {
    const input = "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9slya";
    const addr = try zcash.sapling.SaplingAddress.decode(input);

    var out: [256]u8 = undefined;
    const n = try addr.encode(out[0..]);

    const stdout = std.io.getStdOut().writer();
    try stdout.print("input      : {s}\n", .{input});
    try stdout.print("network    : {s}\n", .{if (addr.network == .mainnet) "mainnet" else "testnet"});
    try stdout.print("payload len: {d}\n", .{addr.payload().len});
    try stdout.print("re-encoded : {s}\n", .{out[0..n]});
}
