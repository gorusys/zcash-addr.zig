const std = @import("std");
const zcash = @import("zcash_addr");

pub fn main() !void {
    const input = "t1KzZ5n2TPEGYXTZ3WYGL1AYEumEQaRoHaL";
    const addr = try zcash.transparent.TransparentAddress.decode(input);

    var out: [128]u8 = undefined;
    const n = try addr.encode(out[0..]);

    const stdout = std.io.getStdOut().writer();
    try stdout.print("input      : {s}\n", .{input});
    try stdout.print("network    : {s}\n", .{if (addr.network == .mainnet) "mainnet" else "testnet"});
    try stdout.print("type       : {s}\n", .{if (addr.addr_type == .p2pkh) "p2pkh" else "p2sh"});
    try stdout.print("re-encoded : {s}\n", .{out[0..n]});
}
