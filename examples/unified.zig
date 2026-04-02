const std = @import("std");
const zcash = @import("zcash_addr");

pub fn main() !void {
    const input = "utest15t0mmwzmc3jzl2hms7nem630wkm397tft82afwsl30zzxdxcrnjj9rg4e0uf2rusk0r9jjh00gtkxs7amcz385qqhe6c44rlqyhmwhme";
    const addr = try zcash.unified.UnifiedAddress.decode(std.heap.page_allocator, input);

    var out: [800]u8 = undefined;
    const n = try addr.encode(std.heap.page_allocator, out[0..]);

    const stdout = std.io.getStdOut().writer();
    try stdout.print("input         : {s}\n", .{input});
    try stdout.print("network       : {s}\n", .{if (addr.network == .mainnet) "mainnet" else "testnet"});
    try stdout.print("receivers: {d}\n", .{addr.receivers.len});
    try stdout.print("re-encoded    : {s}\n", .{out[0..n]});
}
