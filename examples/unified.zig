const std = @import("std");
const zcash = @import("zcash_addr");

pub fn main() !void {
    const input = "utest10ne56d9j9rf8j0a7cq8uyfgxhywhthfegz6qkml7c9yxhm785fxv8fwnppfuaujnxglz7lq9";
    const addr = try zcash.unified.UnifiedAddress.decode(std.heap.page_allocator, input);

    var out: [800]u8 = undefined;
    const n = try addr.encode(std.heap.page_allocator, out[0..]);

    const stdout = std.io.getStdOut().writer();
    try stdout.print("input         : {s}\n", .{input});
    try stdout.print("network       : {s}\n", .{if (addr.network == .mainnet) "mainnet" else "testnet"});
    try stdout.print("known receivers: {d}\n", .{addr.receivers.len});
    try stdout.print("re-encoded    : {s}\n", .{out[0..n]});
}
