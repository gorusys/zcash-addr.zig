pub const address = @import("address.zig");
pub const transparent = @import("transparent.zig");
pub const sapling = @import("sapling.zig");
pub const unified = @import("unified.zig");
pub const bech32 = @import("bech32.zig");
pub const base58 = @import("base58.zig");

pub const Address = address.Address;
pub const Network = address.Network;
pub const Receiver = unified.Receiver;

test {
    std.testing.refAllDecls(@This());
    _ = @import("test_vectors.zig");
}

const std = @import("std");
