const std = @import("std");
const bech32 = @import("bech32.zig");

pub const Network = enum { mainnet, testnet };

pub const SaplingError = error{
    InvalidHrp,
    InvalidLength,
    BufferTooSmall,
    TooShort,
    TooLong,
    NoSeparator,
    InvalidChar,
    InvalidChecksum,
    MixedCase,
    InvalidPadding,
};

fn hrpForNetwork(network: Network) []const u8 {
    return switch (network) {
        .mainnet => "zs",
        .testnet => "ztestsapling",
    };
}

pub const SaplingAddress = struct {
    network: Network,
    diversifier: [11]u8,
    pk_d: [32]u8,

    pub fn payload(self: SaplingAddress) [43]u8 {
        var p: [43]u8 = undefined;
        @memcpy(p[0..11], self.diversifier[0..]);
        @memcpy(p[11..43], self.pk_d[0..]);
        return p;
    }

    pub fn encode(self: SaplingAddress, out: []u8) SaplingError!usize {
        const hrp = hrpForNetwork(self.network);
        const p = self.payload();
        return bech32.encode(hrp, p[0..], .bech32, out) catch |err| switch (err) {
            error.HrpTooLong => error.TooLong,
            error.DataTooLong => error.BufferTooSmall,
            error.InvalidChar => error.InvalidChar,
        };
    }

    pub fn decode(input: []const u8) SaplingError!SaplingAddress {
        var payload_buf: [64]u8 = undefined;
        const res = bech32.decode(input, .bech32, payload_buf[0..]) catch |err| switch (err) {
            error.TooShort => return error.TooShort,
            error.TooLong => return error.TooLong,
            error.NoSeparator => return error.NoSeparator,
            error.InvalidChar => return error.InvalidChar,
            error.InvalidChecksum => return error.InvalidChecksum,
            error.MixedCase => return error.MixedCase,
            error.InvalidPadding => return error.InvalidPadding,
        };
        if (res.data_len != 43) return error.InvalidLength;

        var hrp_lc: [16]u8 = [_]u8{0} ** 16;
        if (res.hrp_len > hrp_lc.len) return error.InvalidHrp;
        for (input[0..res.hrp_len], 0..) |c, i| hrp_lc[i] = std.ascii.toLower(c);

        const network: Network = if (std.mem.eql(u8, hrp_lc[0..res.hrp_len], "zs"))
            .mainnet
        else if (std.mem.eql(u8, hrp_lc[0..res.hrp_len], "ztestsapling"))
            .testnet
        else
            return error.InvalidHrp;

        var d: [11]u8 = undefined;
        var pkd: [32]u8 = undefined;
        @memcpy(d[0..], payload_buf[0..11]);
        @memcpy(pkd[0..], payload_buf[11..43]);
        return .{ .network = network, .diversifier = d, .pk_d = pkd };
    }
};

test "known mainnet sapling address round-trip" {
    const s = "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9slya";
    const addr = try SaplingAddress.decode(s);
    try std.testing.expectEqual(Network.mainnet, addr.network);
    var out: [256]u8 = undefined;
    const n = try addr.encode(out[0..]);
    try std.testing.expectEqualSlices(u8, s, out[0..n]);
}

test "wrong hrp returns InvalidHrp" {
    const good = "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9slya";
    var payload: [64]u8 = undefined;
    const d = try bech32.decode(good, .bech32, payload[0..]);
    var bad: [256]u8 = undefined;
    const n = try bech32.encode("bc", payload[0..d.data_len], .bech32, bad[0..]);
    try std.testing.expectError(error.InvalidHrp, SaplingAddress.decode(bad[0..n]));
}

test "wrong payload length returns InvalidLength" {
    var out: [128]u8 = undefined;
    const n = try bech32.encode("zs", "short", .bech32, out[0..]);
    try std.testing.expectError(error.InvalidLength, SaplingAddress.decode(out[0..n]));
}
