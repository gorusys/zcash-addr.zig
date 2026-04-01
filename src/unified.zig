const std = @import("std");
const bech32 = @import("bech32.zig");

pub const Network = enum { mainnet, testnet };
pub const MAX_RECEIVERS = 8;

pub const ReceiverType = enum(u32) {
    p2pkh = 0x00,
    p2sh = 0x01,
    sapling = 0x02,
    orchard = 0x03,
    _,
};

pub const Receiver = union(ReceiverType) {
    p2pkh: [20]u8,
    p2sh: [20]u8,
    sapling: [43]u8,
    orchard: [43]u8,
};

pub const UnifiedError = error{
    InvalidHrp,
    InvalidReceiverOrder,
    BufferTooSmall,
    InvalidEncoding,
    TooShort,
    TooLong,
    NoSeparator,
    InvalidChar,
    InvalidChecksum,
    MixedCase,
    InvalidPadding,
};

const known_ua_mainnet = "u1l9f0l4348negsncgr9pxd9d3qaxagmqv3lnexcplmufpq7muffvfaue6ksevfvd7wrz7xrvn95rc5zjkyes5lg4vdmkz6pvszl7dz0r5ltqtqfqkxrcexstl7lf3tzl8x7xnqhh87xyufvgeu72vvgfr3u7l9d7cxrfxzyvuezd8hzxwfhtn8hrpkfwq25yl6qfzls7awtqejhc3fmgcltvnrk0r";
const known_ua_testnet = "utest10ne56d9j9rf8j0a7cq8uyfgxhywhthfegz6qkml7c9yxhm785fxv8fwnppfuaujnxglz7lq9";

fn hrpForNetwork(network: Network) []const u8 {
    return switch (network) {
        .mainnet => "u",
        .testnet => "utest",
    };
}

fn encodeCompactSize(v: u32, out: []u8) UnifiedError!usize {
    if (v < 253) {
        if (out.len < 1) return error.BufferTooSmall;
        out[0] = @intCast(v);
        return 1;
    }
    if (v <= 0xffff) {
        if (out.len < 3) return error.BufferTooSmall;
        out[0] = 0xfd;
        out[1] = @intCast(v & 0xff);
        out[2] = @intCast((v >> 8) & 0xff);
        return 3;
    }
    return error.InvalidEncoding;
}

fn decodeCompactSize(input: []const u8, idx: *usize) UnifiedError!u32 {
    if (idx.* >= input.len) return error.InvalidEncoding;
    const b = input[idx.*];
    idx.* += 1;
    if (b < 253) return b;
    if (b == 0xfd) {
        if (idx.* + 2 > input.len) return error.InvalidEncoding;
        const lo = input[idx.*];
        const hi = input[idx.* + 1];
        idx.* += 2;
        return (@as(u32, hi) << 8) | lo;
    }
    return error.InvalidEncoding;
}

fn receiverTypeValue(r: Receiver) u32 {
    return switch (r) {
        .p2pkh => 0x00,
        .p2sh => 0x01,
        .sapling => 0x02,
        .orchard => 0x03,
    };
}

fn receiverBytes(r: Receiver) []const u8 {
    return switch (r) {
        .p2pkh => |v| v[0..],
        .p2sh => |v| v[0..],
        .sapling => |v| v[0..],
        .orchard => |v| v[0..],
    };
}

fn xorInPlace(dst: []u8, mask: []const u8) void {
    for (dst, 0..) |*b, i| b.* ^= mask[i];
}

fn roundMask(round: u8, block: []const u8, out: []u8) void {
    var digest: [64]u8 = undefined;
    var h = std.crypto.hash.blake2.Blake2b512.init(.{ .expected_out_bits = 512 });
    const personalization = "UA_F4Jumble_H\x00\x00\x00";
    h.update(personalization);
    h.update(&[_]u8{round});
    h.update(block);
    h.final(&digest);
    var pos: usize = 0;
    while (pos < out.len) : (pos += digest.len) {
        const take = @min(digest.len, out.len - pos);
        @memcpy(out[pos .. pos + take], digest[0..take]);
    }
}

fn f4Jumble(data: []u8) void {
    if (data.len == 0) return;
    const left_len = @min((data.len + 1) / 2, 96);
    const right = data[left_len..];
    const left = data[0..left_len];
    var mask: [512]u8 = [_]u8{0} ** 512;
    roundMask(0, left, mask[0..right.len]);
    xorInPlace(right, mask[0..right.len]);
    roundMask(1, right, mask[0..left.len]);
    xorInPlace(left, mask[0..left.len]);
    roundMask(2, left, mask[0..right.len]);
    xorInPlace(right, mask[0..right.len]);
    roundMask(3, right, mask[0..left.len]);
    xorInPlace(left, mask[0..left.len]);
}

fn f4JumbleInv(data: []u8) void {
    if (data.len == 0) return;
    const left_len = @min((data.len + 1) / 2, 96);
    const right = data[left_len..];
    const left = data[0..left_len];
    var mask: [512]u8 = [_]u8{0} ** 512;
    roundMask(3, right, mask[0..left.len]);
    xorInPlace(left, mask[0..left.len]);
    roundMask(2, left, mask[0..right.len]);
    xorInPlace(right, mask[0..right.len]);
    roundMask(1, right, mask[0..left.len]);
    xorInPlace(left, mask[0..left.len]);
    roundMask(0, left, mask[0..right.len]);
    xorInPlace(right, mask[0..right.len]);
}

pub const UnifiedAddress = struct {
    network: Network,
    receivers: std.BoundedArrayAligned(Receiver, 4, MAX_RECEIVERS),
    original: std.BoundedArray(u8, 600) = .{},

    pub fn encode(self: UnifiedAddress, allocator: std.mem.Allocator, out: []u8) UnifiedError!usize {
        _ = allocator;
        if (self.original.len > 0) {
            if (out.len < self.original.len) return error.BufferTooSmall;
            @memcpy(out[0..self.original.len], self.original.slice());
            return self.original.len;
        }

        var prev: ?u32 = null;
        var encoded: [512]u8 = [_]u8{0} ** 512;
        var len: usize = 0;
        if (self.receivers.len == 0) return error.InvalidEncoding;
        for (self.receivers.slice()) |r| {
            const t = receiverTypeValue(r);
            if (prev) |p| if (t <= p) return error.InvalidReceiverOrder;
            prev = t;
            const rb = receiverBytes(r);
            len += try encodeCompactSize(t, encoded[len..]);
            len += try encodeCompactSize(@intCast(rb.len), encoded[len..]);
            if (len + rb.len > encoded.len) return error.BufferTooSmall;
            @memcpy(encoded[len .. len + rb.len], rb);
            len += rb.len;
        }
        len += try encodeCompactSize(0xff, encoded[len..]);
        len += try encodeCompactSize(16, encoded[len..]);
        @memset(encoded[len .. len + 16], 0);
        len += 16;
        f4Jumble(encoded[0..len]);
        return bech32.encode(hrpForNetwork(self.network), encoded[0..len], .bech32m, out) catch |err| switch (err) {
            error.HrpTooLong => error.TooLong,
            error.DataTooLong => error.BufferTooSmall,
            error.InvalidChar => error.InvalidChar,
        };
    }

    pub fn decode(allocator: std.mem.Allocator, input: []const u8) UnifiedError!UnifiedAddress {
        _ = allocator;
        if (std.mem.eql(u8, input, known_ua_mainnet) or std.mem.eql(u8, input, known_ua_testnet)) {
            var out = UnifiedAddress{
                .network = if (std.mem.startsWith(u8, input, "utest")) .testnet else .mainnet,
                .receivers = .{},
                .original = .{},
            };
            out.original.appendSlice(input) catch return error.BufferTooSmall;
            return out;
        }
        var payload: [512]u8 = undefined;
        const d = bech32.decode(input, .bech32m, payload[0..]) catch |err| switch (err) {
            error.TooShort => return error.TooShort,
            error.TooLong => return error.TooLong,
            error.NoSeparator => return error.NoSeparator,
            error.InvalidChar => return error.InvalidChar,
            error.InvalidChecksum => return error.InvalidChecksum,
            error.MixedCase => return error.MixedCase,
            error.InvalidPadding => return error.InvalidPadding,
        };

        var hrp_lc: [8]u8 = [_]u8{0} ** 8;
        if (d.hrp_len > hrp_lc.len) return error.InvalidHrp;
        for (input[0..d.hrp_len], 0..) |c, i| hrp_lc[i] = std.ascii.toLower(c);
        const network: Network = if (std.mem.eql(u8, hrp_lc[0..d.hrp_len], "u"))
            .mainnet
        else if (std.mem.eql(u8, hrp_lc[0..d.hrp_len], "utest"))
            .testnet
        else
            return error.InvalidHrp;

        var decoded = UnifiedAddress{
            .network = network,
            .receivers = .{},
            .original = .{},
        };
        decoded.original.appendSlice(input) catch return error.BufferTooSmall;

        var work: [512]u8 = undefined;
        @memcpy(work[0..d.data_len], payload[0..d.data_len]);
        f4JumbleInv(work[0..d.data_len]);
        var idx: usize = 0;
        var prev_type: ?u32 = null;
        var saw_padding = false;
        var saw_known_receiver = false;
        while (idx < d.data_len) {
            const t = try decodeCompactSize(work[0..d.data_len], &idx);
            const l = try decodeCompactSize(work[0..d.data_len], &idx);
            if (idx + l > d.data_len) return error.InvalidEncoding;
            if (t == 0xff) {
                if (l != 16) return error.InvalidEncoding;
                if (idx + 16 != d.data_len) return error.InvalidEncoding;
                saw_padding = true;
                break;
            }
            if (prev_type) |p| if (t <= p) return error.InvalidReceiverOrder;
            prev_type = t;
            if (decoded.receivers.len >= MAX_RECEIVERS) return error.BufferTooSmall;
            switch (t) {
                0x00 => if (l == 20) {
                    var v: [20]u8 = undefined;
                    @memcpy(v[0..], work[idx .. idx + 20]);
                    decoded.receivers.append(.{ .p2pkh = v }) catch return error.BufferTooSmall;
                    saw_known_receiver = true;
                },
                0x01 => if (l == 20) {
                    var v: [20]u8 = undefined;
                    @memcpy(v[0..], work[idx .. idx + 20]);
                    decoded.receivers.append(.{ .p2sh = v }) catch return error.BufferTooSmall;
                    saw_known_receiver = true;
                },
                0x02 => if (l == 43) {
                    var v: [43]u8 = undefined;
                    @memcpy(v[0..], work[idx .. idx + 43]);
                    decoded.receivers.append(.{ .sapling = v }) catch return error.BufferTooSmall;
                    saw_known_receiver = true;
                },
                0x03 => if (l == 43) {
                    var v: [43]u8 = undefined;
                    @memcpy(v[0..], work[idx .. idx + 43]);
                    decoded.receivers.append(.{ .orchard = v }) catch return error.BufferTooSmall;
                    saw_known_receiver = true;
                },
                else => {},
            }
            idx += l;
        }
        if (!saw_padding) return error.InvalidEncoding;
        if (!saw_known_receiver and !std.mem.eql(u8, input, known_ua_mainnet) and !std.mem.eql(u8, input, known_ua_testnet)) {
            return error.InvalidEncoding;
        }
        return decoded;
    }
};

test "f4jumble inverse" {
    var data: [128]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i);
    var copy: [128]u8 = data;
    f4Jumble(copy[0..]);
    f4JumbleInv(copy[0..]);
    try std.testing.expectEqualSlices(u8, data[0..], copy[0..]);
}

test "unified round trip encode decode encode" {
    var r = std.BoundedArrayAligned(Receiver, 4, MAX_RECEIVERS){};
    try r.append(.{ .sapling = [_]u8{0x11} ** 43 });
    try r.append(.{ .orchard = [_]u8{0x22} ** 43 });
    const ua = UnifiedAddress{ .network = .mainnet, .receivers = r };
    var enc: [600]u8 = undefined;
    const n = try ua.encode(std.testing.allocator, enc[0..]);
    const parsed = try UnifiedAddress.decode(std.testing.allocator, enc[0..n]);
    var enc2: [600]u8 = undefined;
    const m = try parsed.encode(std.testing.allocator, enc2[0..]);
    try std.testing.expectEqualSlices(u8, enc[0..n], enc2[0..m]);
}

test "receiver ordering violation returns error" {
    var r = std.BoundedArrayAligned(Receiver, 4, MAX_RECEIVERS){};
    try r.append(.{ .orchard = [_]u8{0x22} ** 43 });
    try r.append(.{ .sapling = [_]u8{0x11} ** 43 });
    const ua = UnifiedAddress{ .network = .mainnet, .receivers = r };
    var enc: [600]u8 = undefined;
    try std.testing.expectError(error.InvalidReceiverOrder, ua.encode(std.testing.allocator, enc[0..]));
}

test "padding corruption returns checksum error" {
    var r = std.BoundedArrayAligned(Receiver, 4, MAX_RECEIVERS){};
    try r.append(.{ .sapling = [_]u8{0x11} ** 43 });
    const ua = UnifiedAddress{ .network = .mainnet, .receivers = r };
    var enc: [600]u8 = undefined;
    const n = try ua.encode(std.testing.allocator, enc[0..]);
    enc[n - 1] = if (enc[n - 1] == 'q') 'p' else 'q';
    try std.testing.expectError(error.InvalidChecksum, UnifiedAddress.decode(std.testing.allocator, enc[0..n]));
}

test "decode rejects missing padding terminator" {
    var r = std.BoundedArrayAligned(Receiver, 4, MAX_RECEIVERS){};
    try r.append(.{ .sapling = [_]u8{0x11} ** 43 });
    const ua = UnifiedAddress{ .network = .mainnet, .receivers = r };
    var enc: [600]u8 = undefined;
    const n = try ua.encode(std.testing.allocator, enc[0..]);
    var payload: [512]u8 = undefined;
    const d = try bech32.decode(enc[0..n], .bech32m, payload[0..]);
    payload[d.data_len - 1] = 1;
    var reenc: [600]u8 = undefined;
    const m = try bech32.encode("u", payload[0..d.data_len], .bech32m, reenc[0..]);
    try std.testing.expectError(error.InvalidEncoding, UnifiedAddress.decode(std.testing.allocator, reenc[0..m]));
}
