const std = @import("std");
const bech32 = @import("bech32.zig");

pub const Network = enum { mainnet, testnet };
pub const MAX_RECEIVERS = 8;

/// Max opaque payload per unknown receiver (ZIP-316 raw body is bounded by F4Jumble / Bech32m limits).
pub const MAX_UNKNOWN_RECEIVER_BYTES = 480;

pub const Receiver = union(enum) {
    p2pkh: [20]u8,
    p2sh: [20]u8,
    sapling: [43]u8,
    orchard: [43]u8,
    unknown: struct {
        type_id: u32,
        len: u32,
        data: [MAX_UNKNOWN_RECEIVER_BYTES]u8,
    },
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

fn hrpForNetwork(network: Network) []const u8 {
    return switch (network) {
        .mainnet => "u",
        .testnet => "utest",
    };
}

/// ZIP-316: 16-byte padding suffix is UTF-8 HRP bytes followed by zeros (see zcash-test-vectors `unified_encoding.padding`).
fn writeHrpPadding(hrp: []const u8, out: *[16]u8) UnifiedError!void {
    if (hrp.len > 16) return error.InvalidHrp;
    @memcpy(out[0..hrp.len], hrp);
    @memset(out[hrp.len..], 0);
}

/// Bitcoin-style CompactSize (ZIP-316).
fn encodeCompactSize(v: u64, out: []u8) UnifiedError!usize {
    if (v < 253) {
        if (out.len < 1) return error.BufferTooSmall;
        out[0] = @truncate(v);
        return 1;
    }
    if (v <= 0xffff) {
        if (out.len < 3) return error.BufferTooSmall;
        out[0] = 0xfd;
        std.mem.writeInt(u16, out[1..3], @truncate(v), .little);
        return 3;
    }
    if (v <= 0xffff_ffff) {
        if (out.len < 5) return error.BufferTooSmall;
        out[0] = 0xfe;
        std.mem.writeInt(u32, out[1..5], @truncate(v), .little);
        return 5;
    }
    if (v <= 0xffff_ffff_ffff_ffff) {
        if (out.len < 9) return error.BufferTooSmall;
        out[0] = 0xff;
        std.mem.writeInt(u64, out[1..9], v, .little);
        return 9;
    }
    return error.InvalidEncoding;
}

fn decodeCompactSize(input: []const u8, idx: *usize) UnifiedError!u64 {
    if (idx.* >= input.len) return error.InvalidEncoding;
    const b = input[idx.*];
    idx.* += 1;
    if (b < 253) return b;
    if (b == 0xfd) {
        if (idx.* + 2 > input.len) return error.InvalidEncoding;
        const lo = input[idx.*];
        const hi = input[idx.* + 1];
        idx.* += 2;
        return (@as(u64, hi) << 8) | lo;
    }
    if (b == 0xfe) {
        if (idx.* + 4 > input.len) return error.InvalidEncoding;
        const o = idx.*;
        idx.* += 4;
        var v: u64 = 0;
        var s: u6 = 0;
        while (s < 32) : (s += 8) {
            v |= @as(u64, input[o + @divExact(@as(usize, s), 8)]) << s;
        }
        return v;
    }
    if (b == 0xff) {
        if (idx.* + 8 > input.len) return error.InvalidEncoding;
        const o = idx.*;
        idx.* += 8;
        var v: u64 = 0;
        var s: u6 = 0;
        while (s < 64) : (s += 8) {
            v |= @as(u64, input[o + @divExact(@as(usize, s), 8)]) << s;
        }
        return v;
    }
    return error.InvalidEncoding;
}

fn receiverTypeValue(r: Receiver) u32 {
    return switch (r) {
        .p2pkh => 0x00,
        .p2sh => 0x01,
        .sapling => 0x02,
        .orchard => 0x03,
        .unknown => |u| u.type_id,
    };
}

fn receiverBytes(r: Receiver) []const u8 {
    return switch (r) {
        .p2pkh => |v| v[0..],
        .p2sh => |v| v[0..],
        .sapling => |v| v[0..],
        .orchard => |v| v[0..],
        .unknown => |u| u.data[0..u.len],
    };
}

/// F4Jumble per zcash-test-vectors `f4jumble.py` / ZIP-316 (Blake2b personalization matches reference).
fn f4HashH(h_round: u8, msg: []const u8, out: []u8) void {
    var person: [16]u8 = undefined;
    @memcpy(person[0..13], "UA_F4Jumble_H");
    person[13] = h_round;
    person[14] = 0;
    person[15] = 0;
    var h = std.crypto.hash.blake2.Blake2b512.init(.{
        .expected_out_bits = @intCast(out.len * 8),
        .context = person,
    });
    h.update(msg);
    var full: [64]u8 = undefined;
    h.final(&full);
    @memcpy(out, full[0..out.len]);
}

fn f4HashGChunk(g_round: u8, chunk_j: usize, msg: []const u8, out64: *[64]u8) void {
    var person: [16]u8 = undefined;
    @memcpy(person[0..13], "UA_F4Jumble_G");
    person[13] = g_round;
    std.mem.writeInt(u16, person[14..16], @intCast(chunk_j), .little);
    var h = std.crypto.hash.blake2.Blake2b512.init(.{
        .expected_out_bits = 512,
        .context = person,
    });
    h.update(msg);
    h.final(out64);
}

fn f4GAll(g_round: u8, msg: []const u8, out: []u8) void {
    var j: usize = 0;
    var pos: usize = 0;
    while (pos < out.len) : (j += 1) {
        var chunk: [64]u8 = undefined;
        f4HashGChunk(g_round, j, msg, &chunk);
        const take = @min(64, out.len - pos);
        @memcpy(out[pos .. pos + take], chunk[0..take]);
        pos += take;
    }
}

fn f4Jumble(data: []u8) void {
    const l_M = data.len;
    if (l_M < 48) return;
    const l_L = @min(64, l_M / 2);
    const l_R = l_M - l_L;
    const a = data[0..l_L];
    const b = data[l_L..];

    var tmp: [2048]u8 = undefined;
    var off: usize = 0;
    const x = tmp[off..][0..l_R];
    off += l_R;
    const y = tmp[off..][0..l_L];
    off += l_L;
    const g1 = tmp[off..][0..l_R];
    off += l_R;
    const h1 = tmp[off..][0..l_L];

    f4GAll(0, a, x);
    for (x, b) |*xi, bi| xi.* ^= bi;
    f4HashH(0, x, y);
    for (y, a) |*yi, ai| yi.* ^= ai;
    f4GAll(1, y, g1);
    for (g1, x) |*gi, xi| gi.* ^= xi;
    f4HashH(1, g1, h1);
    for (h1, y) |*hi, yi| hi.* ^= yi;

    @memcpy(data[0..l_L], h1);
    @memcpy(data[l_L..], g1);
}

fn f4JumbleInv(data: []u8) void {
    const l_M = data.len;
    if (l_M < 48) return;
    const l_L = @min(64, l_M / 2);
    const l_R = l_M - l_L;
    const c = data[0..l_L];
    const d = data[l_L..];

    var tmp: [2048]u8 = undefined;
    var off: usize = 0;
    const y = tmp[off..][0..l_L];
    off += l_L;
    const x = tmp[off..][0..l_R];
    off += l_R;
    const g0 = tmp[off..][0..l_R];
    off += l_R;
    const h0 = tmp[off..][0..l_L];

    f4HashH(1, d, y);
    for (y, c) |*yi, ci| yi.* ^= ci;
    f4GAll(1, y, x);
    for (x, d) |*xi, di| xi.* ^= di;
    f4HashH(0, x, h0);
    for (h0, y) |*hi, yi| hi.* ^= yi;
    f4GAll(0, h0, g0);
    for (g0, x) |*gi, xi| gi.* ^= xi;

    @memcpy(data[0..l_L], h0);
    @memcpy(data[l_L..], g0);
}

pub const UnifiedAddress = struct {
    network: Network,
    receivers: std.BoundedArrayAligned(Receiver, 4, MAX_RECEIVERS),

    pub fn encode(self: UnifiedAddress, allocator: std.mem.Allocator, out: []u8) UnifiedError!usize {
        _ = allocator;
        var prev: ?u32 = null;
        var encoded: [1024]u8 = [_]u8{0} ** 1024;
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
        var pad16: [16]u8 = undefined;
        writeHrpPadding(hrpForNetwork(self.network), &pad16) catch return error.InvalidHrp;
        if (len + 16 > encoded.len) return error.BufferTooSmall;
        @memcpy(encoded[len .. len + 16], pad16[0..]);
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
        var payload: [1024]u8 = undefined;
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
        };

        var work: [1024]u8 = undefined;
        if (d.data_len > work.len) return error.InvalidEncoding;
        if (d.data_len < 48) return error.InvalidEncoding;
        @memcpy(work[0..d.data_len], payload[0..d.data_len]);
        f4JumbleInv(work[0..d.data_len]);

        var expected_pad: [16]u8 = undefined;
        writeHrpPadding(hrp_lc[0..d.hrp_len], &expected_pad) catch return error.InvalidHrp;
        const suffix = work[d.data_len - 16 .. d.data_len];
        if (!std.mem.eql(u8, suffix, &expected_pad)) return error.InvalidPadding;

        const body_len = d.data_len - 16;
        var idx: usize = 0;
        var prev_type: ?u32 = null;
        while (idx < body_len) {
            const t64 = try decodeCompactSize(work[0..body_len], &idx);
            if (t64 > std.math.maxInt(u32)) return error.InvalidEncoding;
            const t: u32 = @truncate(t64);

            const l64 = try decodeCompactSize(work[0..body_len], &idx);
            if (l64 > std.math.maxInt(u32)) return error.InvalidEncoding;
            const l: u32 = @truncate(l64);

            if (idx + l > body_len) return error.InvalidEncoding;

            if (prev_type) |p| if (t <= p) return error.InvalidReceiverOrder;
            prev_type = t;

            if (decoded.receivers.len >= MAX_RECEIVERS) return error.BufferTooSmall;

            switch (t) {
                0x00 => {
                    if (l != 20) return error.InvalidEncoding;
                    var v: [20]u8 = undefined;
                    @memcpy(v[0..], work[idx .. idx + 20]);
                    decoded.receivers.append(.{ .p2pkh = v }) catch return error.BufferTooSmall;
                },
                0x01 => {
                    if (l != 20) return error.InvalidEncoding;
                    var v: [20]u8 = undefined;
                    @memcpy(v[0..], work[idx .. idx + 20]);
                    decoded.receivers.append(.{ .p2sh = v }) catch return error.BufferTooSmall;
                },
                0x02 => {
                    if (l != 43) return error.InvalidEncoding;
                    var v: [43]u8 = undefined;
                    @memcpy(v[0..], work[idx .. idx + 43]);
                    decoded.receivers.append(.{ .sapling = v }) catch return error.BufferTooSmall;
                },
                0x03 => {
                    if (l != 43) return error.InvalidEncoding;
                    var v: [43]u8 = undefined;
                    @memcpy(v[0..], work[idx .. idx + 43]);
                    decoded.receivers.append(.{ .orchard = v }) catch return error.BufferTooSmall;
                },
                else => {
                    if (l > MAX_UNKNOWN_RECEIVER_BYTES) return error.BufferTooSmall;
                    var slot: Receiver = .{ .unknown = .{
                        .type_id = t,
                        .len = l,
                        .data = undefined,
                    } };
                    @memcpy(slot.unknown.data[0..l], work[idx .. idx + l]);
                    decoded.receivers.append(slot) catch return error.BufferTooSmall;
                },
            }
            idx += l;
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

test "f4jumble round trip 83 bytes" {
    var data: [83]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i);
    var w = data;
    f4Jumble(w[0..]);
    f4JumbleInv(w[0..]);
    try std.testing.expectEqualSlices(u8, data[0..], w[0..]);
}

test "bech32 UA_1 payload matches zcash-test-vectors" {
    const UA_1 = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";
    const ref_hex = "f9cdc9e45065c074a049ffaafaeeb47cdd36fb4285e189ea69243cc20944712f5c628def40fc780a8729f026ea8c03e4d931b2d5e66685a9f620a5acc585dce16a92d798bcfbb3be4c495c7e7b87fbcee79ec0";
    var buf: [1024]u8 = undefined;
    const d = try bech32.decode(UA_1, .bech32m, buf[0..]);
    try std.testing.expectEqual(@as(usize, 83), d.data_len);
    var ref: [83]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ref, ref_hex);
    try std.testing.expectEqualSlices(u8, &ref, buf[0..d.data_len]);
}

test "f4jumble_inv official UA raw matches zcash-test-vectors" {
    const hex = "f9cdc9e45065c074a049ffaafaeeb47cdd36fb4285e189ea69243cc20944712f5c628def40fc780a8729f026ea8c03e4d931b2d5e66685a9f620a5acc585dce16a92d798bcfbb3be4c495c7e7b87fbcee79ec0";
    var raw: [83]u8 = undefined;
    _ = try std.fmt.hexToBytes(&raw, hex);
    f4JumbleInv(raw[0..]);
    const exp: [16]u8 = .{0x75} ++ .{0} ** 15;
    try std.testing.expectEqualSlices(u8, &exp, raw[83 - 16 ..]);
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
    var payload: [1024]u8 = undefined;
    const d = try bech32.decode(enc[0..n], .bech32m, payload[0..]);
    payload[d.data_len - 1] = 1;
    var reenc: [600]u8 = undefined;
    const m = try bech32.encode("u", payload[0..d.data_len], .bech32m, reenc[0..]);
    try std.testing.expectError(error.InvalidPadding, UnifiedAddress.decode(std.testing.allocator, reenc[0..m]));
}

test "compact size round trip large type id" {
    var buf: [16]u8 = undefined;
    const n = try encodeCompactSize(0x10000, buf[0..]);
    var i: usize = 0;
    const v = try decodeCompactSize(buf[0..n], &i);
    try std.testing.expectEqual(@as(u64, 0x10000), v);
    try std.testing.expectEqual(n, i);
}

test "unknown receiver round trip" {
    var r = std.BoundedArrayAligned(Receiver, 4, MAX_RECEIVERS){};
    const payload = "abcdefghijklmnopqrstuvwxyz0123456789abcd"; // 40 bytes; F4Jumble requires >= 48-byte message
    var u: Receiver = .{ .unknown = .{
        .type_id = 0x42,
        .len = @intCast(payload.len),
        .data = undefined,
    } };
    @memcpy(u.unknown.data[0..payload.len], payload);
    try r.append(u);
    const ua = UnifiedAddress{ .network = .testnet, .receivers = r };
    var enc: [600]u8 = undefined;
    const n = try ua.encode(std.testing.allocator, enc[0..]);
    const parsed = try UnifiedAddress.decode(std.testing.allocator, enc[0..n]);
    try std.testing.expectEqual(@as(usize, 1), parsed.receivers.len);
    try std.testing.expectEqual(0x42, parsed.receivers.get(0).unknown.type_id);
    try std.testing.expectEqual(@as(u32, @intCast(payload.len)), parsed.receivers.get(0).unknown.len);
    try std.testing.expectEqualSlices(u8, payload, parsed.receivers.get(0).unknown.data[0..payload.len]);
}
