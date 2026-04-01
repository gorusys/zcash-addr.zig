const std = @import("std");

pub const Variant = enum { bech32, bech32m };

pub const EncodeError = error{ HrpTooLong, DataTooLong, InvalidChar };
pub const DecodeError = error{
    TooShort,
    TooLong,
    NoSeparator,
    InvalidChar,
    InvalidChecksum,
    MixedCase,
    InvalidPadding,
};

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const bech32_const: u32 = 1;
const bech32m_const: u32 = 0x2bc830a3;
const max_len: usize = 600;

const ConvertError = error{ BufferTooSmall, InvalidPadding };

const decode_map = blk: {
    var map: [128]i16 = [_]i16{-1} ** 128;
    for (charset, 0..) |c, i| {
        map[c] = @as(i16, @intCast(i));
    }
    break :blk map;
};

fn variantConst(variant: Variant) u32 {
    return switch (variant) {
        .bech32 => bech32_const,
        .bech32m => bech32m_const,
    };
}

pub fn polymod(values: []const u5) u32 {
    var chk: u32 = 1;
    for (values) |value| {
        const b: u5 = @truncate(chk >> 25);
        chk = (chk & 0x1ffffff) << 5;
        chk ^= @as(u32, value);
        if ((b & 0x01) != 0) chk ^= 0x3b6a57b2;
        if ((b & 0x02) != 0) chk ^= 0x26508e6d;
        if ((b & 0x04) != 0) chk ^= 0x1ea119fa;
        if ((b & 0x08) != 0) chk ^= 0x3d4233dd;
        if ((b & 0x10) != 0) chk ^= 0x2a1462b3;
    }
    return chk;
}

pub fn hrpExpand(hrp: []const u8, out: []u5) void {
    std.debug.assert(out.len >= (hrp.len * 2 + 1));
    for (hrp, 0..) |c, i| {
        out[i] = @as(u5, @truncate(c >> 5));
    }
    out[hrp.len] = 0;
    for (hrp, 0..) |c, i| {
        out[hrp.len + 1 + i] = @as(u5, @truncate(c & 31));
    }
}

pub fn createChecksum(hrp: []const u8, data: []const u5, variant: Variant) [6]u5 {
    var expanded: [180]u5 = [_]u5{0} ** 180;
    const exp_len = hrp.len * 2 + 1;
    hrpExpand(hrp, expanded[0..exp_len]);

    var values: [2048]u5 = [_]u5{0} ** 2048;
    if (exp_len + data.len + 6 > values.len) unreachable;
    @memcpy(values[0..exp_len], expanded[0..exp_len]);
    @memcpy(values[exp_len .. exp_len + data.len], data);
    for (0..6) |i| values[exp_len + data.len + i] = 0;

    const mod = polymod(values[0 .. exp_len + data.len + 6]) ^ variantConst(variant);
    var out: [6]u5 = undefined;
    for (0..6) |i| {
        const shift: u5 = @intCast(5 * (5 - i));
        out[i] = @as(u5, @truncate(mod >> shift));
    }
    return out;
}

pub fn verifyChecksum(hrp: []const u8, data: []const u5, variant: Variant) bool {
    var expanded: [180]u5 = [_]u5{0} ** 180;
    const exp_len = hrp.len * 2 + 1;
    hrpExpand(hrp, expanded[0..exp_len]);

    var values: [2048]u5 = [_]u5{0} ** 2048;
    if (exp_len + data.len > values.len) return false;
    @memcpy(values[0..exp_len], expanded[0..exp_len]);
    @memcpy(values[exp_len .. exp_len + data.len], data);
    return polymod(values[0 .. exp_len + data.len]) == variantConst(variant);
}

pub fn convertBits(data: []const u8, from: u4, to: u4, pad: bool, out: []u8) ConvertError!usize {
    var acc: u16 = 0;
    var bits: u8 = 0;
    var out_len: usize = 0;
    const maxv: u16 = (@as(u16, 1) << to) - 1;
    const from_mask: u16 = (@as(u16, 1) << from) - 1;

    for (data) |value| {
        if ((value & ~@as(u8, @truncate(from_mask))) != 0) return error.InvalidPadding;
        acc = (acc << from) | @as(u16, value);
        bits += from;
        while (bits >= to) {
            bits -= to;
            if (out_len >= out.len) return error.BufferTooSmall;
            out[out_len] = @as(u8, @truncate((acc >> @as(u4, @intCast(bits))) & maxv));
            out_len += 1;
        }
    }

    if (pad) {
        if (bits > 0) {
            if (out_len >= out.len) return error.BufferTooSmall;
            out[out_len] = @as(u8, @truncate((acc << @as(u4, @intCast(to - bits))) & maxv));
            out_len += 1;
        }
    } else {
        if (bits >= from) return error.InvalidPadding;
        if (((acc << @as(u4, @intCast(to - bits))) & maxv) != 0) return error.InvalidPadding;
    }

    return out_len;
}

pub fn encode(hrp: []const u8, data: []const u8, variant: Variant, out: []u8) EncodeError!usize {
    if (hrp.len + 1 + 6 > max_len) return error.HrpTooLong;
    const max_groups = max_len - hrp.len - 1 - 6;
    var data_5bit: [1024]u8 = [_]u8{0} ** 1024;
    const converted_len = convertBits(data, 8, 5, true, data_5bit[0..max_groups]) catch |err| switch (err) {
        error.BufferTooSmall => return error.DataTooLong,
        error.InvalidPadding => return error.InvalidChar,
    };

    const total_len = hrp.len + 1 + converted_len + 6;
    if (total_len > max_len) return error.DataTooLong;
    if (out.len < total_len) return error.DataTooLong;

    for (hrp, 0..) |c, i| {
        if (c < 33 or c > 126) return error.InvalidChar;
        out[i] = std.ascii.toLower(c);
    }
    out[hrp.len] = '1';
    for (data_5bit[0..converted_len], 0..) |v, i| {
        out[hrp.len + 1 + i] = charset[v];
    }
    var data_values: [1024]u5 = [_]u5{0} ** 1024;
    for (data_5bit[0..converted_len], 0..) |v, i| data_values[i] = @as(u5, @intCast(v));
    const checksum = createChecksum(out[0..hrp.len], data_values[0..converted_len], variant);
    for (checksum, 0..) |v, i| {
        out[hrp.len + 1 + converted_len + i] = charset[v];
    }
    return total_len;
}

pub fn decode(input: []const u8, variant: Variant, out: []u8) DecodeError!struct { hrp_len: usize, data_len: usize } {
    if (input.len < 8) return error.TooShort;
    if (input.len > max_len) return error.TooLong;

    var has_lower = false;
    var has_upper = false;
    var sep_idx: ?usize = null;

    for (input, 0..) |c, i| {
        if (c >= 'a' and c <= 'z') has_lower = true;
        if (c >= 'A' and c <= 'Z') has_upper = true;
        if (c == '1') sep_idx = i;
    }
    if (has_lower and has_upper) return error.MixedCase;

    const sep = sep_idx orelse return error.NoSeparator;
    if (sep == 0 or sep + 7 > input.len) return error.NoSeparator;

    var hrp_buf: [83]u8 = [_]u8{0} ** 83;
    for (input[0..sep], 0..) |c, i| {
        if (c < 33 or c > 126) return error.InvalidChar;
        hrp_buf[i] = std.ascii.toLower(c);
    }

    const data_part = input[sep + 1 ..];
    var values_5: [1024]u5 = [_]u5{0} ** 1024;
    if (data_part.len > values_5.len) return error.TooLong;
    for (data_part, 0..) |c, i| {
        const lc = std.ascii.toLower(c);
        if (lc >= decode_map.len) return error.InvalidChar;
        const v = decode_map[lc];
        if (v < 0) return error.InvalidChar;
        values_5[i] = @as(u5, @intCast(v));
    }

    if (!verifyChecksum(hrp_buf[0..sep], values_5[0..data_part.len], variant)) {
        return error.InvalidChecksum;
    }

    const payload_5 = values_5[0 .. data_part.len - 6];
    var payload_u8: [1024]u8 = [_]u8{0} ** 1024;
    for (payload_5, 0..) |v, i| payload_u8[i] = @intCast(v);
    const data_len = convertBits(payload_u8[0..payload_5.len], 5, 8, false, out) catch |err| switch (err) {
        error.BufferTooSmall => return error.TooLong,
        error.InvalidPadding => return error.InvalidPadding,
    };

    return .{ .hrp_len = sep, .data_len = data_len };
}

test "bech32 decode known vectors" {
    var out: [64]u8 = undefined;
    _ = try decode("A12UEL5L", .bech32, out[0..]);
    _ = try decode("an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs", .bech32, out[0..]);
}

test "bech32m decode known vectors" {
    var out: [64]u8 = undefined;
    _ = try decode("A1LQFN3A", .bech32m, out[0..]);
    _ = try decode("a1lqfn3a", .bech32m, out[0..]);
}

test "encode/decode round trip bech32" {
    const data = "hello world";
    var enc: [90]u8 = undefined;
    const n = try encode("zs", data, .bech32, enc[0..]);
    var dec: [64]u8 = undefined;
    const res = try decode(enc[0..n], .bech32, dec[0..]);
    try std.testing.expectEqual(@as(usize, 2), res.hrp_len);
    try std.testing.expectEqualSlices(u8, data, dec[0..res.data_len]);
}

test "encode/decode round trip bech32m" {
    const data = "unified";
    var enc: [90]u8 = undefined;
    const n = try encode("u", data, .bech32m, enc[0..]);
    var dec: [64]u8 = undefined;
    const res = try decode(enc[0..n], .bech32m, dec[0..]);
    try std.testing.expectEqual(@as(usize, 1), res.hrp_len);
    try std.testing.expectEqualSlices(u8, data, dec[0..res.data_len]);
}

test "invalid checksum returns InvalidChecksum" {
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.InvalidChecksum, decode("a12uel5m", .bech32, out[0..]));
}

test "mixed case returns MixedCase" {
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.MixedCase, decode("a12UEL5L", .bech32, out[0..]));
}

test "too long returns TooLong" {
    var long: [601]u8 = [_]u8{'a'} ** 601;
    long[1] = '1';
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.TooLong, decode(long[0..], .bech32, out[0..]));
}

test "fuzz-style bech32 round trips" {
    var prng = std.Random.DefaultPrng.init(0x1234_5678);
    const random = prng.random();
    var payload: [48]u8 = undefined;
    var enc: [600]u8 = undefined;
    var dec: [64]u8 = undefined;

    var i: usize = 0;
    while (i < 64) : (i += 1) {
        const len = random.intRangeAtMost(usize, 0, payload.len);
        random.bytes(payload[0..len]);
        const hrp = if ((i & 1) == 0) "zs" else "u";
        const variant: Variant = if ((i & 1) == 0) .bech32 else .bech32m;
        const n = try encode(hrp, payload[0..len], variant, enc[0..]);
        const d = try decode(enc[0..n], variant, dec[0..]);
        try std.testing.expectEqualSlices(u8, payload[0..len], dec[0..d.data_len]);
    }
}
