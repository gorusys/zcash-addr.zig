const std = @import("std");

pub const EncodeError = error{BufferTooSmall};
pub const DecodeError = error{
    InvalidChar,
    InvalidChecksum,
    BufferTooSmall,
    InputTooShort,
};

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const decode_map = blk: {
    var map: [128]i16 = [_]i16{-1} ** 128;
    for (alphabet, 0..) |c, i| map[c] = @intCast(i);
    break :blk map;
};

pub fn sha256d(data: []const u8, out: *[32]u8) void {
    var first: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &first, .{});
    std.crypto.hash.sha2.Sha256.hash(first[0..], out, .{});
}

fn encode(payload: []const u8, out: []u8) EncodeError!usize {
    var zeros: usize = 0;
    while (zeros < payload.len and payload[zeros] == 0) : (zeros += 1) {}

    var temp: [512]u8 = [_]u8{0} ** 512;
    if (payload.len > temp.len) return error.BufferTooSmall;
    @memcpy(temp[0..payload.len], payload);
    var start = zeros;

    var digits: [1024]u8 = [_]u8{0} ** 1024;
    var digits_len: usize = 0;
    while (start < payload.len) {
        var rem: u32 = 0;
        for (start..payload.len) |i| {
            const n = rem * 256 + temp[i];
            temp[i] = @as(u8, @intCast(n / 58));
            rem = n % 58;
        }
        if (digits_len >= digits.len) return error.BufferTooSmall;
        digits[digits_len] = @as(u8, @intCast(rem));
        digits_len += 1;
        while (start < payload.len and temp[start] == 0) : (start += 1) {}
    }

    const total_len = zeros + digits_len;
    if (out.len < total_len) return error.BufferTooSmall;

    for (0..zeros) |i| out[i] = '1';
    for (0..digits_len) |i| out[zeros + i] = alphabet[digits[digits_len - 1 - i]];
    return total_len;
}

fn decode(input: []const u8, out: []u8) DecodeError!usize {
    var zeros: usize = 0;
    while (zeros < input.len and input[zeros] == '1') : (zeros += 1) {}

    var b256: [1024]u8 = [_]u8{0} ** 1024;
    var b256_len: usize = 0;

    for (input[zeros..]) |c| {
        if (c >= decode_map.len) return error.InvalidChar;
        const val_i = decode_map[c];
        if (val_i < 0) return error.InvalidChar;
        const value: u32 = @intCast(val_i);

        var carry = value;
        var i: usize = 0;
        while (i < b256_len) : (i += 1) {
            const idx = b256.len - 1 - i;
            const x = @as(u32, b256[idx]) * 58 + carry;
            b256[idx] = @as(u8, @intCast(x & 0xff));
            carry = x >> 8;
        }
        while (carry > 0) {
            if (b256_len >= b256.len) return error.BufferTooSmall;
            b256[b256.len - 1 - b256_len] = @as(u8, @intCast(carry & 0xff));
            b256_len += 1;
            carry >>= 8;
        }
    }

    var decoded: [1024]u8 = [_]u8{0} ** 1024;
    var decoded_len: usize = 0;
    for (0..zeros) |_| {
        decoded[decoded_len] = 0;
        decoded_len += 1;
    }
    @memcpy(decoded[decoded_len .. decoded_len + b256_len], b256[b256.len - b256_len ..]);
    decoded_len += b256_len;

    if (out.len < decoded_len) return error.BufferTooSmall;
    @memcpy(out[0..decoded_len], decoded[0..decoded_len]);
    return decoded_len;
}

pub fn encodeCheck(payload: []const u8, out: []u8) EncodeError!usize {
    var extended: [512]u8 = [_]u8{0} ** 512;
    if (payload.len + 4 > extended.len) return error.BufferTooSmall;
    @memcpy(extended[0..payload.len], payload);
    var digest: [32]u8 = undefined;
    sha256d(payload, &digest);
    @memcpy(extended[payload.len .. payload.len + 4], digest[0..4]);
    return encode(extended[0 .. payload.len + 4], out);
}

pub fn decodeCheck(input: []const u8, out: []u8) DecodeError!usize {
    var decoded: [512]u8 = [_]u8{0} ** 512;
    const n = try decode(input, decoded[0..]);
    if (n < 4) return error.InputTooShort;
    const payload_len = n - 4;
    if (out.len < payload_len) return error.BufferTooSmall;

    var digest: [32]u8 = undefined;
    sha256d(decoded[0..payload_len], &digest);
    if (!std.mem.eql(u8, decoded[payload_len..n], digest[0..4])) return error.InvalidChecksum;

    @memcpy(out[0..payload_len], decoded[0..payload_len]);
    return payload_len;
}

test "base58check round trip" {
    const payload = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44 };
    var enc: [128]u8 = undefined;
    const n = try encodeCheck(payload[0..], enc[0..]);
    var dec: [128]u8 = undefined;
    const m = try decodeCheck(enc[0..n], dec[0..]);
    try std.testing.expectEqualSlices(u8, payload[0..], dec[0..m]);
}

test "known bitcoin address decodes to version plus hash" {
    const addr = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs";
    var out: [64]u8 = undefined;
    const n = try decodeCheck(addr, out[0..]);
    try std.testing.expectEqual(@as(usize, 21), n);
    try std.testing.expectEqual(@as(u8, 0x00), out[0]);
}

test "bad checksum returns InvalidChecksum" {
    const bad = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUA1";
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.InvalidChecksum, decodeCheck(bad, out[0..]));
}

test "invalid character returns InvalidChar" {
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.InvalidChar, decodeCheck("0OIl", out[0..]));
}

test "fuzz-style base58check round trips" {
    var prng = std.Random.DefaultPrng.init(0xabcd_0123);
    const random = prng.random();
    var payload: [64]u8 = undefined;
    var enc: [256]u8 = undefined;
    var dec: [96]u8 = undefined;

    var i: usize = 0;
    while (i < 64) : (i += 1) {
        const len = random.intRangeAtMost(usize, 1, 48);
        random.bytes(payload[0..len]);
        const n = try encodeCheck(payload[0..len], enc[0..]);
        const m = try decodeCheck(enc[0..n], dec[0..]);
        try std.testing.expectEqualSlices(u8, payload[0..len], dec[0..m]);
    }
}
