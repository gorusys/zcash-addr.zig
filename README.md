# zcash-addr.zig

Pure Zig address encoding/decoding library for Zcash:

- Transparent addresses (`t1...`, `t3...`) via Base58Check
- Sapling shielded addresses (`zs...`) via Bech32 (ZIP-173)
- Unified addresses (`u1...`, `utest...`) via Bech32m (ZIP-316)

Targeted for Zig `0.14.x`, with `link_libc = false` and no external package dependencies.

## Installation

Add as a dependency in your `build.zig.zon`:

```zig
.{
    .dependencies = .{
        .zcash_addr = .{
            .url = "https://github.com/gorusys/zcash-addr.zig/archive/refs/heads/main.tar.gz",
            .hash = "<fill me with zig fetch hash>",
        },
    },
}
```

Then wire the module in `build.zig` as usual for your project.

## Usage

### Top-level auto-detect decode/encode

```zig
const std = @import("std");
const zcash = @import("zcash-addr");

pub fn main() !void {
    var out: [800]u8 = undefined;
    const addr = try zcash.Address.decode(std.heap.page_allocator, "t1KzZ5n2TPEGYXTZ3WYGL1AYEumEQaRoHaL");
    const n = try addr.encode(std.heap.page_allocator, out[0..]);
    _ = n;
}
```

### Transparent address

```zig
const t = try zcash.transparent.TransparentAddress.decode("t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ");
```

### Sapling address

```zig
const s = try zcash.sapling.SaplingAddress.decode("zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9slya");
```

### Unified address

```zig
const ua = try zcash.unified.UnifiedAddress.decode(std.heap.page_allocator, "utest15t0mmwzmc3jzl2hms7nem630wkm397tft82afwsl30zzxdxcrnjj9rg4e0uf2rusk0r9jjh00gtkxs7amcz385qqhe6c44rlqyhmwhme");
```

## Address Type Reference

| Type | Prefix examples | Encoding | Core payload |
|---|---|---|---|
| Transparent P2PKH | `t1...` | Base58Check | 2-byte version + 20-byte hash160 |
| Transparent P2SH | `t3...` | Base58Check | 2-byte version + 20-byte hash160 |
| Sapling | `zs...` / `ztestsapling...` | Bech32 | 11-byte diversifier + 32-byte `pk_d` |
| Unified | `u1...` / `utest...` | Bech32m + F4Jumble framing | variable receiver list |

## Development

Run unit and integration tests:

```bash
zig build test
```

Build static library:

```bash
zig build
```

## Specs

- [ZIP-173](https://zips.z.cash/zip-0173)
- [ZIP-316](https://zips.z.cash/zip-0316)
- [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
- [BIP-350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)
