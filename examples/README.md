# Examples

This folder contains runnable examples for each supported address type.

## Build all examples

```bash
zig build examples
```

## Run examples

Run via build steps:

```bash
zig build run-example-transparent
zig build run-example-sapling
zig build run-example-unified
zig build run-example-autodetect
```

## What each example shows

- `transparent.zig`: decode and re-encode a transparent `t1...` address
- `sapling.zig`: decode and re-encode a Sapling `zs...` address
- `unified.zig`: decode and re-encode a Unified `utest...` address
- `autodetect.zig`: top-level `Address.decode()` auto-detection across multiple address types
