# Multi VPN Decryptor

A local-first Rust/WebAssembly tool for decrypting VPN configuration files in
your browser.

Supported formats:

- HTTP Injector (`.ehi`)
- HTTP Custom (`.hc`)
- SSH Custom (`.ssc` and `ssc://`)

## Web app

Requirements: Rust, the `wasm32-unknown-unknown` target, and pnpm.

```console
rustup target add wasm32-unknown-unknown
cd web
pnpm install
pnpm dev
```

Open the printed local URL. Files are decrypted locally and never uploaded.
Build a production bundle with `pnpm build`.

The HC decoder reports some nested credential and protocol fields as
best-effort when their semantics cannot be verified.

## License

MIT
