# Multi VPN Decryptor

A local-first Rust/WebAssembly tool for decrypting VPN configuration files in
your browser.

## Compatibility

| App / format | Analyzed or verified app version | Decodable configurations |
| --- | --- | --- |
| HTTP Injector (`.ehi`) | **6.5.0** (APK analysis) | Layered containers, nested locks, and supported encrypted fields. |
| HTTP Custom (`.hc`), legacy | **7.10.12 - Patch 2**, build **810** (verified) | Legacy outer container and 32-slot configurations; nested credential/protocol semantics remain best-effort. |
| HTTP Custom (`.hc`), modern | **7.11.28 Patch 1** (build **899**) & **8.0.22 - Patch 2** (build **934**) | Container **10** (`n11`) and Container **12** (`n15`), **unpassworded**: manifest, sections, runtime profiles, and separately encrypted custom payloads. |
| SSH Custom (`.ssc`, `ssc://`) | App version not pinned | APK-derived compact format, nested lock, and encrypted profile fields. |

**Latest verified HTTP Custom version: 8.0.22 - Patch 2 (934).** These are
specific compatibility targets, not a guarantee that every earlier or later
app version uses the same format. Modern password/access-bound schemes are
explicitly rejected. Legacy and modern HC files are detected automatically.

## Web app

You can run the hosted app directly in your browser without installing
anything: <https://kralonur.github.io/multi-vpn-decryptor-rs/>.

For local development, requirements are Rust, the `wasm32-unknown-unknown`
target, and pnpm.

```console
rustup target add wasm32-unknown-unknown
cd web
pnpm install
pnpm dev
```

Open the printed local URL. Files are decrypted locally and never uploaded.
Build a production bundle with `pnpm build`.

## HTTP Custom output

Modern results preserve serialized fields in `config` and `profiles`.
`decoded` adds readable names and expands profile `configJson`.
`protected_payloads` contains authenticated custom payloads, also restored
into the readable profile. `protections` exposes manifest protection settings.

Legacy results include decoded `config`, lossless `raw_slots`, and an
`unresolved` section identifying best-effort interpretations.

## License

MIT
