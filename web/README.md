# Web UI

The browser UI is a declarative Svelte app built with Vite. Decryption runs
locally in WebAssembly; configuration files are not uploaded.

## Hosted app

Run the latest deployed app directly in your browser:

<https://kralonur.github.io/multi-vpn-decryptor-rs/>

## Development

Install dependencies and start the development server from this directory:

```text
pnpm install
pnpm dev
```

`pnpm dev` builds the Rust WebAssembly package through the local
`wasm-pack` dependency before starting Vite. No separate build file is
required.

Svelte diagnostics run as part of `pnpm build` through `svelte-check`.

## Production build

```text
pnpm build
pnpm preview
```

Generated WebAssembly and Vite output are ignored by Git. Rust and the
`wasm32-unknown-unknown` target must be installed on the development machine.

## GitHub Pages

The repository workflow builds and deploys `web/dist` automatically on pushes
to `main` or `master`. In the repository settings, set **Pages → Build and
deployment → Source** to **GitHub Actions** once.
