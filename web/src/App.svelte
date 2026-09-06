<script lang="ts">
  import { onMount } from "svelte";
  import init, {
    decrypt_ehi,
    decrypt_hc,
    decrypt_ssc,
  } from "./wasm/decryptor_core.js";

  type Format = "ehi" | "hc" | "ssc";
  type WasmDecryptor = (bytes: Uint8Array, option: boolean) => unknown;

  let format = $state<Format>("ehi");
  let fileInput = $state<HTMLInputElement>();
  let selectedFileName = $state("");
  let pastedText = $state("");
  let redactSecrets = $state(true);
  let status = $state("");
  let statusIsError = $state(false);
  let output = $state("");
  let isReady = $state(false);
  let isDecrypting = $state(false);

  let isHc = $derived(format === "hc");
  let optionLabel = $derived(format === "ehi" ? "Redact secrets" : "Remap compact keys");
  let fileAccept = $derived(
    format === "ehi" ? ".ehi" : format === "ssc" ? ".ssc,.txt" : ".hc,.txt",
  );
  let decryptDisabled = $derived(!isReady || isDecrypting);
  let copyDisabled = $derived(isDecrypting || output.length === 0);

  function setStatus(message: string, isError = false): void {
    status = message;
    statusIsError = isError;
  }

  function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
  }

  function normalizeValue(value: unknown): unknown {
    if (value instanceof Map) {
      return Object.fromEntries(
        [...value.entries()].map(([key, entry]) => [key, normalizeValue(entry)]),
      );
    }
    if (Array.isArray(value)) {
      return value.map(normalizeValue);
    }
    if (value !== null && typeof value === "object") {
      return Object.fromEntries(
        Object.entries(value).map(([key, entry]) => [key, normalizeValue(entry)]),
      );
    }
    return value;
  }

  function handleFileChange(event: Event): void {
    const input = event.currentTarget as HTMLInputElement;
    if (input.files?.length) {
      pastedText = "";
      selectedFileName = input.files[0].name;
    }
  }

  function handleTextInput(): void {
    if (pastedText.length > 0 && fileInput) {
      fileInput.value = "";
      selectedFileName = "";
    }
  }

  function selectedInput(): Promise<Uint8Array> {
    const selectedFile = fileInput?.files?.[0];
    if (selectedFile) {
      return selectedFile.arrayBuffer().then((buffer) => new Uint8Array(buffer));
    }

    if (pastedText.length > 0) {
      return Promise.resolve(new TextEncoder().encode(pastedText));
    }

    throw new Error("Choose a file or paste a configuration first.");
  }

  function decryptorFor(selected: Format): WasmDecryptor {
    switch (selected) {
      case "ehi":
        return decrypt_ehi;
      case "hc":
        return (bytes) => decrypt_hc(bytes);
      case "ssc":
        return decrypt_ssc;
    }
  }

  async function decryptConfiguration(): Promise<void> {
    isDecrypting = true;
    output = "";
    setStatus("Decrypting…");

    try {
      const value = decryptorFor(format)(await selectedInput(), redactSecrets);
      output = JSON.stringify(normalizeValue(value), null, 2) ?? "";
      setStatus("Decrypted locally.");
    } catch (error: unknown) {
      setStatus(errorMessage(error), true);
    } finally {
      isDecrypting = false;
    }
  }

  async function copyOutput(): Promise<void> {
    if (!output) {
      return;
    }

    try {
      await navigator.clipboard.writeText(output);
      setStatus("JSON copied to the clipboard.");
    } catch (error: unknown) {
      setStatus(errorMessage(error), true);
    }
  }

  onMount(() => {
    let mounted = true;

    init()
      .then(() => {
        if (mounted) {
          isReady = true;
          setStatus("Ready.");
        }
      })
      .catch((error: unknown) => {
        if (mounted) {
          setStatus(`WebAssembly could not load: ${errorMessage(error)}`, true);
        }
      });

    return () => {
      mounted = false;
    };
  });
</script>

<main class="app-shell">
  <section class="hero" aria-labelledby="page-title">
    <div class="hero-topline">
      <span class="local-badge"><span class="badge-dot"></span> Runs locally</span>
    </div>
    <p class="eyebrow">Local-first configuration tooling</p>
    <h1 id="page-title">Multi VPN Decryptor</h1>
    <p class="lede">
      Decode EHI, HTTP Custom, and SSH Custom configurations locally. Your files
      never leave this browser.
    </p>
  </section>

  <section class="panel" aria-labelledby="input-title">
    <div class="panel-heading">
      <div>
        <p class="panel-kicker">INPUT</p>
        <h2 id="input-title">Configuration</h2>
      </div>
      <span class="panel-caption">Nothing leaves your browser</span>
    </div>
    <div class="field-grid">
      <label class="field">
        <span>Format</span>
        <select bind:value={format}>
          <option value="ehi">HTTP Injector (.ehi)</option>
          <option value="hc">HTTP Custom (.hc)</option>
          <option value="ssc">SSH Custom (.ssc / ssc://)</option>
        </select>
      </label>

      <label class="field">
        <span>Configuration file</span>
        <div class="file-picker">
          <input
            class="file-input"
            bind:this={fileInput}
            type="file"
            accept={fileAccept}
            onchange={handleFileChange}
          />
          <span class="file-button" aria-hidden="true">Browse</span>
          <span class="file-name">{selectedFileName || "No file selected"}</span>
        </div>
      </label>
    </div>

    <label class="field">
      <span>Or paste configuration text</span>
      <textarea
        bind:value={pastedText}
        rows="8"
        spellcheck="false"
        placeholder="Paste an EHI, HC, or SSC configuration here"
        oninput={handleTextInput}
      ></textarea>
    </label>

    {#if !isHc}
      <label class="toggle">
        <input bind:checked={redactSecrets} type="checkbox" />
        <span>{optionLabel}</span>
      </label>
    {/if}

    <button type="button" disabled={decryptDisabled} onclick={decryptConfiguration}>
      {#if isDecrypting}
        Decrypting…
      {:else if isReady}
        Decrypt configuration
      {:else}
        Loading decryptor…
      {/if}
    </button>
    <p class:error={statusIsError} class="status" role="status" aria-live="polite">{status}</p>
  </section>

  <section class="panel" aria-labelledby="output-title">
    <div class="section-heading">
      <div>
        <p class="panel-kicker">OUTPUT</p>
        <h2 id="output-title">Decrypted JSON</h2>
      </div>
      <button
        class="secondary-button"
        type="button"
        disabled={copyDisabled}
        onclick={copyOutput}
      >
        Copy JSON
      </button>
    </div>
    <pre class:empty={!output}>
      {#if output}
        <code>{output}</code>
      {:else}
        <span class="output-placeholder">Your decrypted JSON will appear here.</span>
      {/if}
    </pre>
  </section>
</main>
