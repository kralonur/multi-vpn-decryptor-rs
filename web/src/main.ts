import init, {
  decrypt_ehi,
  decrypt_hc,
  decrypt_ssc,
} from "./wasm/decryptor_core.js";
import "./styles.css";

type Format = "ehi" | "hc" | "ssc";

type WasmDecryptor = (
  bytes: Uint8Array,
  option: boolean,
) => unknown;

const format = getElement<HTMLSelectElement>("format");
const file = getElement<HTMLInputElement>("file");
const text = getElement<HTMLTextAreaElement>("text");
const option = getElement<HTMLInputElement>("option");
const optionControl = getElement<HTMLLabelElement>("option-control");
const optionLabel = getElement<HTMLSpanElement>("option-label");
const decryptButton = getElement<HTMLButtonElement>("decrypt");
const copyButton = getElement<HTMLButtonElement>("copy");
const status = getElement<HTMLParagraphElement>("status");
const output = getElement<HTMLElement>("output");
const outputCodeElement = output.querySelector<HTMLElement>("code");
if (!outputCodeElement) {
  throw new Error("Output element is missing its code container.");
}
const outputCode: HTMLElement = outputCodeElement;

function getElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`Missing element: #${id}`);
  }
  return element as T;
}

function currentFormat(): Format {
  return format.value as Format;
}

function updateFormatControls(): void {
  const selected = currentFormat();
  const isEhi = selected === "ehi";
  const isHc = selected === "hc";

  optionLabel.textContent = isEhi ? "Redact secrets" : "Remap compact keys";
  optionControl.hidden = isHc;
  option.disabled = isHc;
  file.accept = isEhi ? ".ehi" : selected === "ssc" ? ".ssc,.txt" : ".hc,.txt";
}

function setStatus(message: string, isError = false): void {
  status.textContent = message;
  status.className = isError ? "status error" : "status";
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

function selectedInput(): Promise<Uint8Array> {
  const selectedFile = file.files?.[0];
  if (selectedFile) {
    return selectedFile.arrayBuffer().then((buffer) => new Uint8Array(buffer));
  }

  const pastedText = text.value;
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
  decryptButton.disabled = true;
  copyButton.disabled = true;
  outputCode.textContent = "";
  setStatus("Decrypting…");

  try {
    const selected = currentFormat();
    const decrypt = decryptorFor(selected);
    const value = decrypt(await selectedInput(), option.checked);
    outputCode.textContent = JSON.stringify(normalizeValue(value), null, 2);
    copyButton.disabled = false;
    setStatus("Decrypted locally.");
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    setStatus(message, true);
  } finally {
    decryptButton.disabled = false;
  }
}

async function copyOutput(): Promise<void> {
  if (!outputCode.textContent) {
    return;
  }
  await navigator.clipboard.writeText(outputCode.textContent);
  setStatus("JSON copied to the clipboard.");
}

format.addEventListener("change", updateFormatControls);
file.addEventListener("change", () => {
  if (file.files?.length) {
    text.value = "";
  }
});
text.addEventListener("input", () => {
  if (text.value.length > 0) {
    file.value = "";
  }
});
decryptButton.addEventListener("click", () => void decryptConfiguration());
copyButton.addEventListener("click", () => void copyOutput());

updateFormatControls();

try {
  await init();
  decryptButton.disabled = false;
  decryptButton.textContent = "Decrypt configuration";
  setStatus("Ready.");
} catch (error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  setStatus(`WebAssembly could not load: ${message}`, true);
}
