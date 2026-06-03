/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_ENABLE_LOGGER: string;
  readonly VITE_LOGGER_FILTER: string;
  // Caladon (SURGERY.md §D) — deploy-time config for the attestation gate + shim base.
  readonly VITE_CALADON_PINNED?: string;
  readonly VITE_CALADON_ATTESTATION?: string;
  readonly VITE_CALADON_SHIM_BASE?: string;
  // Add other env variables here
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
