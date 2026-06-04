import { useCallback, useId, useMemo, useRef, useState } from 'react';
import { Button, Spinner } from '@librechat/client';
import { ErrorMessage } from '~/components/Auth/ErrorMessage';
import { useAuthContext } from '~/hooks/AuthContext';
import { AttestationFailedError } from '~/lib/caladon';

/**
 * CaladonUnlock — the seed-unlock screen (SURGERY.md §A3, gap G2).
 *
 * This replaces LibreChat's password `<Login/>` at `/login`. Caladon has no password, no email and
 * no server-side user record — identity is a key derived from a local 32-byte SEED. This screen is
 * the ONLY UI that calls `caladon.unlock(seed)`, which runs the full fail-closed handshake
 * (onboard → attest → verify → derive session key → deliver WMK) in the WASM via @caladon/protocol.
 * On success AuthContext flips `isUnlocked` and navigates to `/c/new`; this component does not
 * navigate itself.
 *
 * The seed is a RAW 32-byte Uint8Array. There is no mnemonic codec in the SDK, so this UI owns the
 * human-facing encode/decode: a RECOVERY CODE is the lowercase hex of the 32 bytes, displayed in
 * dash-separated groups for legibility. Restore decodes any whitespace/dash-formatted hex back to
 * exactly 32 bytes (it rejects anything else). The seed never leaves the browser; identity is held
 * in memory only, so every reload re-locks and returns here.
 *
 * Fail-closed: any handshake error (AttestationFailedError or otherwise) lands in an error state
 * that refuses to connect and offers retry. We never proceed to chat on an unverified session.
 */

type Mode = 'choose' | 'create' | 'restore';
type Phase = 'idle' | 'unlocking' | 'error';

const VERIFY_FAILED_MESSAGE =
  'Could not establish a verified session — refusing to connect.';

/** Lowercase hex of the 32 seed bytes, grouped 8 chars per block for legible transcription. */
function encodeRecoveryCode(seed: Uint8Array): string {
  const hex = Array.from(seed, (b) => b.toString(16).padStart(2, '0')).join('');
  return (hex.match(/.{1,8}/g) ?? []).join('-');
}

/**
 * Decode a recovery code back to exactly 32 bytes. Tolerates spaces, dashes and case; rejects any
 * non-hex character and any length other than 64 hex digits. Returns null on any invalid input so
 * the caller can show a precise error rather than unlock with a malformed seed.
 */
function decodeRecoveryCode(input: string): Uint8Array | null {
  const cleaned = input.replace(/[\s-]/g, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(cleaned)) {
    return null;
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export default function CaladonUnlock() {
  const { caladon } = useAuthContext();

  const [mode, setMode] = useState<Mode>('choose');
  const [phase, setPhase] = useState<Phase>('idle');
  const [errorText, setErrorText] = useState<string>(VERIFY_FAILED_MESSAGE);

  // Create flow: a freshly generated seed + its display code, and the "I saved it" confirmation.
  const [newSeed, setNewSeed] = useState<Uint8Array | null>(null);
  const [savedConfirmed, setSavedConfirmed] = useState(false);

  // Restore flow: the pasted recovery code + a synchronous validation message.
  const [restoreInput, setRestoreInput] = useState('');
  const [restoreError, setRestoreError] = useState<string | null>(null);

  // The seed we last attempted to unlock with, so the error state's "Try again" can retry it.
  const lastSeedRef = useRef<Uint8Array | null>(null);

  const recoveryCode = useMemo(
    () => (newSeed ? encodeRecoveryCode(newSeed) : ''),
    [newSeed],
  );

  const unlockId = useId();

  const resetTransient = useCallback(() => {
    setPhase('idle');
    setRestoreError(null);
  }, []);

  /** The single entry point: run the fail-closed handshake; surface any failure as fail-closed. */
  const runUnlock = useCallback(
    async (seed: Uint8Array) => {
      if (!caladon) {
        setErrorText('Caladon identity is unavailable in this build.');
        setPhase('error');
        return;
      }
      lastSeedRef.current = seed;
      setPhase('unlocking');
      try {
        // AuthContext.unlock runs the handshake and, on success, navigates to /c/new.
        await caladon.unlock(seed);
      } catch (err) {
        if (err instanceof AttestationFailedError) {
          setErrorText(
            `${VERIFY_FAILED_MESSAGE} The server could not prove it is the attested enclave.`,
          );
        } else {
          setErrorText(VERIFY_FAILED_MESSAGE);
        }
        setPhase('error');
      }
    },
    [caladon],
  );

  const handleCreate = useCallback(() => {
    const seed = new Uint8Array(32);
    crypto.getRandomValues(seed);
    setNewSeed(seed);
    setSavedConfirmed(false);
    resetTransient();
    setMode('create');
  }, [resetTransient]);

  const handleRestore = useCallback(() => {
    setRestoreInput('');
    setRestoreError(null);
    resetTransient();
    setMode('restore');
  }, [resetTransient]);

  const handleBack = useCallback(() => {
    setMode('choose');
    setNewSeed(null);
    setSavedConfirmed(false);
    setRestoreInput('');
    setRestoreError(null);
    resetTransient();
  }, [resetTransient]);

  const handleRestoreSubmit = useCallback(() => {
    const seed = decodeRecoveryCode(restoreInput);
    if (!seed) {
      setRestoreError(
        'That is not a valid recovery code. It must be 64 hexadecimal characters (32 bytes).',
      );
      return;
    }
    setRestoreError(null);
    void runUnlock(seed);
  }, [restoreInput, runUnlock]);

  const handleRetry = useCallback(() => {
    if (lastSeedRef.current) {
      void runUnlock(lastSeedRef.current);
    } else {
      setPhase('idle');
    }
  }, [runUnlock]);

  // ---- Fail-closed error state (any handshake failure) ----------------------------------------
  if (phase === 'error') {
    return (
      <div className="flex flex-col gap-4">
        <ErrorMessage>{errorText}</ErrorMessage>
        <p className="text-sm text-text-secondary">
          Caladon refuses to connect unless it has verified an attested session. Your identity stays
          locked on this device until a verified session is established.
        </p>
        <div className="flex gap-3">
          <Button variant="submit" className="flex-1" onClick={handleRetry}>
            Try again
          </Button>
          <Button variant="outline" className="flex-1" onClick={handleBack}>
            Back
          </Button>
        </div>
      </div>
    );
  }

  // ---- Loading state (handshake in flight) ----------------------------------------------------
  if (phase === 'unlocking') {
    return (
      <div className="flex flex-col items-center gap-4 py-6" aria-live="polite">
        <Spinner className="text-text-primary" />
        <p className="text-center text-sm text-text-secondary">
          Establishing a verified session… running the attestation handshake.
        </p>
      </div>
    );
  }

  // ---- Restore flow ---------------------------------------------------------------------------
  if (mode === 'restore') {
    return (
      <div className="flex flex-col gap-4">
        <p className="text-sm text-text-secondary">
          Paste your recovery code to restore your identity. It never leaves this device.
        </p>
        <div>
          <label htmlFor={unlockId} className="mb-1 block text-sm font-medium text-text-primary">
            Recovery code
          </label>
          <textarea
            id={unlockId}
            value={restoreInput}
            onChange={(e) => {
              setRestoreInput(e.target.value);
              if (restoreError) {
                setRestoreError(null);
              }
            }}
            rows={3}
            spellCheck={false}
            autoComplete="off"
            autoCapitalize="off"
            autoCorrect="off"
            placeholder="abcd1234-…"
            className="w-full resize-none rounded-lg border border-border-light bg-surface-primary px-3 py-2 font-mono text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
        {restoreError != null && <ErrorMessage>{restoreError}</ErrorMessage>}
        <div className="flex gap-3">
          <Button
            variant="submit"
            className="flex-1"
            disabled={restoreInput.trim().length === 0}
            onClick={handleRestoreSubmit}
          >
            Unlock
          </Button>
          <Button variant="outline" className="flex-1" onClick={handleBack}>
            Back
          </Button>
        </div>
      </div>
    );
  }

  // ---- Create flow ----------------------------------------------------------------------------
  if (mode === 'create') {
    return (
      <div className="flex flex-col gap-4">
        <p className="text-sm text-text-secondary">
          This is your recovery code. It is the only way to restore your identity — Caladon cannot
          recover it for you. Write it down and keep it somewhere safe.
        </p>
        <div
          className="select-all break-all rounded-lg border border-border-light bg-surface-secondary px-4 py-3 text-center font-mono text-base tracking-wide text-text-primary"
          data-testid="recovery-code"
        >
          {recoveryCode}
        </div>
        <label className="flex items-start gap-2 text-sm text-text-primary">
          <input
            type="checkbox"
            checked={savedConfirmed}
            onChange={(e) => setSavedConfirmed(e.target.checked)}
            className="mt-0.5 h-4 w-4 rounded border-border-medium"
          />
          <span>I have saved my recovery code. I understand it cannot be recovered if lost.</span>
        </label>
        <div className="flex gap-3">
          <Button
            variant="submit"
            className="flex-1"
            disabled={!savedConfirmed || !newSeed}
            onClick={() => newSeed && void runUnlock(newSeed)}
          >
            Continue
          </Button>
          <Button variant="outline" className="flex-1" onClick={handleBack}>
            Back
          </Button>
        </div>
      </div>
    );
  }

  // ---- Choose (default) -----------------------------------------------------------------------
  return (
    <div className="flex flex-col gap-4">
      <p className="text-center text-sm text-text-secondary">
        Caladon uses a local identity, not a password. Create a new identity or restore one from a
        recovery code — your keys are derived on this device and never leave it.
      </p>
      <Button variant="submit" className="w-full" onClick={handleCreate}>
        Create new identity
      </Button>
      <Button variant="outline" className="w-full" onClick={handleRestore}>
        Restore from recovery code
      </Button>
    </div>
  );
}
