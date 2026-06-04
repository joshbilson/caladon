import { useCallback, useId, useMemo, useRef } from 'react';
import { Button, Spinner } from '@librechat/client';
import { FileText, Paperclip, X, AlertCircle, CheckCircle2 } from 'lucide-react';
import { useRag, type RagFile, type RagFileStatus } from '~/store/useRag';
import { ACCEPTED_DESCRIPTION } from '~/lib/rag/parsers';

/**
 * RagFileAttach — the on-device document-retrieval attach surface (Batch 1 client foundation).
 *
 * Lets the user attach files (txt/md/code, PDF, .docx) to be indexed for retrieval. EVERYTHING here
 * is on-device: the chosen files are parsed, chunked and embedded locally (see `useRag`), and their
 * vectors are written to the SQLCipher-encrypted store. Nothing is uploaded. At chat time, relevant
 * chunks are retrieved and injected into the prompt BEFORE it is sealed, so the gateway never sees
 * the document text.
 *
 * This component is intentionally self-contained (drag-drop zone + file list + per-file progress)
 * so it can be mounted next to the composer or in a side panel without wiring global state. It uses
 * the overlay's existing UI primitives (`Button`/`Spinner` from `@librechat/client`) and
 * lucide-react icons to match the surrounding LibreChat look.
 */

const ACCEPT_ATTR = [
  '.txt', '.md', '.markdown', '.mdx', '.rst', '.csv', '.tsv', '.log', '.json', '.yaml', '.yml',
  '.xml', '.html', '.css', '.js', '.jsx', '.ts', '.tsx', '.py', '.rb', '.go', '.rs', '.java',
  '.c', '.h', '.cpp', '.cs', '.swift', '.php', '.sh', '.sql', '.pdf', '.docx',
  'text/*', 'application/pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
].join(',');

const STATUS_LABEL: Record<RagFileStatus, string> = {
  parsing: 'Reading…',
  chunking: 'Splitting…',
  embedding: 'Embedding on device…',
  storing: 'Saving…',
  done: 'Indexed',
  error: 'Failed',
};

export interface RagFileAttachProps {
  /** Optional extra classes for the outer container. */
  className?: string;
  /** Hide the explanatory privacy note (e.g. when shown inline next to the composer). */
  compact?: boolean;
}

export default function RagFileAttach({ className, compact = false }: RagFileAttachProps) {
  const { files, isIngesting, ingestFiles, removeFile, clear } = useRag();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const inputId = useId();

  const onPick = useCallback(() => inputRef.current?.click(), []);

  const onInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const picked = e.target.files;
      if (picked && picked.length > 0) {
        void ingestFiles(picked);
      }
      // Reset so picking the same file again re-triggers change.
      e.target.value = '';
    },
    [ingestFiles],
  );

  const onDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
      const dropped = e.dataTransfer?.files;
      if (dropped && dropped.length > 0) {
        void ingestFiles(dropped);
      }
    },
    [ingestFiles],
  );

  const onDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const indexedCount = useMemo(() => files.filter((f) => f.status === 'done').length, [files]);

  return (
    <div className={`flex flex-col gap-3 ${className ?? ''}`}>
      {!compact && (
        <p className="text-sm text-text-secondary">
          Attach documents to ground answers in your own files. They are read, embedded and stored{' '}
          <strong className="text-text-primary">entirely on this device</strong> — never uploaded.
          Relevant excerpts are added to your message and sealed before it leaves the browser.
        </p>
      )}

      {/* Drop zone / picker */}
      <div
        role="button"
        tabIndex={0}
        onClick={onPick}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onPick();
          }
        }}
        onDrop={onDrop}
        onDragOver={onDragOver}
        className="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border-medium bg-surface-secondary px-4 py-6 text-center transition-colors hover:border-border-heavy hover:bg-surface-tertiary focus:outline-none focus:ring-2 focus:ring-ring"
        aria-label="Attach documents for on-device retrieval"
      >
        <Paperclip className="h-5 w-5 text-text-secondary" aria-hidden="true" />
        <span className="text-sm font-medium text-text-primary">
          Drop files here, or click to choose
        </span>
        <span className="text-xs text-text-secondary">{ACCEPTED_DESCRIPTION}</span>
        <input
          id={inputId}
          ref={inputRef}
          type="file"
          multiple
          accept={ACCEPT_ATTR}
          onChange={onInputChange}
          className="hidden"
          aria-hidden="true"
          tabIndex={-1}
        />
      </div>

      {/* File list */}
      {files.length > 0 && (
        <ul className="flex flex-col gap-2" aria-live="polite">
          {files.map((file) => (
            <RagFileRow key={file.id} file={file} onRemove={() => void removeFile(file.id)} />
          ))}
        </ul>
      )}

      {/* Footer status / actions */}
      {files.length > 0 && (
        <div className="flex items-center justify-between text-xs text-text-secondary">
          <span>
            {isIngesting ? (
              <span className="inline-flex items-center gap-1.5">
                <Spinner className="h-3 w-3" />
                Indexing on device…
              </span>
            ) : (
              `${indexedCount} document${indexedCount === 1 ? '' : 's'} ready for retrieval`
            )}
          </span>
          <Button variant="outline" className="h-7 px-2 text-xs" onClick={clear} disabled={isIngesting}>
            Clear list
          </Button>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * One file row
 * ------------------------------------------------------------------ */

function RagFileRow({ file, onRemove }: { file: RagFile; onRemove: () => void }) {
  const isBusy =
    file.status === 'parsing' ||
    file.status === 'chunking' ||
    file.status === 'embedding' ||
    file.status === 'storing';

  return (
    <li className="flex items-center gap-3 rounded-lg border border-border-light bg-surface-primary px-3 py-2">
      <StatusIcon status={file.status} busy={isBusy} />
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm text-text-primary" title={file.name}>
          {file.name}
        </div>
        <div className="flex items-center gap-2 text-xs text-text-secondary">
          <span>{STATUS_LABEL[file.status]}</span>
          {file.chunks > 0 && file.status !== 'error' && (
            <span>
              · {file.chunks} chunk{file.chunks === 1 ? '' : 's'}
            </span>
          )}
          {file.status === 'error' && file.error && (
            <span className="text-text-destructive" title={file.error}>
              · {file.error}
            </span>
          )}
        </div>
      </div>
      <button
        type="button"
        onClick={onRemove}
        disabled={isBusy}
        className="rounded p-1 text-text-secondary transition-colors hover:bg-surface-tertiary hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-40"
        aria-label={`Remove ${file.name}`}
      >
        <X className="h-4 w-4" aria-hidden="true" />
      </button>
    </li>
  );
}

function StatusIcon({ status, busy }: { status: RagFileStatus; busy: boolean }) {
  if (busy) return <Spinner className="h-4 w-4 shrink-0 text-text-secondary" />;
  if (status === 'done') {
    return <CheckCircle2 className="h-4 w-4 shrink-0 text-green-500" aria-hidden="true" />;
  }
  if (status === 'error') {
    return <AlertCircle className="h-4 w-4 shrink-0 text-text-destructive" aria-hidden="true" />;
  }
  return <FileText className="h-4 w-4 shrink-0 text-text-secondary" aria-hidden="true" />;
}
