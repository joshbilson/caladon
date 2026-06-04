/**
 * Caladon — ImportConversationButton (Batch 1 client foundation, in-browser import UI).
 *
 * The device-side analogue of LibreChat's `ImportConversations` settings control. Upstream uploads
 * the selected `.json` to the gateway as multipart FormData; Caladon reads the file ENTIRELY in the
 * browser (`useImportConversation` → `FileReader`), parses it, and writes it into the on-device
 * encrypted store. The file's bytes NEVER leave the device.
 *
 * Visually this mirrors the upstream control (a labelled `Import` button with the `Import` lucide
 * icon and a spinner while working) so it drops into the Settings → Data tab unchanged. A hidden
 * `<input type="file" accept=".json">` drives the native file picker; the input is reset after each
 * pick so re-selecting the same file fires `onChange` again.
 *
 * Trust model (LOCKED): nothing is uploaded. The parse + the store write happen locally; the store
 * key never leaves the worker.
 */

import { useCallback, useRef, useState } from 'react';
import { Import } from 'lucide-react';
import { Spinner, Label, Button, useToastContext } from '@librechat/client';
import { useLocalize } from '~/hooks';
import { NotificationSeverity } from '~/common';
import { cn, logger } from '~/utils';
import { useImportConversation, UnsupportedImportError } from '~/store/useImportConversation';

export interface ImportConversationButtonProps {
  /** Optional max file size (bytes), e.g. from startup config; rejects larger files early. */
  maxFileSizeBytes?: number;
  className?: string;
}

export default function ImportConversationButton({
  maxFileSizeBytes,
  className,
}: ImportConversationButtonProps) {
  const localize = useLocalize();
  const { showToast } = useToastContext();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isUploading, setIsUploading] = useState(false);

  const { importFile } = useImportConversation({
    maxFileSizeBytes,
    onMutate: () => setIsUploading(true),
    onSuccess: () => {
      showToast({
        message: localize('com_ui_import_conversation_success'),
        status: NotificationSeverity.SUCCESS,
      });
      setIsUploading(false);
    },
    onError: (error) => {
      logger.error('Import error:', error);
      setIsUploading(false);
      const isUnsupportedType =
        error instanceof UnsupportedImportError ||
        (error?.toString().includes('Unsupported import type') ?? false);
      showToast({
        message: localize(
          isUnsupportedType
            ? 'com_ui_import_conversation_file_type_error'
            : 'com_ui_import_conversation_error',
        ),
        status: NotificationSeverity.ERROR,
      });
    },
  });

  const handleFileChange = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (file) {
        void importFile(file);
      }
      // Reset so picking the same file again still fires onChange.
      event.target.value = '';
    },
    [importFile],
  );

  const handleImportClick = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLButtonElement>) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        handleImportClick();
      }
    },
    [handleImportClick],
  );

  return (
    <div className={cn('flex items-center justify-between', className)}>
      <Label id="caladon-import-conversation-label">
        {localize('com_ui_import_conversation_info')}
      </Label>
      <Button
        variant="outline"
        onClick={handleImportClick}
        onKeyDown={handleKeyDown}
        disabled={isUploading}
        aria-label={localize('com_ui_import')}
        aria-labelledby="caladon-import-conversation-label"
      >
        {isUploading ? (
          <>
            <Spinner className="mr-1 w-4" />
            <span>{localize('com_ui_importing')}</span>
          </>
        ) : (
          <>
            <Import className="mr-1 flex h-4 w-4 items-center stroke-1" aria-hidden="true" />
            <span>{localize('com_ui_import')}</span>
          </>
        )}
      </Button>
      <input
        ref={fileInputRef}
        type="file"
        className={cn('hidden')}
        accept=".json"
        onChange={handleFileChange}
        aria-hidden="true"
      />
    </div>
  );
}
