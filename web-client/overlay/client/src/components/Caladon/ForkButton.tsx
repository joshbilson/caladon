/**
 * Caladon — ForkButton (Batch 1 client foundation, device-side fork UI).
 *
 * The device-side analogue of LibreChat's `Fork` message action. Upstream `Fork.tsx` opens a popover
 * to pick a server fork strategy (direct path / branches / target level) and POSTs to the gateway.
 * Caladon has no server-side conversation record — history lives ONLY in the on-device encrypted
 * store — so this is a single icon button that forks the direct lineage (root → this message,
 * inclusive) entirely on-device via `useForkConversation`, then seeds the cache and navigates. No
 * popover, no network, no plaintext leaving the device.
 *
 * It keeps the upstream visual language (the `GitFork` lucide icon, the hover-button classes, the
 * info/processing/success/error toasts, localized strings) so it drops into the message hover bar
 * next to the other actions and reads identically to the rest of the chat UI.
 */

import { useCallback } from 'react';
import { GitFork } from 'lucide-react';
import { Spinner, useToastContext } from '@librechat/client';
import { useLocalize } from '~/hooks';
import { NotificationSeverity } from '~/common';
import { cn } from '~/utils';
import { useForkConversation } from '~/store/useForkConversation';

export interface ForkButtonProps {
  /** The message the forked branch ends at (inclusive). */
  messageId: string;
  conversationId: string | null;
  /** Whether forking is available for this message (e.g. a persisted, non-streaming message). */
  forkingSupported?: boolean;
  /** When false, the button stays visible (e.g. the last message in the thread). */
  isLast?: boolean;
  className?: string;
}

export default function ForkButton({
  messageId,
  conversationId,
  forkingSupported = true,
  isLast = false,
  className,
}: ForkButtonProps) {
  const localize = useLocalize();
  const { showToast } = useToastContext();

  const { forkConversation, isLoading } = useForkConversation({
    onMutate: () => {
      showToast({
        message: localize('com_ui_fork_processing'),
        status: NotificationSeverity.INFO,
      });
    },
    onSuccess: () => {
      showToast({
        message: localize('com_ui_fork_success'),
        status: NotificationSeverity.SUCCESS,
      });
    },
    onError: () => {
      showToast({
        message: localize('com_ui_fork_error'),
        status: NotificationSeverity.ERROR,
      });
    },
  });

  const handleClick = useCallback(() => {
    if (!conversationId || !messageId || isLoading) {
      return;
    }
    void forkConversation({ conversationId, fromMessageId: messageId });
  }, [conversationId, messageId, isLoading, forkConversation]);

  if (!forkingSupported || !conversationId || !messageId) {
    return null;
  }

  const buttonStyle = cn(
    'hover-button rounded-lg p-1.5 text-text-secondary-alt',
    'hover:text-text-primary hover:bg-surface-hover',
    'md:group-hover:visible md:group-focus-within:visible md:group-[.final-completion]:visible',
    !isLast && 'md:opacity-0 md:group-hover:opacity-100 md:group-focus-within:opacity-100',
    'focus-visible:ring-2 focus-visible:ring-black dark:focus-visible:ring-white focus-visible:outline-none',
    isLoading && 'cursor-not-allowed opacity-60',
    className,
  );

  return (
    <button
      type="button"
      className={buttonStyle}
      onClick={handleClick}
      disabled={isLoading}
      aria-label={localize('com_ui_fork')}
      title={localize('com_ui_fork')}
    >
      {isLoading ? (
        <Spinner className="h-[19px] w-[19px]" />
      ) : (
        <GitFork size="19" aria-hidden="true" />
      )}
    </button>
  );
}
