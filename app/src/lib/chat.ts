// Which folder chats deserve a system notification after a refresh.
import type { ChatSummary } from './types';

/**
 * Newer messages from someone else that this device has not seen, except in the chat that is
 * open in a focused window. `prev === null`: lists were not loaded yet (right after unlock).
 */
export function toNotify(
  prev: ChatSummary[] | null,
  next: ChatSummary[],
  seen: Record<string, string>,
  openChat: string | null,
  focused: boolean,
): ChatSummary[] {
  if (!prev) return [];
  return next.filter((n) => {
    const before = prev.find((p) => p.collection_id === n.collection_id);
    const newer = !before || n.last_at > before.last_at;
    const unseen = n.last_at > (seen[n.collection_id] ?? '');
    const watching = focused && openChat === n.collection_id;
    return newer && unseen && !n.last_mine && !watching;
  });
}
