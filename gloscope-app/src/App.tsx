import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

type ChatMessage = {
  id: string;
  role: "user" | "agent";
  text: string;
};

type FileUpdateChange = {
  path: string;
  kind: { type: "add" | "delete" | "update" };
  diff: string;
};

type PatchApprovalRequest = {
  requestId: string;
  itemId: string;
  reason: string | null;
};

type FileChangeItem = { type: "fileChange"; id: string; changes: FileUpdateChange[]; status: string };

// Shape of ServerNotification values forwarded from Rust as
// "gloscope://notification" events. Only the fields M2/M6b actually read are
// declared; the enum has many more variants we don't handle yet.
type ServerNotification =
  | { method: "item/agentMessage/delta"; params: { itemId: string; delta: string } }
  | {
      method: "item/started" | "item/completed";
      params: {
        item:
          | { type: "agentMessage"; id: string; text?: string }
          | FileChangeItem
          | { type: string; id: string };
      };
    }
  | { method: "turn/completed"; params: Record<string, unknown> }
  | { method: "error"; params: { error: { message: string } } }
  | { method: string; params: unknown };

function App() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const streamingIds = useRef<Set<string>>(new Set());
  // fileChange items seen via item/started or item/completed, keyed by item id, so a
  // pending patch approval (keyed by the same item id) can show the actual diff.
  const [fileChanges, setFileChanges] = useState<Record<string, FileChangeItem>>({});
  const [pendingApprovals, setPendingApprovals] = useState<PatchApprovalRequest[]>([]);
  const [respondingTo, setRespondingTo] = useState<string | null>(null);

  useEffect(() => {
    const unlistenNotification = listen<ServerNotification>("gloscope://notification", (event) => {
      const notification = event.payload;
      switch (notification.method) {
        case "item/agentMessage/delta": {
          const { itemId, delta } = notification.params as {
            itemId: string;
            delta: string;
          };
          setMessages((prev) => {
            if (streamingIds.current.has(itemId)) {
              return prev.map((m) => (m.id === itemId ? { ...m, text: m.text + delta } : m));
            }
            streamingIds.current.add(itemId);
            return [...prev, { id: itemId, role: "agent", text: delta }];
          });
          break;
        }
        case "item/started":
        case "item/completed": {
          const { item } = notification.params as {
            item: { type: string; id: string; text?: string };
          };
          if (item.type === "agentMessage" && typeof item.text === "string") {
            setMessages((prev) => {
              if (streamingIds.current.has(item.id)) {
                return prev.map((m) => (m.id === item.id ? { ...m, text: item.text! } : m));
              }
              streamingIds.current.add(item.id);
              return [...prev, { id: item.id, role: "agent", text: item.text! }];
            });
          } else if (item.type === "fileChange") {
            const fileChange = item as FileChangeItem;
            setFileChanges((prev) => ({ ...prev, [fileChange.id]: fileChange }));
          }
          break;
        }
        case "error": {
          const { error } = notification.params as { error: { message: string } };
          setMessages((prev) => [
            ...prev,
            { id: crypto.randomUUID(), role: "agent", text: `[error] ${error.message}` },
          ]);
          break;
        }
        default:
          break;
      }
    });
    const unlistenApproval = listen<PatchApprovalRequest>(
      "gloscope://patchApprovalRequest",
      (event) => {
        setPendingApprovals((prev) => [...prev, event.payload]);
      },
    );
    return () => {
      unlistenNotification.then((fn) => fn());
      unlistenApproval.then((fn) => fn());
    };
  }, []);

  async function respondToApproval(requestId: string, accept: boolean) {
    setRespondingTo(requestId);
    try {
      await invoke("respond_to_patch_approval", { requestId, accept });
      setPendingApprovals((prev) => prev.filter((req) => req.requestId !== requestId));
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        { id: crypto.randomUUID(), role: "agent", text: `[error] ${String(err)}` },
      ]);
    } finally {
      setRespondingTo(null);
    }
  }

  async function sendMessage() {
    const text = input.trim();
    if (!text || sending) return;
    setMessages((prev) => [...prev, { id: crypto.randomUUID(), role: "user", text }]);
    setInput("");
    setSending(true);
    try {
      await invoke("send_message", { message: text });
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        { id: crypto.randomUUID(), role: "agent", text: `[error] ${String(err)}` },
      ]);
    } finally {
      setSending(false);
    }
  }

  return (
    <main className="container">
      <h1>GloScope</h1>
      <div className="chat-log">
        {messages.map((m) => (
          <div key={m.id} className={`chat-message chat-message--${m.role}`}>
            <strong>{m.role === "user" ? "You" : "Agent"}:</strong> {m.text}
          </div>
        ))}
      </div>
      {pendingApprovals.map((req) => {
        const fileChange = fileChanges[req.itemId];
        return (
          <div key={req.requestId} className="patch-approval">
            <div className="patch-approval__header">
              Agent wants to apply a file change
              {req.reason ? `: ${req.reason}` : ""}
            </div>
            {fileChange ? (
              fileChange.changes.map((change) => (
                <div key={change.path} className="patch-approval__change">
                  <div className="patch-approval__path">
                    {change.kind.type} {change.path}
                  </div>
                  <pre className="patch-approval__diff">{change.diff}</pre>
                </div>
              ))
            ) : (
              <div className="patch-approval__path">(waiting for diff content...)</div>
            )}
            <div className="patch-approval__actions">
              <button
                type="button"
                disabled={respondingTo === req.requestId}
                onClick={() => respondToApproval(req.requestId, true)}
              >
                Accept
              </button>
              <button
                type="button"
                disabled={respondingTo === req.requestId}
                onClick={() => respondToApproval(req.requestId, false)}
              >
                Decline
              </button>
            </div>
          </div>
        );
      })}
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          sendMessage();
        }}
      >
        <input
          value={input}
          onChange={(e) => setInput(e.currentTarget.value)}
          placeholder="Message the agent..."
          disabled={sending}
        />
        <button type="submit" disabled={sending}>
          {sending ? "Sending..." : "Send"}
        </button>
      </form>
    </main>
  );
}

export default App;
