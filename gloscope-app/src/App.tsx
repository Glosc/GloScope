import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

type ChatMessage = {
  id: string;
  role: "user" | "agent";
  text: string;
};

// Shape of ServerNotification values forwarded from Rust as
// "gloscope://notification" events. Only the fields M2 actually reads are
// declared; the enum has many more variants we don't handle yet.
type ServerNotification =
  | { method: "item/agentMessage/delta"; params: { itemId: string; delta: string } }
  | { method: "item/completed"; params: { item: { type: string; id: string; text?: string } } }
  | { method: "turn/completed"; params: Record<string, unknown> }
  | { method: "error"; params: { error: { message: string } } }
  | { method: string; params: unknown };

function App() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const streamingIds = useRef<Set<string>>(new Set());

  useEffect(() => {
    const unlisten = listen<ServerNotification>("gloscope://notification", (event) => {
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
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

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
