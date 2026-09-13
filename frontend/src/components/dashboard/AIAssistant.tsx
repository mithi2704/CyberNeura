import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { fetchChatHistory, sendChatMessage } from '../../services/chatService';
import type { ChatMessage } from '../../types';
import { GlassCard } from '../ui/GlassCard';
import { Send, Bot, User, ShieldAlert, CheckCircle2 } from 'lucide-react';

export const AIAssistant: React.FC = () => {
  const { user } = useAuth();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  const loadHistory = async () => {
    const history = await fetchChatHistory();
    setMessages(history);
  };

  useEffect(() => {
    loadHistory();
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const handleSend = async (textToSend?: string) => {
    const text = textToSend || input;
    if (!text.trim()) return;

    if (!textToSend) setInput('');
    setLoading(true);

    // Optimistically add user message
    const userMsg: ChatMessage = {
      id: Math.random().toString(),
      role: 'user',
      content: text,
      timestamp: new Date().toISOString(),
    };
    setMessages(prev => [...prev, userMsg]);

    try {
      const response = await sendChatMessage(text, user?.uid);
      setMessages(prev => [...prev, response]);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <GlassCard className="w-full flex flex-col h-[380px]" hoverEffect={false}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-cyber-inner-border pb-3">
        <div className="flex items-center gap-2">
          <Bot className="w-5 h-5 text-cyber-blue" />
          <h3 className="text-sm font-semibold text-cyber-text font-cyber tracking-wide">
            AI Security Assistant
          </h3>
        </div>
        <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyber-blue/10 text-cyber-blue border border-cyber-blue/20 font-mono flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-cyber-blue animate-pulse"></span>
          Realtime Agent Active
        </span>
      </div>

      {/* Messages Scroll Area */}
      <div className="flex-1 overflow-y-auto custom-scrollbar my-4 space-y-3 pr-1 text-xs font-light">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex gap-2.5 max-w-[92%] ${
              msg.role === 'user' ? 'ml-auto flex-row-reverse' : 'mr-auto'
            }`}
          >
            <div
              className={`w-6 h-6 rounded-full flex items-center justify-center shrink-0 border ${
                msg.role === 'user'
                  ? 'bg-cyber-purple/20 border-cyber-purple/40 text-cyber-purple'
                  : 'bg-cyber-blue/10 border-cyber-blue/30 text-cyber-blue'
              }`}
            >
              {msg.role === 'user' ? <User className="w-3.5 h-3.5" /> : <Bot className="w-3.5 h-3.5" />}
            </div>

            <div
              className={`p-3 rounded-xl border leading-relaxed ${
                msg.role === 'user'
                  ? 'bg-cyber-inner border-cyber-inner-border text-gray-200 rounded-tr-none'
                  : 'bg-cyber-inner border-cyber-blue/10 text-cyber-text rounded-tl-none'
              }`}
            >
              {/* Message text with basic formatting */}
              <div className="space-y-1.5 whitespace-pre-wrap break-words">
                {msg.content}
              </div>

              {/* Assessment Chips if returned by Agent */}
              {msg.risk !== undefined && (
                <div className="mt-2.5 pt-2 border-t border-cyber-inner-border/60 flex items-center gap-2 flex-wrap">
                  <span
                    className={`inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded border ${
                      msg.risk >= 80
                        ? 'bg-red-500/20 text-red-400 border-red-500/30'
                        : msg.risk >= 40
                        ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                        : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                    }`}
                  >
                    <ShieldAlert className="w-2.5 h-2.5" />
                    Risk: {msg.risk}/100
                  </span>
                  {msg.confidence !== undefined && (
                    <span className="text-[10px] text-cyber-muted font-mono">
                      Confidence: {msg.confidence}%
                    </span>
                  )}
                  {msg.threatCategory && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyber-purple/10 text-cyber-purple border border-cyber-purple/20 font-mono">
                      {msg.threatCategory}
                    </span>
                  )}
                </div>
              )}

              {/* Agent Activity Timeline */}
              {msg.timeline && msg.timeline.length > 0 && (
                <div className="mt-2 pt-1.5 border-t border-cyber-inner-border/40 flex flex-wrap gap-1">
                  {msg.timeline.map((item, idx) => (
                    <span
                      key={idx}
                      className="inline-flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded bg-cyber-blue/5 text-cyber-blue/80 border border-cyber-blue/15"
                    >
                      <CheckCircle2 className="w-2.5 h-2.5 text-emerald-400" />
                      {item.step.replace(/_/g, ' ')}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
        {loading && (
          <div className="flex gap-2.5 max-w-[80%] mr-auto items-center">
            <div className="w-6 h-6 rounded-full bg-cyber-blue/10 border border-cyber-blue/30 flex items-center justify-center text-cyber-blue">
              <Bot className="w-3.5 h-3.5" />
            </div>
            <div className="p-2.5 px-3 rounded-xl bg-cyber-inner border border-cyber-blue/10 flex items-center gap-2 rounded-tl-none text-xs text-cyber-muted">
              <span className="w-1.5 h-1.5 bg-cyber-blue rounded-full animate-bounce"></span>
              <span className="w-1.5 h-1.5 bg-cyber-blue rounded-full animate-bounce [animation-delay:0.2s]"></span>
              <span className="w-1.5 h-1.5 bg-cyber-blue rounded-full animate-bounce [animation-delay:0.4s]"></span>
              <span className="text-[10px] text-cyber-blue/80 font-mono ml-1">
                Agent investigating & correlating evidence...
              </span>
            </div>
          </div>
        )}
        <div ref={scrollRef}></div>
      </div>

      {/* Chat Input form */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSend();
        }}
        className="flex gap-2"
      >
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask about this link, why it's malicious, or investigate deeply..."
          className="flex-1 bg-cyber-input border border-cyber-inner-border rounded-xl px-3 py-2.5 text-xs text-cyber-text placeholder:text-cyber-muted focus:outline-none focus:border-cyber-blue/50 transition duration-300"
          disabled={loading}
        />
        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyber-blue to-cyber-purple flex items-center justify-center text-[#050814] hover:shadow-glow active:scale-95 disabled:opacity-50 disabled:pointer-events-none transition duration-300 shrink-0 cursor-pointer"
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </GlassCard>
  );
};
export default AIAssistant;
