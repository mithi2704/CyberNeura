import { aiClient } from '../lib/api/aiService';
import type { ChatMessage } from '../types';

export async function fetchChatHistory(_userId?: string): Promise<ChatMessage[]> {
  try {
    const res = await aiClient.get('/chat/history');
    if (res.data && Array.isArray(res.data)) {
      return res.data.map((r: any) => ({
        id: r.id || Math.random().toString(36).substring(7),
        role: r.role,
        content: r.content,
        timestamp: r.timestamp || new Date().toISOString(),
      }));
    }
    return [];
  } catch (err) {
    console.warn('Could not fetch chat history from backend:', err);
    return [];
  }
}

export async function sendChatMessage(content: string, _userId?: string, scanId?: string): Promise<ChatMessage> {
  const res = await aiClient.post('/chat', { message: content, scanId });

  const assistantMessage: ChatMessage = {
    id: Math.random().toString(36).substring(7),
    role: 'assistant',
    content: res.data.message || res.data.answer,
    timestamp: res.data.timestamp || new Date().toISOString(),
    scanId: res.data.scan_id || scanId,
    sessionId: res.data.session_id,
    risk: res.data.risk,
    confidence: res.data.confidence,
    threatCategory: res.data.threat_category,
    recommendations: res.data.recommendations,
    toolsUsed: res.data.tools_used,
    timeline: res.data.timeline,
    evidence: res.data.evidence,
  };

  return assistantMessage;
}
