/**
 * Content Script for CyberNeura Chrome Extension.
 * Injects a floating AI Security Agent icon and expandable in-page chat assistant.
 * Encapsulated inside an isolated Shadow DOM to prevent host page CSS/JS conflicts.
 * Allows users to ask any question about the website they are visiting.
 */

(function () {
  // Prevent injection in non-top frames
  if (window.top !== window.self) return;
  if (document.getElementById('cyberneura-floating-agent-root')) return;

  // Retrieve current tab security status from service worker
  let currentStatus: any = {
    url: window.location.href,
    isInspected: false,
    decision: 'ALLOW',
    riskScore: 0,
    threatCategory: 'Safe',
    summary: 'Evaluating active browsing session...',
  };

  try {
    chrome.runtime.sendMessage({ type: 'GET_TAB_STATUS' }, (status) => {
      if (!chrome.runtime.lastError && status) {
        currentStatus = { ...currentStatus, ...status };
      }
      initFloatingAgent(currentStatus);
    });
  } catch {
    initFloatingAgent(currentStatus);
  }

  function initFloatingAgent(status: any) {
    if (document.getElementById('cyberneura-floating-agent-root')) return;

    const host = document.createElement('div');
    host.id = 'cyberneura-floating-agent-root';
    host.style.position = 'fixed';
    host.style.bottom = '24px';
    host.style.right = '24px';
    host.style.zIndex = '2147483647';
    host.style.pointerEvents = 'auto';

    const shadow = host.attachShadow({ mode: 'closed' });

    // Detect form inputs on active page
    const hasPasswordInputs = document.querySelectorAll('input[type="password"]').length > 0;
    const hasCardInputs =
      document.querySelectorAll(
        'input[name*="card"], input[id*="card"], input[name*="cc-"], input[autocomplete*="cc-"], input[placeholder*="card" i]'
      ).length > 0;
    const pageTitle = document.title || window.location.hostname;
    const currentUrl = window.location.href;
    const isHttps = window.location.protocol === 'https:';
    const domain = window.location.hostname || 'current site';

    const riskScore = typeof status.riskScore === 'number' ? status.riskScore : 0;
    const decision = status.decision || (riskScore >= 70 ? 'BLOCK' : riskScore >= 35 ? 'WARN' : 'ALLOW');
    const isThreat = decision === 'BLOCK' || riskScore >= 70;
    const isWarn = decision === 'WARN' || riskScore >= 35;

    let accentColor = '#10b981'; // Green (Safe)
    let statusLabel = 'Safe';
    if (isThreat) {
      accentColor = '#ef4444'; // Red (Threat)
      statusLabel = `Threat (${riskScore}/100)`;
    } else if (isWarn) {
      accentColor = '#f59e0b'; // Amber (Suspicious)
      statusLabel = `Suspicious (${riskScore}/100)`;
    } else {
      statusLabel = `Verified Safe (${riskScore}/100)`;
    }

    // Embed comprehensive scoped styles inside Shadow DOM
    const style = document.createElement('style');
    style.textContent = `
      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      }

      /* Trigger Floating Button */
      .cn-floating-btn {
        display: flex;
        align-items: center;
        gap: 10px;
        background: rgba(15, 23, 42, 0.94);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid rgba(255, 255, 255, 0.14);
        border-radius: 9999px;
        padding: 6px 14px 6px 6px;
        color: #f8fafc;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), 0 0 20px ${accentColor}33;
        cursor: pointer;
        user-select: none;
        transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        transform: translateY(0) scale(1);
      }
      .cn-floating-btn:hover {
        transform: translateY(-2px) scale(1.02);
        box-shadow: 0 14px 36px rgba(0, 0, 0, 0.6), 0 0 25px ${accentColor}55;
        border-color: ${accentColor}88;
      }
      .cn-floating-btn:active {
        transform: scale(0.98);
      }

      .cn-avatar-wrap {
        position: relative;
        width: 38px;
        height: 38px;
        border-radius: 50%;
        background: linear-gradient(135deg, #1e293b, #0f172a);
        display: flex;
        align-items: center;
        justify-content: center;
        border: 1.5px solid ${accentColor};
      }
      .cn-avatar-icon {
        font-size: 18px;
        line-height: 1;
      }
      .cn-pulse-dot {
        position: absolute;
        bottom: 0px;
        right: 0px;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background: ${accentColor};
        border: 2px solid #0f172a;
        box-shadow: 0 0 8px ${accentColor};
        animation: cn-pulse 2s infinite;
      }
      @keyframes cn-pulse {
        0%, 100% { transform: scale(1); opacity: 1; }
        50% { transform: scale(1.2); opacity: 0.8; }
      }

      .cn-btn-text {
        display: flex;
        flex-direction: column;
        line-height: 1.25;
      }
      .cn-btn-title {
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #94a3b8;
      }
      .cn-btn-status {
        font-size: 12px;
        font-weight: 600;
        color: ${accentColor};
      }

      /* Chat Panel Container */
      .cn-chat-panel {
        display: none;
        flex-direction: column;
        width: 380px;
        height: 540px;
        max-width: calc(100vw - 40px);
        max-height: calc(100vh - 50px);
        background: rgba(15, 23, 42, 0.97);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 18px;
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.7), 0 0 30px rgba(99, 102, 241, 0.15);
        overflow: hidden;
        animation: cn-slide-up 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
      }
      @keyframes cn-slide-up {
        from { opacity: 0; transform: translateY(20px) scale(0.96); }
        to { opacity: 1; transform: translateY(0) scale(1); }
      }

      /* Panel Header */
      .cn-header {
        padding: 14px 16px;
        background: linear-gradient(180deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.4));
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        display: flex;
        align-items: center;
        justify-content: space-between;
      }
      .cn-header-left {
        display: flex;
        align-items: center;
        gap: 10px;
      }
      .cn-header-title {
        font-size: 13px;
        font-weight: 700;
        color: #f8fafc;
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .cn-header-domain {
        font-size: 11px;
        color: #94a3b8;
        max-width: 170px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .cn-header-actions {
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .cn-icon-btn {
        width: 28px;
        height: 28px;
        border-radius: 8px;
        background: rgba(255, 255, 255, 0.06);
        border: 1px solid rgba(255, 255, 255, 0.08);
        color: #94a3b8;
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        transition: all 0.2s;
        font-size: 13px;
      }
      .cn-icon-btn:hover {
        background: rgba(255, 255, 255, 0.12);
        color: #f8fafc;
      }

      /* Site Context Banner */
      .cn-context-banner {
        padding: 8px 14px;
        background: rgba(30, 41, 59, 0.4);
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        display: flex;
        align-items: center;
        justify-content: space-between;
        font-size: 11px;
      }
      .cn-badge-pill {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 3px 8px;
        border-radius: 9999px;
        font-weight: 600;
        background: ${accentColor}1a;
        color: ${accentColor};
        border: 1px solid ${accentColor}44;
      }
      .cn-protocol-pill {
        color: ${isHttps ? '#38bdf8' : '#f87171'};
        display: flex;
        align-items: center;
        gap: 4px;
        font-weight: 500;
      }

      /* Chat Messages Body */
      .cn-chat-body {
        flex: 1;
        overflow-y: auto;
        padding: 14px;
        display: flex;
        flex-direction: column;
        gap: 12px;
        scroll-behavior: smooth;
      }
      .cn-chat-body::-webkit-scrollbar {
        width: 5px;
      }
      .cn-chat-body::-webkit-scrollbar-thumb {
        background: rgba(255, 255, 255, 0.15);
        border-radius: 9999px;
      }

      .cn-msg {
        display: flex;
        flex-direction: column;
        max-width: 86%;
        font-size: 12.5px;
        line-height: 1.45;
        word-break: break-word;
      }
      .cn-msg-agent {
        align-self: flex-start;
        background: rgba(30, 41, 59, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 14px 14px 14px 4px;
        padding: 10px 12px;
        color: #e2e8f0;
      }
      .cn-msg-agent strong, .cn-msg-agent b {
        color: #f8fafc;
        font-weight: 600;
      }
      .cn-msg-agent code {
        background: rgba(0, 0, 0, 0.3);
        padding: 2px 5px;
        border-radius: 4px;
        font-family: monospace;
        font-size: 11px;
        color: #38bdf8;
      }
      .cn-msg-user {
        align-self: flex-end;
        background: linear-gradient(135deg, #4f46e5, #0ea5e9);
        color: #ffffff;
        border-radius: 14px 14px 4px 14px;
        padding: 9px 12px;
        box-shadow: 0 4px 12px rgba(14, 165, 233, 0.25);
      }

      /* Quick Action Chips */
      .cn-chips-container {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-top: 4px;
      }
      .cn-chip {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        color: #cbd5e1;
        font-size: 11px;
        padding: 5px 10px;
        border-radius: 9999px;
        cursor: pointer;
        transition: all 0.2s;
        user-select: none;
      }
      .cn-chip:hover {
        background: rgba(99, 102, 241, 0.2);
        border-color: #6366f1;
        color: #ffffff;
        transform: translateY(-1px);
      }

      /* Typing Indicator */
      .cn-typing-indicator {
        display: none;
        align-self: flex-start;
        background: rgba(30, 41, 59, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 14px 14px 14px 4px;
        padding: 10px 14px;
        gap: 4px;
        align-items: center;
      }
      .cn-typing-dot {
        width: 6px;
        height: 6px;
        background: #38bdf8;
        border-radius: 50%;
        animation: cn-bounce 1.4s infinite ease-in-out both;
      }
      .cn-typing-dot:nth-child(1) { animation-delay: -0.32s; }
      .cn-typing-dot:nth-child(2) { animation-delay: -0.16s; }
      @keyframes cn-bounce {
        0%, 80%, 100% { transform: scale(0); }
        40% { transform: scale(1); }
      }

      /* Input Footer */
      .cn-footer {
        padding: 10px 12px;
        background: rgba(15, 23, 42, 0.95);
        border-top: 1px solid rgba(255, 255, 255, 0.08);
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .cn-input {
        flex: 1;
        background: rgba(30, 41, 59, 0.6);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 10px;
        padding: 9px 12px;
        color: #f8fafc;
        font-size: 12px;
        outline: none;
        transition: border-color 0.2s;
      }
      .cn-input:focus {
        border-color: #6366f1;
        background: rgba(30, 41, 59, 0.9);
      }
      .cn-input::placeholder {
        color: #64748b;
      }
      .cn-send-btn {
        width: 34px;
        height: 34px;
        border-radius: 10px;
        background: linear-gradient(135deg, #6366f1, #06b6d4);
        border: none;
        color: #ffffff;
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        transition: transform 0.15s, opacity 0.15s;
        flex-shrink: 0;
      }
      .cn-send-btn:hover {
        transform: scale(1.05);
      }
      .cn-send-btn:active {
        transform: scale(0.95);
      }
      .cn-send-btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
      }
    `;

    shadow.appendChild(style);

    // Floating Button (Collapsed View)
    const floatingBtn = document.createElement('div');
    floatingBtn.className = 'cn-floating-btn';
    floatingBtn.innerHTML = `
      <div class="cn-avatar-wrap">
        <span class="cn-avatar-icon">🧠</span>
        <span class="cn-pulse-dot"></span>
      </div>
      <div class="cn-btn-text">
        <span class="cn-btn-title">CyberNeura AI</span>
        <span class="cn-btn-status">${statusLabel}</span>
      </div>
    `;

    // Chat Panel (Expanded View)
    const chatPanel = document.createElement('div');
    chatPanel.className = 'cn-chat-panel';
    chatPanel.innerHTML = `
      <div class="cn-header">
        <div class="cn-header-left">
          <div class="cn-avatar-wrap" style="width: 30px; height: 30px;">
            <span style="font-size: 15px;">🧠</span>
          </div>
          <div>
            <div class="cn-header-title">
              CyberNeura AI
              <span style="display:inline-block; width:6px; height:6px; border-radius:50%; background:${accentColor};"></span>
            </div>
            <div class="cn-header-domain" title="${domain}">${domain}</div>
          </div>
        </div>
        <div class="cn-header-actions">
          <button class="cn-icon-btn" id="cn-clear-btn" title="Clear conversation">↺</button>
          <button class="cn-icon-btn" id="cn-close-btn" title="Minimize">✕</button>
        </div>
      </div>

      <div class="cn-context-banner">
        <div class="cn-protocol-pill">
          ${isHttps ? '🔒 HTTPS Encrypted' : '⚠️ Plaintext HTTP'}
        </div>
        <div class="cn-badge-pill">
          ${statusLabel}
        </div>
      </div>

      <div class="cn-chat-body" id="cn-chat-body">
        <!-- Messages rendered dynamically -->
      </div>

      <div class="cn-typing-indicator" id="cn-typing-indicator">
        <span class="cn-typing-dot"></span>
        <span class="cn-typing-dot"></span>
        <span class="cn-typing-dot"></span>
      </div>

      <div class="cn-footer">
        <input type="text" class="cn-input" id="cn-input-field" placeholder="Ask anything about this website..." />
        <button class="cn-send-btn" id="cn-send-btn" title="Send message">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="22" y1="2" x2="11" y2="13"></line>
            <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
          </svg>
        </button>
      </div>
    `;

    shadow.appendChild(floatingBtn);
    shadow.appendChild(chatPanel);
    document.documentElement.appendChild(host);

    // Elements inside shadow DOM
    const chatBody = shadow.getElementById('cn-chat-body') as HTMLDivElement;
    const inputField = shadow.getElementById('cn-input-field') as HTMLInputElement;
    const sendBtn = shadow.getElementById('cn-send-btn') as HTMLButtonElement;
    const closeBtn = shadow.getElementById('cn-close-btn') as HTMLButtonElement;
    const clearBtn = shadow.getElementById('cn-clear-btn') as HTMLButtonElement;
    const typingIndicator = shadow.getElementById('cn-typing-indicator') as HTMLDivElement;

    // Chat State
    const history: Array<{ role: string; content: string }> = [];

    // Toggle Chat Panel
    floatingBtn.addEventListener('click', () => {
      floatingBtn.style.display = 'none';
      chatPanel.style.display = 'flex';
      inputField.focus();
      if (history.length === 0) {
        renderWelcomeMessage();
      }
    });

    closeBtn.addEventListener('click', () => {
      chatPanel.style.display = 'none';
      floatingBtn.style.display = 'flex';
    });

    clearBtn.addEventListener('click', () => {
      history.length = 0;
      chatBody.innerHTML = '';
      renderWelcomeMessage();
    });

    // Send Message Handlers
    sendBtn.addEventListener('click', () => {
      submitUserQuery(inputField.value);
    });

    inputField.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        submitUserQuery(inputField.value);
      }
    });

    function renderWelcomeMessage() {
      const welcomeText = isThreat
        ? `🚨 **Warning: Threat Detected on ${domain}**\n\nThis site has been flagged with an elevated risk score of **${riskScore}/100**. Do NOT enter passwords, personal data, or credit card numbers.`
        : isWarn
        ? `⚠️ **Caution Advised for ${domain}**\n\nCyberNeura detected suspicious indicators (Risk: **${riskScore}/100**). ${
            !isHttps ? 'Additionally, this page is not encrypted (HTTP).' : ''
          } What would you like to know before continuing?`
        : `👋 **Welcome to ${domain}!**\n\nCyberNeura AI has verified this site as **Safe** (Risk: **${riskScore}/100** over ${
            isHttps ? 'secure HTTPS' : 'HTTP'
          }). ${hasPasswordInputs ? 'I also detected password fields on this page.' : ''}\n\nAsk me anything about this site's security!`;

      appendAgentMessage(welcomeText);

      // Add Quick Action Chips
      const chipsWrap = document.createElement('div');
      chipsWrap.className = 'cn-chips-container';

      const chips = [
        '🛡️ Is this website safe?',
        '🔑 Can I enter my password?',
        '💳 Is payment safe here?',
        '🔍 Why this risk score?',
      ];

      chips.forEach((chipText) => {
        const chip = document.createElement('div');
        chip.className = 'cn-chip';
        chip.textContent = chipText;
        chip.addEventListener('click', () => {
          submitUserQuery(chipText);
        });
        chipsWrap.appendChild(chip);
      });

      chatBody.appendChild(chipsWrap);
      scrollChatToBottom();
    }

    function appendUserMessage(text: string) {
      const msgDiv = document.createElement('div');
      msgDiv.className = 'cn-msg cn-msg-user';
      msgDiv.textContent = text;
      chatBody.appendChild(msgDiv);
      history.push({ role: 'user', content: text });
      scrollChatToBottom();
    }

    function appendAgentMessage(markdownText: string) {
      const msgDiv = document.createElement('div');
      msgDiv.className = 'cn-msg cn-msg-agent';
      msgDiv.innerHTML = formatMarkdown(markdownText);
      chatBody.appendChild(msgDiv);
      history.push({ role: 'assistant', content: markdownText });
      scrollChatToBottom();
    }

    function formatMarkdown(text: string): string {
      return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\n\n/g, '<br/><br/>')
        .replace(/\n/g, '<br/>');
    }

    function scrollChatToBottom() {
      chatBody.scrollTop = chatBody.scrollHeight;
    }

    function submitUserQuery(rawText: string) {
      const text = rawText.trim();
      if (!text) return;

      inputField.value = '';
      appendUserMessage(text);

      // Show typing indicator
      typingIndicator.style.display = 'flex';
      sendBtn.disabled = true;
      scrollChatToBottom();

      const payload = {
        url: currentUrl,
        question: text,
        risk_score: riskScore,
        decision: decision,
        threat_category: status.threatCategory,
        page_title: pageTitle,
        has_password_inputs: hasPasswordInputs,
        has_card_inputs: hasCardInputs,
        history: history.slice(-6),
      };

      try {
        chrome.runtime.sendMessage({ type: 'ASK_AI_AGENT', payload }, (response) => {
          typingIndicator.style.display = 'none';
          sendBtn.disabled = false;

          if (response && response.success && response.data && response.data.reply) {
            appendAgentMessage(response.data.reply);
          } else {
            // Local fallback
            appendAgentMessage(generateLocalResponse(text));
          }
        });
      } catch (err) {
        typingIndicator.style.display = 'none';
        sendBtn.disabled = false;
        appendAgentMessage(generateLocalResponse(text));
      }
    }

    function generateLocalResponse(query: string): string {
      const q = query.toLowerCase();
      if (q.includes('password') || q.includes('login') || q.includes('credential')) {
        if (!isHttps) {
          return `⚠️ **DANGER:** This page uses unencrypted HTTP. Entering your password here risks interception.`;
        }
        if (isThreat) {
          return `🚨 **DO NOT enter your password.** ${domain} has been classified as a threat (${riskScore}/100).`;
        }
        return `✅ **${domain}** uses HTTPS encryption and has a clean score (${riskScore}/100). It is safe to proceed, but make sure the URL in your browser bar is authentic.`;
      }

      if (q.includes('card') || q.includes('pay') || q.includes('checkout') || q.includes('buy')) {
        if (!isHttps) {
          return `⚠️ **NEVER enter financial details over HTTP.** Always look for the lock icon (HTTPS).`;
        }
        if (isThreat || isWarn) {
          return `⚠️ **Exercise high caution.** Due to risk indicators (${riskScore}/100), verify the merchant independently before paying.`;
        }
        return `✅ **${domain}** is encrypted over HTTPS with low risk (${riskScore}/100). Secure for standard purchases.`;
      }

      if (q.includes('safe') || q.includes('legit') || q.includes('phish') || q.includes('trust')) {
        if (isThreat) {
          return `🚨 **Unsafe Website.** ${domain} triggered active threat signatures with a risk score of ${riskScore}/100.`;
        }
        if (isWarn) {
          return `⚠️ **Suspicious Website.** ${domain} has a risk score of ${riskScore}/100. Avoid downloading files or sharing personal data.`;
        }
        return `🛡️ **Verified Safe.** ${domain} has a clean reputation (${riskScore}/100) with active TLS encryption.`;
      }

      return `CyberNeura Agent summary for **${domain}**:\n• Status: **${statusLabel}**\n• Protocol: ${
        isHttps ? 'HTTPS Encrypted' : 'HTTP Plaintext'
      }\n• Passwords on page: ${hasPasswordInputs ? 'Yes' : 'No'}\n\nFeel free to ask specific questions about credentials, payments, or domain identity!`;
    }
  }
})();
