(function(){(function(){if(window.top!==window.self||document.getElementById(`cyberneura-floating-agent-root`))return;let e={url:window.location.href,isInspected:!1,decision:`ALLOW`,riskScore:0,threatCategory:`Safe`,summary:`Evaluating active browsing session...`};try{chrome.runtime.sendMessage({type:`GET_TAB_STATUS`},n=>{!chrome.runtime.lastError&&n&&(e={...e,...n}),t(e)})}catch{t(e)}function t(e){if(document.getElementById(`cyberneura-floating-agent-root`))return;let t=document.createElement(`div`);t.id=`cyberneura-floating-agent-root`,t.style.position=`fixed`,t.style.bottom=`24px`,t.style.right=`24px`,t.style.zIndex=`2147483647`,t.style.pointerEvents=`auto`;let n=t.attachShadow({mode:`closed`}),r=document.querySelectorAll(`input[type="password"]`).length>0,i=document.querySelectorAll(`input[name*="card"], input[id*="card"], input[name*="cc-"], input[autocomplete*="cc-"], input[placeholder*="card" i]`).length>0,a=document.title||window.location.hostname,o=window.location.href,s=window.location.protocol===`https:`,c=window.location.hostname||`current site`,l=typeof e.riskScore==`number`?e.riskScore:0,u=e.decision||(l>=70?`BLOCK`:l>=35?`WARN`:`ALLOW`),d=u===`BLOCK`||l>=70,f=u===`WARN`||l>=35,p=`#10b981`,m=`Safe`;d?(p=`#ef4444`,m=`Threat (${l}/100)`):f?(p=`#f59e0b`,m=`Suspicious (${l}/100)`):m=`Verified Safe (${l}/100)`;let h=document.createElement(`style`);h.textContent=`
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
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), 0 0 20px ${p}33;
        cursor: pointer;
        user-select: none;
        transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        transform: translateY(0) scale(1);
      }
      .cn-floating-btn:hover {
        transform: translateY(-2px) scale(1.02);
        box-shadow: 0 14px 36px rgba(0, 0, 0, 0.6), 0 0 25px ${p}55;
        border-color: ${p}88;
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
        border: 1.5px solid ${p};
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
        background: ${p};
        border: 2px solid #0f172a;
        box-shadow: 0 0 8px ${p};
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
        color: ${p};
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
        background: ${p}1a;
        color: ${p};
        border: 1px solid ${p}44;
      }
      .cn-protocol-pill {
        color: ${s?`#38bdf8`:`#f87171`};
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
    `,n.appendChild(h);let g=document.createElement(`div`);g.className=`cn-floating-btn`,g.innerHTML=`
      <div class="cn-avatar-wrap">
        <span class="cn-avatar-icon">🧠</span>
        <span class="cn-pulse-dot"></span>
      </div>
      <div class="cn-btn-text">
        <span class="cn-btn-title">CyberNeura AI</span>
        <span class="cn-btn-status">${m}</span>
      </div>
    `;let _=document.createElement(`div`);_.className=`cn-chat-panel`,_.innerHTML=`
      <div class="cn-header">
        <div class="cn-header-left">
          <div class="cn-avatar-wrap" style="width: 30px; height: 30px;">
            <span style="font-size: 15px;">🧠</span>
          </div>
          <div>
            <div class="cn-header-title">
              CyberNeura AI
              <span style="display:inline-block; width:6px; height:6px; border-radius:50%; background:${p};"></span>
            </div>
            <div class="cn-header-domain" title="${c}">${c}</div>
          </div>
        </div>
        <div class="cn-header-actions">
          <button class="cn-icon-btn" id="cn-clear-btn" title="Clear conversation">↺</button>
          <button class="cn-icon-btn" id="cn-close-btn" title="Minimize">✕</button>
        </div>
      </div>

      <div class="cn-context-banner">
        <div class="cn-protocol-pill">
          ${s?`🔒 HTTPS Encrypted`:`⚠️ Plaintext HTTP`}
        </div>
        <div class="cn-badge-pill">
          ${m}
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
    `,n.appendChild(g),n.appendChild(_),document.documentElement.appendChild(t);let v=n.getElementById(`cn-chat-body`),y=n.getElementById(`cn-input-field`),b=n.getElementById(`cn-send-btn`),x=n.getElementById(`cn-close-btn`),S=n.getElementById(`cn-clear-btn`),C=n.getElementById(`cn-typing-indicator`),w=[];g.addEventListener(`click`,()=>{g.style.display=`none`,_.style.display=`flex`,y.focus(),w.length===0&&T()}),x.addEventListener(`click`,()=>{_.style.display=`none`,g.style.display=`flex`}),S.addEventListener(`click`,()=>{w.length=0,v.innerHTML=``,T()}),b.addEventListener(`click`,()=>{A(y.value)}),y.addEventListener(`keydown`,e=>{e.key===`Enter`&&(e.preventDefault(),A(y.value))});function T(){D(d?`🚨 **Warning: Threat Detected on ${c}**\n\nThis site has been flagged with an elevated risk score of **${l}/100**. Do NOT enter passwords, personal data, or credit card numbers.`:f?`⚠️ **Caution Advised for ${c}**\n\nCyberNeura detected suspicious indicators (Risk: **${l}/100**). ${s?``:`Additionally, this page is not encrypted (HTTP).`} What would you like to know before continuing?`:`👋 **Welcome to ${c}!**\n\nCyberNeura AI has verified this site as **Safe** (Risk: **${l}/100** over ${s?`secure HTTPS`:`HTTP`}). ${r?`I also detected password fields on this page.`:``}\n\nAsk me anything about this site's security!`);let e=document.createElement(`div`);e.className=`cn-chips-container`,[`🛡️ Is this website safe?`,`🔑 Can I enter my password?`,`💳 Is payment safe here?`,`🔍 Why this risk score?`].forEach(t=>{let n=document.createElement(`div`);n.className=`cn-chip`,n.textContent=t,n.addEventListener(`click`,()=>{A(t)}),e.appendChild(n)}),v.appendChild(e),k()}function E(e){let t=document.createElement(`div`);t.className=`cn-msg cn-msg-user`,t.textContent=e,v.appendChild(t),w.push({role:`user`,content:e}),k()}function D(e){let t=document.createElement(`div`);t.className=`cn-msg cn-msg-agent`,t.innerHTML=O(e),v.appendChild(t),w.push({role:`assistant`,content:e}),k()}function O(e){return e.replace(/&/g,`&amp;`).replace(/</g,`&lt;`).replace(/>/g,`&gt;`).replace(/\*\*(.*?)\*\*/g,`<strong>$1</strong>`).replace(/\*(.*?)\*/g,`<em>$1</em>`).replace(/`([^`]+)`/g,`<code>$1</code>`).replace(/\n\n/g,`<br/><br/>`).replace(/\n/g,`<br/>`)}function k(){v.scrollTop=v.scrollHeight}function A(t){let n=t.trim();if(!n)return;y.value=``,E(n),C.style.display=`flex`,b.disabled=!0,k();let s={url:o,question:n,risk_score:l,decision:u,threat_category:e.threatCategory,page_title:a,has_password_inputs:r,has_card_inputs:i,history:w.slice(-6)};try{chrome.runtime.sendMessage({type:`ASK_AI_AGENT`,payload:s},e=>{C.style.display=`none`,b.disabled=!1,e&&e.success&&e.data&&e.data.reply?D(e.data.reply):D(j(n))})}catch{C.style.display=`none`,b.disabled=!1,D(j(n))}}function j(e){let t=e.toLowerCase();return t.includes(`password`)||t.includes(`login`)||t.includes(`credential`)?s?d?`🚨 **DO NOT enter your password.** ${c} has been classified as a threat (${l}/100).`:`✅ **${c}** uses HTTPS encryption and has a clean score (${l}/100). It is safe to proceed, but make sure the URL in your browser bar is authentic.`:`⚠️ **DANGER:** This page uses unencrypted HTTP. Entering your password here risks interception.`:t.includes(`card`)||t.includes(`pay`)||t.includes(`checkout`)||t.includes(`buy`)?s?d||f?`⚠️ **Exercise high caution.** Due to risk indicators (${l}/100), verify the merchant independently before paying.`:`✅ **${c}** is encrypted over HTTPS with low risk (${l}/100). Secure for standard purchases.`:`⚠️ **NEVER enter financial details over HTTP.** Always look for the lock icon (HTTPS).`:t.includes(`safe`)||t.includes(`legit`)||t.includes(`phish`)||t.includes(`trust`)?d?`🚨 **Unsafe Website.** ${c} triggered active threat signatures with a risk score of ${l}/100.`:f?`⚠️ **Suspicious Website.** ${c} has a risk score of ${l}/100. Avoid downloading files or sharing personal data.`:`🛡️ **Verified Safe.** ${c} has a clean reputation (${l}/100) with active TLS encryption.`:`CyberNeura Agent summary for **${c}**:\n• Status: **${m}**\n• Protocol: ${s?`HTTPS Encrypted`:`HTTP Plaintext`}\n• Passwords on page: ${r?`Yes`:`No`}\n\nFeel free to ask specific questions about credentials, payments, or domain identity!`}}})()})();