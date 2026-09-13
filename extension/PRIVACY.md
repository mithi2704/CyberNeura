# CyberNeura Chrome Extension — Privacy Policy & Data Minimization

Last Updated: September 13, 2026
Version: 1.0.0

CyberNeura is engineered under the strict principle of **Privacy by Design**. The extension operates as an autonomous, defensive **URL security sensor**, NOT an endpoint surveillance or tracking tool.

---

## 1. What We Collect and Why

| Data Item | Purpose | Retention | Destination |
| :--- | :--- | :--- | :--- |
| **Top-Level Navigation URL** | Canonicalized and analyzed for malware, phishing, typosquatting, and social engineering indicators. | 30 days (security log retention) | CyberNeura Authoritative FastAPI backend |
| **Anonymous Installation ID** | Associates rate limits and security policies without tracking user identity or IP fingerprints. | Persisted locally until extension removal | Included with `/api/v1/extension/analyze` |
| **Security Decision & Telemetry** | Verifies analysis latency, cache hits, and policy compliance (`ALLOW`, `WARN`, `BLOCK`). | 30 days | In-memory store and Supabase `extension_events` |
| **User Override Action** | Logs when a user deliberately chooses "Continue Anyway" past a warning interstitial for compliance auditing. | 30 days | In-memory store and Supabase `extension_events` |
| **User False Positive Feedback** | Evaluates accuracy when a user reports a verdict via the extension popup. | Indefinite model calibration | Stored in extension reports repository |

---

## 2. What We NEVER Collect

CyberNeura strictly forbids accessing, inspecting, transmitting, or storing:

- ❌ **Webpage DOM Contents**: We do not read, scrape, or inspect the text, HTML, or images of websites you visit.
- ❌ **Form Inputs & Typed Text**: We never observe, capture, or log form inputs, keystrokes, or search bar queries.
- ❌ **Passwords & Credentials**: The extension cannot and will never intercept login credentials, tokens, or security answers.
- ❌ **Browser Cookies & Sessions**: We do not request the `cookies` permission and cannot view or access your authenticated sessions.
- ❌ **Browsing History**: We do not access or store your browser history (`chrome.history` is prohibited).
- ❌ **Downloads & Local Files**: We do not intercept, monitor, or scan local filesystem downloads in Phase 6.

---

## 3. Where Data is Sent

All inspection requests are dispatched securely over TLS/HTTPS (or `http://localhost:8000` during local development) to your configured CyberNeura instance:
- Default API Endpoint: `POST /api/v1/extension/analyze`
- No third-party ad networks, telemetry trackers, or external aggregators ever receive browsing data from the extension.

---

## 4. Local Caching & Freshness

- The extension maintains a **short-term local cache (TTL: 300 seconds)** in `chrome.storage.local`.
- When you re-visit or refresh a recently analyzed destination, the security verdict is rendered locally in **<100ms** without re-querying the backend.
- Users can purge all cached entries instantly via **Extension Settings ➔ Clear Local Cache**.

---

## 5. How to Disable Protection

1. Click the CyberNeura shield icon in your Chrome toolbar.
2. Click **⚙️ Settings** (or right-click the extension and select **Options**).
3. Toggle **Enable Real-Time Scanning** to **OFF**.
4. The extension will suspend URL analysis immediately.

---

## 6. How to Remove the Extension

1. Right-click the **CyberNeura** extension icon in your Chrome toolbar.
2. Select **Remove from Chrome...**.
3. In the confirmation dialog, click **Remove**.
4. All local storage, installation tokens, and cached verdicts will be permanently destroyed.
