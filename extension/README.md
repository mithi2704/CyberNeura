# CyberNeura Chrome Browser Extension (Manifest V3)

The **CyberNeura Chrome Extension** provides real-time, automated URL security analysis as users navigate the web. Powered by CyberNeura's multi-source detection architecture, it combines LightGBM machine learning inference, multi-source external Threat Intelligence feeds, deterministic risk assessment, and selective AI security agent investigation into an autonomous in-browser defense shield.

---

## 1. System Architecture

```
                    CHROME BROWSER (User Navigation)
                                  │
                                  ▼
                    CYBERNEURA EXTENSION (MV3)
                                  │
               ┌──────────────────┴──────────────────┐
               ▼                                     ▼
         Local Cache                            Pre-Checks
       (300s TTL, <100ms)               (Filter internal schemes)
               │
               ▼ (Cache Miss)
                    FASTAPI BACKEND (/api/v1/extension/analyze)
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
     ML MODEL               THREAT INTEL                AI AGENT
   (LightGBM v2)        (Google/PhishTank/URLhaus) (Selective Multi-Step)
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  ▼
                         RISK + EVIDENCE ENGINE
                       (Phase 3 Deterministic)
                                  │
                                  ▼
                            POLICY ENGINE
                                  │
               ┌──────────────────┼──────────────────┐
               ▼                  ▼                  ▼
             ALLOW               WARN              BLOCK
               │                  │                  │
               ▼                  ▼                  ▼
         Continue Web       Warning Modal      Interstitial
          Navigation      (Continue Anyway)     (Tab Closed)
                                  │
                                  ▼
                         SUPABASE PERSISTENCE
                                  │
                                  ▼
                       SUPABASE REALTIME (Phase 5)
                                  │
                                  ▼
                         CYBERNEURA DASHBOARD
```

---

## 2. Manifest V3 & Least Privilege Permissions

The extension adheres strictly to the principle of least privilege:

| Permission | Technical Requirement & Justification |
| :--- | :--- |
| `webNavigation` | Detects top-level navigation events (`frameId === 0`) to evaluate destination URLs before page rendering. |
| `tabs` | Directs the active tab to the isolated extension warning/blocking interstitial (`interstitial.html`) when high-risk threats are confirmed. |
| `storage` | Stores short-term analysis cache (300s TTL), anonymous installation identifier, and user preferences locally. |
| `notifications` | Emits native desktop alert notifications for confirmed high and critical malicious threats. |
| Host Permissions (`http://*/*`, `https://*/*`) | Required to inspect destination URLs across the web for phishing and malware prevention. |

**Zero Privileged Surveillance**: The extension **never** requests `cookies`, `history`, `bookmarks`, `downloads`, `debugger`, or `clipboardRead`. It does NOT inspect webpage DOM contents, form inputs, or passwords.

---

## 3. Directory Structure

```
extension/
  ├── manifest.json              # Manifest V3 specification
  ├── package.json               # Build scripts & TypeScript dependencies
  ├── tsconfig.json              # Strict TypeScript compiler options
  ├── vite.config.ts             # Rollup/Vite multi-entry extension bundler
  ├── .env.example               # Public configuration template
  ├── README.md                  # Operational and development documentation
  ├── PRIVACY.md                 # Privacy and data minimization declaration
  ├── dist/                      # Production unpacked extension bundle
  │   ├── manifest.json
  │   ├── service-worker.js
  │   ├── icons/
  │   └── src/ (popup, options, interstitial)
  ├── icons/                     # Extension icons (16, 32, 48, 128 px)
  └── src/
      ├── background/
      │   └── service-worker.ts  # Navigation listener, cache check, backend dispatcher
      ├── interstitial/
      │   ├── interstitial.html  # Standalone warning & blocking interstitial
      │   ├── interstitial.ts    # Evidence populator & override handler
      │   └── interstitial.css   # Dark cyber glassmorphism styles
      ├── popup/
      │   ├── popup.html         # Active tab threat card, risk score & actions
      │   ├── popup.ts           # Popup controller & feedback reporter
      │   └── popup.css
      ├── options/
      │   ├── options.html       # Extension preferences & policy controls
      │   ├── options.ts
      │   └── options.css
      ├── security/
      │   ├── url-normalizer.ts  # Pre-checks & canonicalization
      │   ├── decision.ts        # Decision badges & fail-safe defaults
      │   └── permissions.ts     # Privacy boundary assertion
      ├── storage/
      │   └── storage.ts         # Chrome storage wrapper with 300s TTL cache
      ├── api/
      │   ├── client.ts          # FastAPI HTTP client with 8s timeout
      │   └── types.ts           # Strongly typed API contracts
      ├── messaging/
      │   ├── messages.ts        # Internal message protocols
      │   └── message-handler.ts # Router for background/popup communication
      └── ui/
          ├── notifications.ts   # Desktop notification dispatcher
          └── warning.ts         # Warning message formatters
```

---

## 4. Development & Build

### Prerequisites
- Node.js >= 18
- Running CyberNeura FastAPI Backend (`http://localhost:8000`)

### Building the Extension
```bash
cd extension
npm run build
```
This compiles TypeScript sources and generates a self-contained unpacked extension inside `extension/dist/`.

---

## 5. Loading Unpacked Extension in Chrome

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** using the toggle in the upper-right corner.
3. Click the **Load unpacked** button.
4. Select the `extension/dist/` directory (e.g. `E:\CyberNeura\extension\dist`).
5. The **CyberNeura - Real-Time URL Threat Detection** extension is now active!
6. Pin CyberNeura to your browser toolbar for quick visibility.

---

## 6. Real-Time Browsing Scenarios

| User Action | Extension Behavior | Dashboard Sync |
| :--- | :--- | :--- |
| **Visits `google.com`** | Local pre-check identifies benign destination. Risk score 0/100 (`SAFE`). Extension action badge displays green `OK`. Navigation proceeds seamlessly without interruption. | Logged in URL Logs as `ALLOW`. |
| **Visits Suspicious URL** | ML detects suspicious structure; score 55/100 (`SUSPICIOUS`). Tab redirects to CyberNeura Warning Interstitial. User may choose **Go Back** or **Continue Anyway**. | Emits `EXTENSION_WARNING_SHOWN` via Phase 5 Realtime. |
| **Visits Known Malicious URL** | URLhaus or PhishTank confirms active attack. Score 96/100 (`MALICIOUS`). Interstitial blocks navigation immediately without executing destination scripts. | Emits `EXTENSION_BLOCKED` + `SECURITY_ALERT_CREATED`. |
| **User Clicks "Continue Anyway"** | User overrides warning. Extension logs override to `/api/v1/extension/override` with installation ID and timestamp. Risk score remains unchanged. | Emits `EXTENSION_OVERRIDE` to Dashboard. |
| **Backend Unreachable** | Network drop or server maintenance. Extension applies configured fail-safe policy (`ALLOW` in balanced mode) to prevent breaking internet access. | UI indicates fallback status. |

---

## 7. Security Invariants

- **Zero Secrets**: No ML models, Google Web Risk keys, PhishTank keys, URLhaus keys, or database service keys exist in the extension.
- **Authoritative Backend**: The extension never makes autonomous security determinations; all decisions originate from the FastAPI Policy Engine.
- **Fail-Safe Browsing**: Fails open (`ALLOW`) by default during connectivity loss, unless administrator explicitly enables strict mode.
- **No In-Frame Execution**: Suspicious and malicious URLs are never loaded into iframes or evaluated in the background.
