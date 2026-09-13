/**
 * Content Script Helper for CyberNeura Chrome Extension.
 * Provides in-page warning banner integration when full interstitial redirect is not preferred.
 */

export function injectWarningBanner(message: string, riskScore: number): void {
  if (document.getElementById('cyberneura-warning-banner')) return;

  const banner = document.createElement('div');
  banner.id = 'cyberneura-warning-banner';
  banner.className = 'cyberneura-banner-root';
  banner.innerHTML = `
    <div class="cyberneura-banner-content">
      <span class="cyberneura-banner-icon">⚠️</span>
      <span class="cyberneura-banner-text">
        <strong>CyberNeura Security Warning:</strong> ${message} (Risk: ${riskScore}/100)
      </span>
      <button type="button" id="cyberneura-banner-dismiss" class="cyberneura-banner-btn">Dismiss</button>
    </div>
  `;
  document.body.prepend(banner);

  const dismissBtn = document.getElementById('cyberneura-banner-dismiss');
  if (dismissBtn) {
    dismissBtn.addEventListener('click', () => {
      banner.remove();
    });
  }
}
