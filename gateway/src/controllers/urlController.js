/**
 * URL Scan Controller.
 * Validates URLs, queries ML Service, and maintains scan history.
 */
const { scanURL } = require('../services/mlClient');

// In-memory scan history buffer (retaining last 100 scans)
const scanHistory = [];

async function handleScanURL(req, res) {
  try {
    const { url } = req.body;
    if (!url || typeof url !== 'string' || !url.trim()) {
      return res.status(400).json({
        success: false,
        error: 'INVALID_INPUT',
        message: 'A valid "url" string is required in request body.',
      });
    }

    const cleanUrl = url.trim();
    const mlResponse = await scanURL(cleanUrl);

    const historyRecord = {
      id: `scan-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      url: cleanUrl,
      prediction: mlResponse.data.prediction,
      phishingProbability: mlResponse.data.phishing_probability,
      legitimateProbability: mlResponse.data.legitimate_probability,
      modelVersion: mlResponse.data.model_version,
      timestamp: new Date().toISOString(),
    };

    scanHistory.unshift(historyRecord);
    if (scanHistory.length > 100) scanHistory.pop();

    return res.status(200).json({
      ...mlResponse,
      scan_id: historyRecord.id,
      timestamp: historyRecord.timestamp,
    });
  } catch (error) {
    const status = error.response ? error.response.status : 500;
    const message = error.response?.data?.detail || error.message || 'Scan failed';
    return res.status(status).json({
      success: false,
      error: 'SCAN_ERROR',
      message,
    });
  }
}

function handleGetHistory(req, res) {
  const limit = parseInt(req.query.limit, 10) || 20;
  return res.status(200).json({
    success: true,
    count: Math.min(limit, scanHistory.length),
    items: scanHistory.slice(0, limit),
  });
}

module.exports = {
  handleScanURL,
  handleGetHistory,
};

