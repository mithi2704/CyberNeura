/**
 * CyberNeura Node.js API Gateway.
 * Bridges React Frontend with FastAPI ML Service.
 */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');

const { checkMLHealth, getModelsInfo } = require('./services/mlClient');
const { handleScanURL, handleGetHistory } = require('./controllers/urlController');
const { handleDetectImage } = require('./controllers/imageController');

const app = express();
const PORT = process.env.PORT || 5000;
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:5173';

// Multer memory storage (no disk writes)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 },
});

// Middleware
app.use(cors({ origin: [CORS_ORIGIN, 'http://localhost:5173', 'http://127.0.0.1:5173'], credentials: true }));
app.use(express.json());

// --- Gateway Routes ---

// Health & Info
app.get('/health', async (req, res) => {
  try {
    const mlHealth = await checkMLHealth();
    return res.status(200).json({
      status: 'ok',
      service: 'cyberneura-node-gateway',
      ml_service: mlHealth,
    });
  } catch (err) {
    return res.status(200).json({
      status: 'degraded',
      service: 'cyberneura-node-gateway',
      ml_service: { status: 'unreachable', error: err.message },
    });
  }
});

app.get('/api/v1/models/info', async (req, res) => {
  try {
    const info = await getModelsInfo();
    return res.status(200).json(info);
  } catch (err) {
    return res.status(502).json({ error: 'ML_SERVICE_UNAVAILABLE', message: err.message });
  }
});

// URL Threat Scanning
app.post('/api/v1/scan/url', handleScanURL);
app.get('/api/v1/scan/history', handleGetHistory);

// AI Image Detection
app.post('/api/v1/detect/image', upload.single('file'), handleDetectImage);

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: 'NOT_FOUND', message: `Route ${req.method} ${req.path} does not exist.` });
});

// Start Server
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[CyberNeura Gateway] Running on http://localhost:${PORT}`);
    console.log(`[CyberNeura Gateway] Upstream ML Service: ${process.env.ML_SERVICE_URL || 'http://localhost:8000'}`);
  });
}

module.exports = app;

