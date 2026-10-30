/**
 * ML Service Client for Node.js API Gateway.
 * Dispatches requests to Python FastAPI ML backend.
 */
const axios = require('axios');
const FormData = require('form-data');

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://localhost:8000';

const mlClient = axios.create({
  baseURL: ML_SERVICE_URL,
  timeout: 15000,
});

async function checkMLHealth() {
  const res = await mlClient.get('/health');
  return res.data;
}

async function getModelsInfo() {
  const res = await mlClient.get('/api/v1/models/info');
  return res.data;
}

async function scanURL(url) {
  const res = await mlClient.post('/api/v1/scan/url', { url });
  return res.data;
}

async function detectImage(fileBuffer, originalname, mimetype) {
  const form = new FormData();
  form.append('file', fileBuffer, {
    filename: originalname || 'image.jpg',
    contentType: mimetype || 'image/jpeg',
  });

  const res = await mlClient.post('/api/v1/detect/image', form, {
    headers: {
      ...form.getHeaders(),
    },
    maxContentLength: 25 * 1024 * 1024,
    maxBodyLength: 25 * 1024 * 1024,
  });

  return res.data;
}

module.exports = {
  checkMLHealth,
  getModelsInfo,
  scanURL,
  detectImage,
};

