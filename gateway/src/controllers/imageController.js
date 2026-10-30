/**
 * Image Detection Controller.
 * Validates uploads in memory and dispatches to FastAPI ML Service.
 */
const { detectImage } = require('../services/mlClient');

// Allowed image MIME types
const ALLOWED_MIME_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp']);
const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25 MB

async function handleDetectImage(req, res) {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'NO_FILE',
        message: 'No image file uploaded. Send multipart form with field name "file".',
      });
    }

    const { buffer, originalname, mimetype, size } = req.file;

    if (!ALLOWED_MIME_TYPES.has(mimetype)) {
      return res.status(400).json({
        success: false,
        error: 'INVALID_FORMAT',
        message: `Unsupported image format (${mimetype}). Allowed: JPEG, PNG, WEBP.`,
      });
    }

    if (size > MAX_FILE_SIZE) {
      return res.status(413).json({
        success: false,
        error: 'FILE_TOO_LARGE',
        message: 'Image size exceeds maximum 25MB boundary.',
      });
    }

    // Forward buffer safely in-memory without disk leaks
    const mlResponse = await detectImage(buffer, originalname, mimetype);

    return res.status(200).json(mlResponse);
  } catch (error) {
    const status = error.response ? error.response.status : 500;
    const message = error.response?.data?.detail || error.message || 'Image detection failed';
    return res.status(status).json({
      success: false,
      error: 'DETECTION_ERROR',
      message,
    });
  }
}

module.exports = {
  handleDetectImage,
};

