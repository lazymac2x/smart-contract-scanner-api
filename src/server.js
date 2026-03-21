/**
 * Smart Contract Scanner API — REST Server
 * Premium Solidity vulnerability detection service
 */

const express = require('express');
const cors = require('cors');
const { scan, analyzeGas, VULNERABILITY_CATALOG } = require('./scanner');
const { generateReport } = require('./report');

const app = express();
const PORT = process.env.PORT || 5200;

// ─── Middleware ──────────────────────────────────────────────────────────────────

app.use(cors());
app.use(express.json({ limit: '2mb' }));

// Request logging
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - start;
    console.log(`${req.method} ${req.path} ${res.statusCode} ${ms}ms`);
  });
  next();
});

// ─── Validation ─────────────────────────────────────────────────────────────────

function validateSolidityCode(req, res, next) {
  const { code } = req.body;
  if (!code || typeof code !== 'string') {
    return res.status(400).json({
      error: 'Missing or invalid "code" field',
      message: 'Request body must include a "code" field containing Solidity source code as a string.',
      example: { code: 'pragma solidity ^0.8.0; contract Example { ... }' },
    });
  }
  if (code.length > 500000) {
    return res.status(413).json({
      error: 'Contract too large',
      message: 'Source code exceeds 500KB limit. Split into smaller files if needed.',
    });
  }
  next();
}

// ─── Routes ─────────────────────────────────────────────────────────────────────

// Health check
app.get('/', (req, res) => {
  res.json({
    name: 'Smart Contract Scanner API',
    version: '1.0.0',
    status: 'operational',
    endpoints: {
      scan: 'POST /api/v1/scan',
      quickScan: 'POST /api/v1/quick-scan',
      gasAnalysis: 'POST /api/v1/gas-analysis',
      vulnerabilities: 'GET /api/v1/vulnerabilities',
    },
  });
});

// Full scan — comprehensive vulnerability analysis
app.post('/api/v1/scan', validateSolidityCode, (req, res) => {
  try {
    const { code } = req.body;
    const scanResult = scan(code, { quick: false });
    const report = generateReport(scanResult);
    res.json({
      success: true,
      ...report,
    });
  } catch (err) {
    console.error('Scan error:', err);
    res.status(500).json({
      success: false,
      error: 'Scan failed',
      message: err.message,
    });
  }
});

// Quick scan — top 5 critical checks only
app.post('/api/v1/quick-scan', validateSolidityCode, (req, res) => {
  try {
    const { code } = req.body;
    const scanResult = scan(code, { quick: true });
    const report = generateReport(scanResult);
    res.json({
      success: true,
      ...report,
    });
  } catch (err) {
    console.error('Quick scan error:', err);
    res.status(500).json({
      success: false,
      error: 'Quick scan failed',
      message: err.message,
    });
  }
});

// Gas analysis — optimization suggestions only
app.post('/api/v1/gas-analysis', validateSolidityCode, (req, res) => {
  try {
    const { code } = req.body;
    const suggestions = analyzeGas(code);
    res.json({
      success: true,
      gasOptimization: {
        suggestions,
        totalSuggestions: suggestions.length,
        note: 'Estimated savings are approximate and depend on contract usage patterns.',
      },
    });
  } catch (err) {
    console.error('Gas analysis error:', err);
    res.status(500).json({
      success: false,
      error: 'Gas analysis failed',
      message: err.message,
    });
  }
});

// List all detectable vulnerabilities
app.get('/api/v1/vulnerabilities', (req, res) => {
  res.json({
    success: true,
    vulnerabilities: VULNERABILITY_CATALOG.map((v) => ({
      id: v.id,
      name: v.name,
      severity: v.category,
      description: v.description,
      swcReference: v.owasp,
    })),
    totalDetectors: VULNERABILITY_CATALOG.length,
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    message: `${req.method} ${req.path} is not a valid endpoint.`,
    availableEndpoints: {
      'POST /api/v1/scan': 'Full vulnerability scan',
      'POST /api/v1/quick-scan': 'Quick scan (critical checks only)',
      'POST /api/v1/gas-analysis': 'Gas optimization suggestions',
      'GET /api/v1/vulnerabilities': 'List detectable vulnerabilities',
    },
  });
});

// ─── Start ──────────────────────────────────────────────────────────────────────

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Smart Contract Scanner API running on port ${PORT}`);
    console.log(`Endpoints:`);
    console.log(`  POST http://localhost:${PORT}/api/v1/scan`);
    console.log(`  POST http://localhost:${PORT}/api/v1/quick-scan`);
    console.log(`  POST http://localhost:${PORT}/api/v1/gas-analysis`);
    console.log(`  GET  http://localhost:${PORT}/api/v1/vulnerabilities`);
  });
}

module.exports = app;
