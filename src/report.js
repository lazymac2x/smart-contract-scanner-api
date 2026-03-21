/**
 * Audit Report Generator
 * Produces structured security audit reports from scanner findings
 */

const SEVERITY_WEIGHTS = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 1,
};

const RISK_LEVELS = [
  { maxScore: 10, level: 'Safe', emoji: 'PASS', color: '#00c853' },
  { maxScore: 30, level: 'Low', emoji: 'LOW', color: '#ffeb3b' },
  { maxScore: 55, level: 'Medium', emoji: 'MEDIUM', color: '#ff9800' },
  { maxScore: 80, level: 'High', emoji: 'HIGH', color: '#ff5722' },
  { maxScore: 100, level: 'Critical', emoji: 'CRITICAL', color: '#d50000' },
];

function calculateRiskScore(findings) {
  if (findings.length === 0) return 0;

  let rawScore = 0;
  for (const f of findings) {
    const weight = SEVERITY_WEIGHTS[f.severity] || 1;
    const confidenceMultiplier = f.confidence === 'high' ? 1.0 : f.confidence === 'medium' ? 0.7 : 0.4;
    rawScore += weight * confidenceMultiplier;
  }

  // Normalize to 0-100 scale (cap at 100)
  return Math.min(100, Math.round(rawScore));
}

function getRiskLevel(score) {
  for (const level of RISK_LEVELS) {
    if (score <= level.maxScore) return level;
  }
  return RISK_LEVELS[RISK_LEVELS.length - 1];
}

function groupBySeverity(findings) {
  const groups = { critical: [], high: [], medium: [], low: [], info: [] };
  for (const f of findings) {
    if (groups[f.severity]) {
      groups[f.severity].push(f);
    }
  }
  return groups;
}

function generateSummaryStats(findings) {
  const grouped = groupBySeverity(findings);
  return {
    total: findings.length,
    critical: grouped.critical.length,
    high: grouped.high.length,
    medium: grouped.medium.length,
    low: grouped.low.length,
    info: grouped.info.length,
  };
}

function generateRecommendations(findings) {
  const recommendations = [];
  const seen = new Set();

  // Priority recommendations based on findings
  const grouped = groupBySeverity(findings);

  if (grouped.critical.length > 0) {
    recommendations.push({
      priority: 'immediate',
      text: `Address ${grouped.critical.length} CRITICAL issue(s) before deployment. These vulnerabilities can lead to total loss of funds.`,
    });
  }

  if (grouped.high.length > 0) {
    recommendations.push({
      priority: 'high',
      text: `Fix ${grouped.high.length} HIGH severity issue(s). These can cause significant financial loss or contract malfunction.`,
    });
  }

  // Deduplicated specific recommendations
  for (const f of findings) {
    const key = f.id;
    if (seen.has(key)) continue;
    seen.add(key);

    recommendations.push({
      priority: f.severity,
      finding: f.id,
      text: f.recommendation,
    });
  }

  // General best practices
  recommendations.push({
    priority: 'general',
    text: 'Consider a professional audit from a reputable firm (Trail of Bits, OpenZeppelin, Consensys Diligence) before mainnet deployment.',
  });
  recommendations.push({
    priority: 'general',
    text: 'Implement comprehensive unit tests with >95% code coverage. Use fuzzing tools like Echidna or Foundry fuzz testing.',
  });
  recommendations.push({
    priority: 'general',
    text: 'Deploy to a testnet first and run integration tests. Consider a bug bounty program via Immunefi.',
  });

  return recommendations;
}

function generateReport(scanResult) {
  const { findings, metadata, gasAnalysis } = scanResult;
  const riskScore = calculateRiskScore(findings);
  const riskLevel = getRiskLevel(riskScore);
  const stats = generateSummaryStats(findings);
  const grouped = groupBySeverity(findings);
  const recommendations = generateRecommendations(findings);

  return {
    report: {
      title: 'Smart Contract Security Audit Report',
      generatedAt: new Date().toISOString(),
      scanner: 'smart-contract-scanner-api v1.0.0',

      overview: {
        riskScore,
        riskLevel: riskLevel.level,
        riskIndicator: riskLevel.emoji,
        summary: stats,
        verdict: riskScore <= 10
          ? 'No significant vulnerabilities detected. The contract follows security best practices.'
          : riskScore <= 30
            ? 'Minor issues found. The contract is relatively safe but has room for improvement.'
            : riskScore <= 55
              ? 'Moderate risk. Several issues should be addressed before production deployment.'
              : riskScore <= 80
                ? 'High risk. Significant vulnerabilities found that must be fixed before deployment.'
                : 'Critical risk. The contract has severe vulnerabilities that WILL lead to loss of funds if deployed.',
      },

      contractInfo: {
        linesOfCode: metadata.linesOfCode,
        solidityVersion: metadata.solidityVersion
          ? `${metadata.solidityVersion.major}.${metadata.solidityVersion.minor}.${metadata.solidityVersion.patch}`
          : 'unknown',
        functionsAnalyzed: metadata.functionsAnalyzed,
        stateVariables: metadata.stateVariables,
        scanMode: metadata.scanMode,
        detectorsRun: metadata.detectorCount,
      },

      findings: {
        bySeverity: grouped,
        total: stats.total,
      },

      gasOptimization: {
        suggestions: gasAnalysis || [],
        totalSuggestions: (gasAnalysis || []).length,
      },

      recommendations,
    },
  };
}

module.exports = { generateReport, calculateRiskScore, getRiskLevel };
