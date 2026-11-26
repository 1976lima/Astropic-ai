
import { analyseEvidence } from "../engine/security-engine.js";

const SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4
};

const EXPLANATIONS = {
  "HDR-strict-transport-security": {
    impact: "The website may be vulnerable to insecure HTTP connections.",
    action: "Configure and verify an appropriate HSTS policy."
  },
  "HDR-content-security-policy": {
    impact: "The website may have insufficient protection against content injection.",
    action: "Implement a suitable Content Security Policy."
  },
  "HDR-x-content-type-options": {
    impact: "Browsers may interpret content using unintended MIME types.",
    action: "Configure X-Content-Type-Options: nosniff."
  },
  "HDR-referrer-policy": {
    impact: "Referrer information may be exposed unnecessarily.",
    action: "Configure an appropriate Referrer-Policy."
  },
  "HDR-permissions-policy": {
    impact: "Browser features may not have sufficiently restricted permissions.",
    action: "Configure Permissions-Policy for required browser features."
  },
  "TLS-001": {
    impact: "The supplied evidence indicates a TLS certificate validation concern.",
    action: "Verify the certificate chain, hostname and validity."
  },
  "TLS-002": {
    impact: "The TLS certificate is approaching expiry.",
    action: "Renew the certificate before its expiry date."
  }
};

function riskLabel(score) {
  if (score >= 90) return "Low";
  if (score >= 70) return "Moderate";
  if (score >= 40) return "High";
  return "Critical";
}

function explainFinding(finding) {
  const details = EXPLANATIONS[finding.id] || {};

  return {
    ...finding,
    impact: details.impact ||
      "This security finding requires further investigation.",
    action: details.action ||
      finding.recommendation ||
      "Investigate and apply an appropriate security control.",
    priority: finding.severity || "info"
  };
}

export function analyseWithNyra(evidence) {
  if (!evidence || typeof evidence !== "object") {
    throw new Error("Valid security evidence is required.");
  }

  // Run the existing CyberShield security engine.
  const result = analyseEvidence(evidence);

  const findings = (result.findings || [])
    .map(explainFinding)
    .sort((a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 4) -
      (SEVERITY_ORDER[b.severity] ?? 4)
    );

  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  findings.forEach(finding => {
    const severity = finding.severity;
    if (Object.hasOwn(counts, severity)) {
      counts[severity]++;
    }
  });

  const score = Number.isFinite(result.score)
    ? result.score
    : 0;

  const recommendations = [
    ...new Set(findings.map(f => f.action))
  ];

  return {
    product: "Nyra AI | CyberShield",
    target: result.target,
    score,
    riskLevel: riskLabel(score),
    findings,
    counts,
    recommendations,
    totalFindings: findings.length,
    generatedAt: new Date().toISOString(),
    assessmentType: "Evidence-based security analysis",
    limitations: [
      "Analysis is based only on supplied evidence.",
      "No live website scanning is performed.",
      "Recommendations require technical verification.",
      "Risk score is a preliminary heuristic, not a security certification.",
      "Explanations are rule-based and do not represent live AI inference."
    ]
  };
}

export function formatNyraReport(report) {
  if (!report || !Array.isArray(report.findings)) {
    throw new Error("A valid Nyra report is required.");
  }

  const lines = [
    "NYRA AI - CYBERSHIELD SECURITY REPORT",
    "=====================================",
    `Target: ${report.target || "Not specified"}`,
    `Security score: ${report.score}/100`,
    `Risk level: ${report.riskLevel}`,
    `Total findings: ${report.totalFindings}`,
    "",
    "SECURITY FINDINGS",
    "-----------------"
  ];

  report.findings.forEach((finding, index) => {
    lines.push(
      `${index + 1}. ${finding.title}`,
      `Severity: ${finding.severity}`,
      `Impact: ${finding.impact}`,
      `Recommended action: ${finding.action}`,
      ""
    );
  });

  lines.push(
    "IMPORTANT LIMITATIONS",
    "---------------------",
    ...(report.limitations || [])
  );

  return lines.join("\n");
}

export default {
  analyseWithNyra,
  formatNyraReport
};

