
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
  if (
    !evidence ||
    typeof evidence.target !== "string" ||
    !evidence.http ||
    !evidence.tls
  ) {
    throw new Error("Complete live assessment evidence is required.");
  }

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
    if (Object.hasOwn(counts, finding.severity)) {
      counts[finding.severity]++;
    }
  });

  const score = result.score;

  return {
    product: "Nyra AI | CyberShield",
    target: evidence.target,
    score,
    riskLevel: riskLabel(score),
    findings,
    counts,
    totalFindings: findings.length,
    recommendations: [...new Set(findings.map(f => f.action))],
    generatedAt: new Date().toISOString(),
    assessmentType: "Live passive HTTPS assessment",
    collectionMethod: evidence.collectionMethod,
    evidenceSummary: result.evidenceSummary,
    dns: evidence.dns,
    http: evidence.http,
    tls: evidence.tls,
    limitations: result.limitations
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

