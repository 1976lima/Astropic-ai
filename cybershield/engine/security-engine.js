const POINTS = {
  critical: 40,
  high: 25,
  medium: 12,
  low: 5,
  info: 0
};

const RULES = [
  ["strict-transport-security", "HSTS missing", "medium"],
  ["content-security-policy", "CSP missing", "medium"],
  ["x-content-type-options", "Content type protection missing", "low"],
  ["referrer-policy", "Referrer policy missing", "low"],
  ["permissions-policy", "Permissions policy missing", "info"]
];

export function analyseEvidence(evidence) {
  if (!evidence || typeof evidence.target !== "string") {
    throw new Error("Valid hostname evidence required");
  }

  const findings = [];
  const headers = evidence.headers || {};

  for (const [key, title, severity] of RULES) {
    if (!Object.keys(headers).some(
      h => h.toLowerCase() === key
    )) {
      findings.push({
        id: "HDR-" + key.toUpperCase(),
        title,
        severity,
        category: "Website security",
        recommendation: "Review and configure this security header."
      });
    }
  }

  if (evidence.tls?.checked && evidence.tls.valid === false) {
    findings.push({
      id: "TLS-001",
      title: "TLS certificate validation failed",
      severity: "high",
      category: "Transport security",
      recommendation: "Review certificate validity and configuration."
    });
  }

  if (
    evidence.tls?.valid === true &&
    evidence.tls.daysUntilExpiry <= 21
  ) {
    findings.push({
      id: "TLS-002",
      title: "TLS certificate nearing expiry",
      severity: "medium",
      category: "Transport security",
      recommendation: "Renew the certificate before expiry."
    });
  }

  const counts = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0
  };

  let deductions = 0;

  findings.forEach(f => {
    counts[f.severity]++;
    deductions += POINTS[f.severity];
  });

  const score = Math.max(0, 100 - deductions);

  return {
    product: "Nyra CyberShield",
    target: evidence.target,
    score,
    findings,
    counts,
    generatedAt: new Date().toISOString(),
    assessmentType: "evidence-analysis-only",
    limitations: [
      "Analyses supplied evidence only.",
      "Does not scan or contact live websites.",
      "Score is not a security certification."
    ]
  };
}
