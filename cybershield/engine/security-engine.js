
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
  ["x-frame-options", "Clickjacking protection header missing", "low"],
  ["referrer-policy", "Referrer policy missing", "low"],
  ["permissions-policy", "Permissions policy missing", "info"]
];

export function analyseEvidence(evidence) {
  if (!evidence || typeof evidence.target !== "string") {
    throw new Error("Valid hostname evidence required");
  }

  // Accept both live collector and manually supplied evidence.
  const headers = evidence.http?.headers || evidence.headers || {};
  const tls = evidence.tls || {};

  const findings = [];

  for (const [key, title, severity] of RULES) {
    const present = Object.keys(headers).some(
      header => header.toLowerCase() === key
    );

    if (!present) {
      findings.push({
        id: "HDR-" + key.toUpperCase(),
        title,
        severity,
        category: "Website security",
        recommendation: "Review and configure this security header."
      });
    }
  }

  const tlsChecked =
    typeof tls.checked === "boolean" ? tls.checked :
    typeof tls.authorized === "boolean";

  const tlsValid =
    typeof tls.valid === "boolean" ? tls.valid :
    typeof tls.authorized === "boolean" ? tls.authorized :
    null;

  if (tlsChecked && tlsValid === false) {
    findings.push({
      id: "TLS-001",
      title: "TLS certificate validation failed",
      severity: "high",
      category: "Transport security",
      recommendation: "Review certificate validity and configuration."
    });
  }

  if (
    tlsValid === true &&
    Number.isFinite(tls.daysUntilExpiry) &&
    tls.daysUntilExpiry <= 21
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
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  let deductions = 0;

  findings.forEach(finding => {
    counts[finding.severity]++;
    deductions += POINTS[finding.severity] ?? 0;
  });

  return {
    product: "Nyra CyberShield",
    target: evidence.target,
    score: Math.max(0, 100 - deductions),
    findings,
    counts,
    generatedAt: new Date().toISOString(),
    assessmentType: "Live passive HTTPS evidence analysis",
    evidenceSummary: {
      httpStatus: evidence.http?.statusCode ?? null,
      headersChecked: Object.keys(headers).length,
      tlsChecked,
      tlsValid,
      tlsProtocol: tls.protocol || null,
      certificateExpiry: tls.validTo || null,
      dnsAddresses: evidence.dns?.addresses || []
    },
    limitations: [
      "Only the public HTTPS homepage is assessed.",
      "Only the security headers collected by the assessment are evaluated.",
      "No port scanning, exploitation or authenticated testing is performed.",
      "The score is a preliminary heuristic, not a security certification."
    ]
  };
}
