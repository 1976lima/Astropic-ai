export function explainFindings(report) {
  if (!report || !Array.isArray(report.findings)) {
    return "No valid security report supplied.";
  }

  if (report.findings.length === 0) {
    return "No findings detected in the supplied evidence. This does not guarantee security.";
  }

  const lines = [
    `Nyra Security Analysis: ${report.target}`,
    `Security Score: ${report.score}/100`,
    `Total Findings: ${report.findings.length}`,
    ""
  ];

  for (const finding of report.findings) {
    lines.push(
      `${finding.severity.toUpperCase()}: ${finding.title}`,
      finding.recommendation,
      ""
    );
  }

  lines.push(
    "This analysis is based only on supplied evidence."
  );

  return lines.join("\n");
}
