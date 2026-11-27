import {
  validateAssessmentRequest,
  collectPassiveEvidence
} from "../../cybershield/governance/live-assessment.js";

import {
  analyseWithNyra
} from "../../cybershield/ai/nyra-analysis.js";

const jsonHeaders = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store"
};

function reply(status, payload) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: jsonHeaders
  });
}

export default async function handler(request) {
  if (request.method !== "POST") {
    return reply(405, { error: "Method not allowed." });
  }

  let body;

  try {
    const length = Number(
      request.headers.get("content-length") || 0
    );

    if (length > 5000) {
      return reply(413, { error: "Request is too large." });
    }

    body = await request.json();
  } catch {
    return reply(400, {
      error: "A valid JSON request is required."
    });
  }

  const validation = validateAssessmentRequest(body);

  if (!validation.valid) {
    return reply(400, { error: validation.error });
  }

  try {
    const evidence = await collectPassiveEvidence(
      validation.target
    );

    const report = analyseWithNyra(evidence);

    report.assessmentType = "Live passive HTTPS assessment";
    report.collectionMethod = evidence.collectionMethod;
    report.httpStatus = evidence.http.statusCode;
    report.tls = evidence.tls;
    report.dns = evidence.dns;

    report.limitations = [
      "This is a passive HTTPS assessment of the public homepage only.",
      "No port scanning, exploitation, authenticated testing or vulnerability probing is performed.",
      "Only the security headers returned by the HTTPS HEAD response are evaluated.",
      "TLS details are those observed by the assessment server at collection time.",
      "A passing result is not a security certification or guarantee of website security."
    ];

    return reply(200, { report });

  } catch (error) {
    return reply(422, {
      error: error?.message ||
        "The assessment could not be completed."
    });
  }
}
