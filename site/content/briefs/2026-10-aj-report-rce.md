---
brief_id: brief-2026-10-31-aj-report-rce
event_id: brief-2026-10-31-aj-report-rce
revision: 1
activity_at: "2026-10-31T20:04:33Z"
title: 'AJ-Report: Remote code execution via hard-coded JWT secret (CVE-2026-120209)'
slug: 2026-10-aj-report-rce
description: AJ-Report versions 1.7.1 and earlier contain a hard-coded JWT secret, enabling token forgery and unauthenticated remote code execution via the testTransform endpoint.
date: "2026-10-31T20:04:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Source confirmed; verification of endpoint path required in customer environments.
cpes:
  - cpe:2.3:a:aj-report:aj-report:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - cve-2026-120209
  - web-application-vulnerability
vendors:
  - AJ-Report
products:
  - AJ-Report (<= 1.7.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.004
    subtechnique_name: Private Keys
    evidence: AJ-Report through 1.7.1 signs share tokens with a hard-coded JWT secret, allowing attackers to forge valid Share-Tokens offline.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can mint a token with reportCode 'dataSet' to access the testTransform endpoint, which passes scripts to GroovyClassLoader for unauthenticated remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-120209
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120209
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block access to the /testTransform endpoint on public-facing AJ-Report instances.
      owner: IT Operations
      due: 24h
      evidence: Endpoint is identified as the entry point for GroovyClassLoader script execution.
  hunt_leads:
    - lead: Search web access logs for HTTP requests directed at /testTransform containing 'dataSet' within query parameters.
      technique_id: T1203
      data_needed:
        - Web server access logs (URI stem, query parameters)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Endpoint '/testTransform' accepts 'dataSet' to trigger the vulnerable GroovyClassLoader.
  mitigation_plan:
    - priority: immediate
      action: Upgrade AJ-Report to the latest version to resolve the hard-coded secret vulnerability.
      owner: IT Operations
      addresses: CVE-2026-120209
      evidence: NVD vulnerability disclosure for CVE-2026-120209.
---

AJ-Report versions up to 1.7.1 utilize a hard-coded JSON Web Token (JWT) secret, which allows an attacker to forge valid Share-Tokens offline. Exploitation of this vulnerability permits unauthorized access to the testTransform endpoint. This endpoint insecurely passes user-supplied scripts to the GroovyClassLoader, resulting in unauthenticated remote code execution on the underlying server.

## Attack Chain
1. Attacker identifies the hard-coded JWT secret within the AJ-Report application.
2. Attacker crafts a malicious Share-Token offline using the identified secret.
3. Attacker sends an HTTP request to the testTransform endpoint with the forged token.
4. The application validates the forged token as legitimate.
5. The testTransform endpoint processes the request, extracting reportCode parameters.
6. The application passes the reportCode 'dataSet' input to the GroovyClassLoader.
7. Arbitrary code is executed on the server under the context of the application process.

## Impact
Successful exploitation allows for unauthenticated remote code execution, granting the attacker full control over the application server.

## Recommendation
- Upgrade AJ-Report to a patched version beyond 1.7.1 immediately.
- Implement strict network segmentation for the reporting server to minimize exposure.
- Audit access logs for unauthorized attempts to reach the '/testTransform' endpoint.
- If patching is not immediately feasible, restrict network access to the testTransform endpoint at the web application firewall (WAF) or reverse proxy level.
