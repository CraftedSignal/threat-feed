---
title: MLflow Tracking Server Unauthenticated Full-Read SSRF via Webhook Delivery
slug: 2026-08-mlflow-ssrf
description: MLflow Tracking Server versions prior to 3.15.0 are vulnerable to an unauthenticated full-read SSRF attack because the webhook delivery mechanism follows unvalidated HTTP redirects, allowing attackers to exfiltrate internal data or interact with local services.
date: "2026-08-18T00:46:13Z"
lastmod: "2026-08-19T22:27:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:lfprojects:mlflow:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - mlflow
  - web-vulnerability
vendors:
  - MLflow
products:
  - MLflow Tracking Server
  - MLflow (< 3.15.0)
  - MLflow
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The default MLflow Tracking Server exposes the model-registry webhooks API unauthenticated, including a synchronous POST /api/2.0/mlflow/webhooks/{id}/test endpoint.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated user who can create registered models can read arbitrary files from any other user's artifact directory, bypassing the experiment-level READ permission gate.
    confidence_band: high
cves:
  - id: CVE-2026-64849
    cvss: 9.3
    epss: 0.00349
  - id: CVE-2026-69148
    cvss: 7.1
    epss: 0.00217
references:
  - https://github.com/advisories/GHSA-7gwp-5pfp-969j
  - https://github.com/mlflow/mlflow/pull/24258
  - https://github.com/advisories/GHSA-gqch-g4w5-7qcw
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69148
  - https://www.cve.org/CVERecord?id=CVE-2026-64849
rules:
  - title: Detects CVE-2026-64849 Exploitation - SSRF Attempt via MLflow /test endpoint
    description: Detects attempts to access internal metadata services or local ports via the MLflow webhook /test endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade MLflow to 3.15.0 or later across all tracking server instances.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-64849 fixed in 3.15.0.
updates:
  - at: "2026-08-18T00:46:22Z"
    level: L2
    summary: added coverage for MLflow (< 3.15.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-gqch-g4w5-7qcw
  - at: "2026-08-19T22:27:32Z"
    level: L2
    summary: added CVE-2026-69148
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-64849
---

MLflow Tracking Server (v3.13.0 and earlier) contains an SSRF vulnerability (CVE-2026-64849) in its webhook delivery mechanism. While the application implements a validation function (`_validate_webhook_url`) intended to restrict connections to public IP addresses, the implementation fails to pin the resolved IP address, and the HTTP client follows redirects without re-validating the final destination. An unauthenticated attacker can create a webhook pointing to a controlled HTTPS endpoint that issues a 302 redirect to internal network resources, such as the AWS Instance Metadata Service (169.254.169.254) or loopback addresses. Because the synchronous `/api/2.0/mlflow/webhooks/{id}/test` endpoint reflects the response status and body back to the caller, this allows for unauthenticated full-read exfiltration of sensitive internal data or blind POST interactions with management interfaces on the local network.

## Attack Chain

1. Attacker identifies an internet-facing MLflow Tracking Server instance running with a default configuration (e.g., SQLite backend) lacking authentication plugins.
2. Attacker prepares a malicious HTTPS-enabled server that returns a 302 HTTP redirect to an internal target (e.g., http://169.254.169.254/latest/meta-data/iam/security-credentials/).
3. Attacker submits a POST request to `/api/2.0/mlflow/webhooks` with the `url` parameter pointing to the malicious attacker-controlled HTTPS endpoint.
4. MLflow validates the initial URL; since the attacker's endpoint is a valid public HTTPS URL, the `_validate_webhook_url` check passes.
5. Attacker triggers the SSRF by sending a request to the `/api/2.0/mlflow/webhooks/{id}/test` endpoint.
6. The MLflow server executes the webhook, follows the 302 redirect to the internal target without re-validation, and fetches the sensitive internal resource.
7. The server receives the internal response (e.g., cloud credentials) and reflects the full response body back to the attacker in the HTTP response of the `/test` request.

## Impact

Successful exploitation allows unauthenticated attackers to exfiltrate sensitive cloud metadata (e.g., IAM role credentials), query internal-only services, or perform host scanning from the perspective of the MLflow server. Furthermore, by using 307 or 308 redirects, attackers can perform blind POST operations against internal management interfaces like Docker daemons or Spring Boot Actuator endpoints, potentially leading to remote code execution or service disruption within the internal network.

## Recommendation

Prioritize the following actions to secure your MLflow environment:
- Upgrade MLflow to version 3.15.0 or later immediately to patch CVE-2026-64849.
- Enable MLflow authentication plugins to ensure that the webhook API is not accessible to unauthenticated users.
- Implement network segmentation to isolate MLflow servers from sensitive cloud metadata endpoints (IMDSv1) and internal management interfaces.
- Deploy the suggested webserver-level rules to detect potential SSRF attempts directed at common internal paths.
