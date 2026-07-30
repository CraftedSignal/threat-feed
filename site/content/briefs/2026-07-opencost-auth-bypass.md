---
title: Authentication Bypass and Credential Exposure in OpenCost
slug: 2026-07-opencost-auth-bypass
description: OpenCost versions before 1.121.0 contain authentication bypass vulnerabilities allowing unauthenticated credential exfiltration via GET /helmValues and unauthorized service key modification via POST /serviceKey.
date: "2026-07-30T15:33:54Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - OpenCost
products:
  - OpenCost
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OpenCost before 1.121.0 fails to authenticate the GET /helmValues endpoint, exposing base64-decoded HELM_VALUES environment variable containing cloud provider credentials.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: exposing base64-decoded HELM_VALUES environment variable containing cloud provider credentials.
    confidence_band: high
cves:
  - id: CVE-2026-67349
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67349
  - https://github.com/opencost/opencost/releases/tag/core/v1.121.0
  - https://www.vulncheck.com/advisories/opencost-unauthenticated-helm-values-exposure-and-admin-bypass
rules:
  - title: Detect Unauthenticated Access Attempts to OpenCost Endpoints
    description: Detects CVE-2026-67349 exploitation attempts by identifying unauthenticated GET requests to /helmValues and POST requests to /serviceKey
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
---

OpenCost versions prior to 1.121.0 are vulnerable to multiple authentication bypass flaws that facilitate credential access and administrative manipulation. The vulnerability stems from two primary failures in the application's authentication logic. First, the GET /helmValues endpoint does not perform authentication, which exposes the base64-encoded HELM_VALUES environment variable to unauthenticated attackers. This variable typically contains sensitive cloud provider credentials, such as API keys or service account details. 

Second, the adminAuthMiddleware fails to enforce authentication requirements when the ADMIN_TOKEN environment variable is not set. This allows unauthenticated actors to interact with restricted administrative endpoints, specifically enabling the unauthorized modification of GCP service account keys via the POST /serviceKey endpoint. This could allow an attacker to redirect billing calls or escalate privileges within the compromised cloud environment. Defenders must prioritize upgrading to version 1.121.0 or ensuring that the ADMIN_TOKEN is strictly configured in all production deployments.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing or internally accessible OpenCost endpoints.
2. Attacker sends an unauthenticated GET request to the /helmValues endpoint.
3. The OpenCost server returns the contents of the HELM_VALUES environment variable, including sensitive cloud provider credentials.
4. Attacker decodes the base64-encoded response to retrieve the plain-text credentials.
5. Attacker attempts an unauthenticated POST request to the /serviceKey endpoint.
6. The server confirms the adminAuthMiddleware is inactive due to the absence of the ADMIN_TOKEN.
7. Attacker successfully submits a modified GCP service account key to the endpoint.
8. Attacker achieves the final objective of redirecting billing calls or maintaining persistence within the GCP environment.

## Impact

The vulnerability exposes sensitive cloud provider credentials to unauthenticated attackers, potentially leading to unauthorized access to cloud resources. Successful exploitation of the service key modification allows attackers to redirect billing traffic, resulting in financial loss and potential data exfiltration paths through GCP service accounts. This issue affects any organization deploying OpenCost versions older than 1.121.0 without explicit ADMIN_TOKEN enforcement.

## Recommendation

* Immediately upgrade all OpenCost deployments to version 1.121.0 or newer.
* If upgrading is not immediately possible, enforce a strong, non-default ADMIN_TOKEN across all OpenCost instances to prevent the adminAuthMiddleware from failing open.
* Deploy the provided Sigma rule to detect unauthenticated attempts to access sensitive endpoints.
* Audit cloud service account logs (GCP) for any suspicious modifications to service key objects, correlating these with source IP addresses associated with OpenCost instances.
