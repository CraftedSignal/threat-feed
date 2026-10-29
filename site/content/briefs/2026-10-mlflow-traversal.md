---
brief_id: brief-2026-10-27-mlflow-traversal
event_id: brief-2026-10-27-mlflow-traversal
revision: 2
activity_at: "2026-10-29T20:21:52Z"
revision_history:
  - revision: 2
    at: "2026-10-29T20:21:52Z"
    checksum: sha256:42b511ef0dac7212c0bcadbb453c0e19119b07c4e7c2a806a9f5b4409a441d86
    summary: new product
    changed_fields:
      - claim_state
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4231
title: 'MLflow: Arbitrary file read via model version path validation (CVE-2026-116690)'
slug: 2026-10-mlflow-traversal
description: MLflow versions 3.10.0 through 3.16.x contain a path traversal vulnerability allowing remote attackers to read arbitrary files from the server filesystem via the model-versions/get-artifact API.
date: "2026-10-27T22:07:17Z"
lastmod: "2026-10-29T20:21:09Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source documentation sufficient for mitigation planning.
cpes:
  - cpe:2.3:a:lfprojects:mlflow:*:*:*:*:*:*:*:*
vendors:
  - LF Projects
products:
  - MLflow (3.10.0-3.16.x)
cves:
  - id: CVE-2026-116690
    cvss: 7.5
    epss: 0.00559
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116690
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4231
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade MLflow to 3.17.0
      owner: IT Operations
      due: 24h
      evidence: This issue is fixed in version 3.17.0.
  hunt_leads:
    - lead: Identify suspicious model version creation requests containing local path references or directory traversal patterns
      data_needed:
        - MLflow API access logs
        - Application-level request parameters for /api/2.0/mlflow/model-versions/get-artifact
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: A remote caller can store a server-local path as the model version artifact location and use /api/2.0/mlflow/model-versions/get-artifact to read files
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 3.17.0
      owner: IT Operations
      addresses: CVE-2026-116690
      evidence: This issue is fixed in version 3.17.0.
updates:
  - at: "2026-10-29T20:21:09Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4231
---

MLflow versions 3.10.0 through 3.16.x contain a path traversal vulnerability in the `_create_model_version()` function. The application fails to properly validate source paths that lack a URL scheme, allowing remote users to supply server-local paths. An attacker can leverage the `/api/2.0/mlflow/model-versions/get-artifact` endpoint to access any file readable by the MLflow server process. This vulnerability impacts both unauthenticated instances and deployments utilizing basic authentication where the attacker possesses model registration privileges. This issue is resolved in MLflow version 3.17.0.

## Impact
Successful exploitation allows for unauthorized reading of sensitive files located on the MLflow server's filesystem, potentially exposing credentials, configuration data, or other sensitive system artifacts.

## Recommendation
- Upgrade MLflow to version 3.17.0 or later immediately.
- Implement strict network access controls to limit access to the MLflow API to trusted IP addresses only.
- Review MLflow server process permissions to ensure the service runs with the least privilege necessary, minimizing the impact of potential filesystem traversal.
