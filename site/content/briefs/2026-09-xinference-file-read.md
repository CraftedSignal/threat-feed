---
title: Unauthenticated Arbitrary File Read in Xinference
slug: 2026-09-xinference-file-read
description: Xinference versions 3.x and commit 4a94832 contain an unauthenticated arbitrary file read vulnerability via the model_path parameter in the auto-register endpoint.
date: "2026-09-04T15:29:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:xorbits:xinference:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - file-read
  - webserver
vendors:
  - Xorbits
products:
  - Xinference (3.x, commit 4a94832)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The endpoint reads and parses config.json, tokenizer_config.json, and chat_template.jinja files at the supplied path and reflects the parsed content back to the caller.
    confidence_band: high
cves:
  - id: CVE-2026-85668
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85668
rules:
  - title: Detects CVE-2026-85668 Exploitation - Arbitrary Path File Read in Xinference
    description: Detects exploitation of the Xinference auto-register endpoint where the model_path parameter contains path traversal sequences to access files outside the intended model directory.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1083
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy Sigma detection rule to monitor for traversal in auto-register endpoint.
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms arbitrary-path file read via model_path parameter.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Xinference to a patched version or restrict network access to the API.
      owner: IT Operations
      addresses: CVE-2026-85668
---

Xinference, an open-source model serving framework, is affected by a critical arbitrary file read vulnerability (CVE-2026-85668) within its model registration mechanism. The vulnerability exists in the POST /v1/models/llm/auto-register endpoint, which fails to enforce authentication or restrict file paths provided in the model_path parameter. When a user provides a path, the application attempts to locate and parse config.json, tokenizer_config.json, and chat_template.jinja files within that directory. Because these contents are reflected back in the API response, an unauthenticated attacker can supply arbitrary filesystem paths to read sensitive configuration files or other data stored in locations where these specific filenames exist. This issue affects Xinference version 3.x and commit 4a94832. Successful exploitation allows unauthorized information disclosure, potentially exposing system credentials, environment variables, or other sensitive configuration parameters to remote attackers.

## Impact

The vulnerability poses a high risk to deployments of Xinference, as it permits unauthenticated remote attackers to enumerate files and exfiltrate content from the host server. Depending on the environment, this could lead to the exposure of API keys, database credentials, or internal service configurations, facilitating further compromise of the infrastructure.

## Recommendation

- Upgrade Xinference to a version that implements proper input validation and path sanitization for the model registration process.
- Implement network-level access controls to ensure the Xinference API endpoint is not exposed to the public internet.
- Audit logs for the POST /v1/models/llm/auto-register endpoint to detect anomalous model_path inputs containing path traversal sequences (e.g., ../).
- Configure the Xinference service to run with the least privilege necessary, limiting the filesystem paths the application process can access.
