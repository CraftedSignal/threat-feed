---
title: Path Traversal in Uber Kraken
slug: 2026-09-uber-kraken-path-traversal
description: Uber Kraken versions 0.1.29 and earlier contain a path traversal vulnerability in the /tags/{tag} endpoint, allowing unauthenticated attackers to read arbitrary files from the filesystem.
date: "2026-09-16T21:57:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:uber:kraken:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - vulnerability
  - webserver
vendors:
  - Uber
products:
  - Kraken (<= 0.1.29)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can exploit this by injecting percent-encoded parent-directory sequences into the tag parameter.
    confidence_band: high
cves:
  - id: CVE-2026-92791
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92791
rules:
  - title: Detects CVE-2026-92791 Exploitation - Path Traversal in /tags/ Endpoint
    description: Detects attempts to exploit CVE-2026-92791 by identifying path traversal sequences in the tag parameter of the /tags/ API endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch Kraken to a version newer than 0.1.29
      owner: IT Operations
      due: 48h
      evidence: Source states vulnerability affects versions through 0.1.29
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rule to block /tags/ requests containing percent-encoded traversal patterns
      owner: Security Engineering
      addresses: CVE-2026-92791
      evidence: NVD vulnerability description
---

Uber Kraken versions 0.1.29 and earlier are affected by a path traversal vulnerability tracked as CVE-2026-92791. The issue resides in the /tags/{tag} API endpoint, which fails to properly validate the tag parameter before using it in file system operations. An unauthenticated attacker can exploit this flaw by submitting percent-encoded parent-directory sequences, such as %2e%2e%2f, within the tag parameter. This allows the attacker to traverse outside the designated storage root and access sensitive files on the underlying host that are readable by the testfs backend process. This vulnerability poses a significant risk to confidentiality, potentially exposing configuration files, secrets, or system data.

## Impact

Successful exploitation allows unauthenticated attackers to read arbitrary files on the host system, potentially leading to information disclosure, unauthorized access to credentials, or further compromise of the infrastructure supporting the Kraken container registry service.

## Recommendation

- Upgrade Uber Kraken to a version beyond 0.1.29 immediately to remediate CVE-2026-92791.
- Audit access logs for the /tags/{tag} endpoint for indicators of path traversal attempts, specifically looking for URL-encoded dot-dot-slash patterns.
- Implement web application firewall (WAF) rules to block requests containing percent-encoded parent directory traversal sequences targeting the /tags/ endpoint.
