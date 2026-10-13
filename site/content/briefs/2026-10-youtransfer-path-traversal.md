---
title: Path Traversal Vulnerability in YouTransfer Template Rendering
slug: 2026-10-youtransfer-path-traversal
description: YouTransfer versions up to 0.0.7, 1.0.6, and 1.1.0 contain a path traversal vulnerability in the Template Rendering component that allows remote, unauthenticated file access.
date: "2026-10-13T14:37:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:youtransfer:youtransfer:*:*:*:*:*:*:*:*
vendors:
  - YouTransfer
products:
  - YouTransfer (<= 0.0.7, 1.0.6, 1.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be launched remotely.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The manipulation results in path traversal.
    confidence_band: high
cves:
  - id: CVE-2026-109519
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109519
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy WAF rules to block path traversal strings on /settings/template
      owner: SOC
      due: 24h
      evidence: Source documentation of path traversal flaw
  hunt_leads:
    - lead: Search web logs for traversal sequences in /settings/template requests
      technique_id: T1190
      data_needed:
        - webserver logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability in /settings/template
---

YouTransfer versions up to 0.0.7, 1.0.6, and 1.1.0 are vulnerable to a path traversal flaw located within the Template Rendering component, specifically involving the /settings/template file. This vulnerability is remotely exploitable without authentication, enabling an adversary to manipulate file paths and potentially access sensitive files on the host system. The vulnerability is publicly disclosed, and as the vendor has remained unresponsive to disclosure attempts, no official patches are currently available. Organizations utilizing YouTransfer should restrict access to the application interface or implement compensating controls to mitigate potential unauthorized file system access.

## Attack Chain

1. Attacker identifies a public-facing instance of the YouTransfer application.
2. Attacker crafts a malicious HTTP request targeting the /settings/template endpoint.
3. The request includes directory traversal sequences (such as ../) within a parameter expected by the template rendering function.
4. The application fails to properly sanitize the input before passing it to the file system handler.
5. The file system handler resolves the traversed path to an unintended location on the host server.
6. The application retrieves the content of the target file based on the manipulated path.
7. The application returns the contents of the unauthorized file in the HTTP response body to the attacker.

## Impact

Successful exploitation of this path traversal vulnerability allows an unauthenticated remote attacker to read arbitrary files from the underlying server's file system. This can lead to the exposure of sensitive configuration files, source code, credentials, or system information, potentially facilitating further compromise of the environment.

## Recommendation

Prioritize the identification of all internet-facing instances of YouTransfer within your network environment. Given the lack of a vendor-provided patch, implement the following actions:

- Configure web application firewalls (WAF) or ingress filtering to block requests containing directory traversal sequences (e.g., "..", "%2e%2e/") targeting the /settings/template path.
- Audit web server access logs for anomalous GET or POST requests directed at /settings/template that utilize directory traversal patterns.
- Restrict network access to the YouTransfer administrative or settings interface to authorized internal IP ranges only.
