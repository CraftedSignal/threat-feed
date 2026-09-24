---
title: Path Traversal in Pulpcore Content Upload API (CVE-2026-90959)
slug: 2026-09-pulpcore-path-traversal
description: An authenticated path traversal vulnerability in the pulpcore content upload API allows users to bypass file scheme validation and read arbitrary files on the server process by manipulating the file_url parameter.
date: "2026-09-24T16:47:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - path-traversal
  - pulp
vendors:
  - Pulp
products:
  - pulpcore
  - Pulp Container
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: In deployments that include Pulp Container, successful exploitation allows an attacker to read the container registry token signing private key and forge bearer tokens.
    confidence_band: high
cves:
  - id: CVE-2026-90959
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90959
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Pulpcore and Pulp Container to the vendor-provided fixed version for CVE-2026-90959
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-90959 disclosure
  mitigation_plan:
    - priority: immediate
      action: Review access logs for API requests to the content upload endpoint containing path traversal sequences
      owner: SOC
      addresses: CVE-2026-90959
      evidence: Vulnerability analysis indicates the file_url parameter is the attack vector
---

A path traversal vulnerability exists in the pulpcore content upload API (CVE-2026-90959). The vulnerability stems from an insufficient validation of the 'file_url' parameter used by users with file repository privileges. While the application attempts to restrict file system access by rejecting URLs starting with 'file://', it fails to account for Python URL parser behavior that recognizes 'file:' without double slashes. By supplying a specially crafted URL, an authenticated user can bypass this check and utilize relative path traversal sequences (e.g., ../../) to read any file accessible to the Pulp server process. In environments utilizing Pulp Container, this flaw allows attackers to exfiltrate the container registry token signing private key, enabling the forgery of bearer tokens and providing unauthorized access to private container repositories.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to read arbitrary files on the host system running the Pulp server process. In the context of Pulp Container, this leads to the compromise of the token signing private key, resulting in total loss of confidentiality and integrity for all private container repositories managed by the instance.

## Recommendation

Prioritize patching all affected Pulpcore and Pulp Container instances to the version containing the fix for CVE-2026-90959. Monitor web server access logs for anomalous requests to the content upload API containing traversal sequences such as '..%2f' or '..%5c' within the 'file_url' parameter.
