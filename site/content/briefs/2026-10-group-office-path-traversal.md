---
brief_id: brief-2026-10-22-group-office-path-traversal
event_id: brief-2026-10-22-group-office-path-traversal
revision: 1
activity_at: "2026-10-22T14:14:31Z"
title: 'Intermesh Group-Office: Unauthenticated path traversal (CVE-2018-25438)'
slug: 2026-10-group-office-path-traversal
description: Intermesh Group-Office versions 3.3.0 through 3.5.4 contain an unauthenticated path traversal vulnerability in compress.php, allowing remote attackers to read arbitrary files via directory traversal sequences.
date: "2026-10-22T14:14:31Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: All technical fields derived from NVD source
cpes:
  - cpe:2.3:a:intermesh:group-office:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - web-vulnerability
vendors:
  - Intermesh
products:
  - Group-Office (3.3.0 to 3.5.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attackers can send GET requests to /compress.php with ../ sequences in the file parameter to read files such as /etc/passwd.
    confidence_band: high
cves:
  - id: CVE-2018-25438
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25438
rules:
  - title: Detects CVE-2018-25438 Exploitation - Path Traversal in compress.php
    description: Detects attempts to exploit CVE-2018-25438 by identifying directory traversal sequences in the file parameter of GET requests to compress.php.
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
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Group-Office to version 3.5.5 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects versions 3.3.0 through 3.5.4
  hunt_leads:
    - lead: Search web access logs for GET requests to /compress.php containing traversal patterns
      technique_id: T1083
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation observed in the wild
  mitigation_plan:
    - priority: immediate
      action: Apply WAF rules to block requests to /compress.php with directory traversal strings
      owner: IT Operations
      addresses: CVE-2018-25438
      evidence: Vulnerability is exploited via unauthenticated GET requests
---

Intermesh Group-Office versions 3.3.0 through 3.5.4 contain an unauthenticated path traversal vulnerability in the compress.php component. An attacker can exploit this by sending a crafted HTTP GET request to /compress.php, manipulating the 'file' parameter with directory traversal sequences (such as '../'). The application insecurely appends this input to a cache path and passes it to the readfile() function, resulting in the disclosure of arbitrary files from the host filesystem. The Shadowserver Foundation reported exploitation in the wild starting October 21, 2023.

## Impact

Successful exploitation allows unauthenticated remote attackers to read arbitrary files on the underlying host operating system, such as /etc/passwd, potentially leading to credential theft or system compromise.

## Recommendation

- Upgrade Intermesh Group-Office to version 3.5.5 or later to resolve the vulnerability.
- Implement request validation on all web server inputs to block directory traversal sequences such as '../'.
- Restrict access to /compress.php via web application firewall (WAF) rules or network access controls if immediate patching is not possible.
