---
brief_id: brief-2026-10-22-casdoor-path-traversal
event_id: brief-2026-10-22-casdoor-path-traversal
revision: 1
activity_at: "2026-10-22T07:01:58Z"
title: 'Casbin Casdoor: Path traversal and arbitrary file write (CVE-2026-6815)'
slug: 2026-10-casdoor-path-traversal
description: Casbin Casdoor versions prior to 3.54.1 are vulnerable to an authenticated path traversal vulnerability that allows attackers with administrative access to write arbitrary files to the server, leading to RCE or DoS.
date: "2026-10-22T07:01:58Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Rule verified against logic; environment validation pending.
cpes:
  - cpe:2.3:a:casbin:casdoor:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - arbitrary-file-write
  - casdoor
  - rce
  - dos
vendors:
  - Casbin
products:
  - Casdoor (< 3.54.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated path traversal in Casdoor <3.54.1 enables arbitrary file write leading to RCE or DoS.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: The attacker must be authenticated to the Casdoor instance with admin privileges.
    confidence_band: high
cves:
  - id: CVE-2026-6815
    cvss: 5.9
    epss: 0.0059
    kev_status: "false"
references:
  - https://github.com/casdoor/casdoor/pull/5458
  - https://github.com/casdoor/casdoor/releases/tag/v3.54.1
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6815
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-DANILO-DELLORCO-CVE-2026-6815&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Casdoor Path Traversal Attempt
    description: Detects exploitation attempts against CVE-2026-6815 by identifying path traversal sequences in web server logs targeting the /api/add-provider endpoint.
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
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Casdoor to version 3.54.1 or later.
      owner: IT Operations
      due: 24h
      evidence: The vulnerability has been fixed in version 3.54.1.
  hunt_leads:
    - lead: Search web logs for POST requests to /api/add-provider containing '..' or traversal sequences.
      technique_id: T1190
      data_needed:
        - Web access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows path traversal via pathPrefix in add-provider.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 3.54.1
      owner: IT Operations
      addresses: CVE-2026-6815
      evidence: Fixed in version 3.54.1.
---

Casbin Casdoor versions prior to 3.54.1 contain a path traversal vulnerability in the 'Local File System' storage provider configuration. An authenticated administrator can exploit this flaw by manipulating the 'pathPrefix' and 'fullFilePath' parameters during resource upload or provider configuration. The lack of path validation allows for the writing of arbitrary files to the underlying host filesystem, which can be leveraged for Remote Code Execution (RCE) or Denial of Service (DoS). This vulnerability is confirmed to be fixed in version 3.54.1.

## Attack Chain
1. Attacker gains access to a Casdoor instance with administrative privileges.
2. Attacker navigates to the 'Local File System' storage provider configuration page.
3. Attacker uses directory traversal sequences (e.g., '../') within the 'pathPrefix' parameter.
4. Attacker initiates a resource upload or provider update.
5. The application fails to validate the resulting file path, permitting the write outside the intended storage directory.
6. Attacker overwrites sensitive files such as '.ssh/authorized_keys', web roots, or core application files.
7. Attacker triggers code execution or disrupts service.

## Impact
Successful exploitation allows for arbitrary file writes, resulting in Remote Code Execution (RCE) by overwriting files such as '.ssh/authorized_keys', crontabs, or web shells. Alternatively, attackers can cause a Denial of Service (DoS) by overwriting application databases or core binary files.

## Recommendation
- Upgrade Casdoor to version 3.54.1 or later immediately.
- Audit Casdoor administrator account activity for suspicious 'Local File System' provider configurations or modifications.
- Inspect application file paths and logs for unauthorized file write attempts using directory traversal sequences.
- Apply the Principle of Least Privilege to the system user running the Casdoor process to restrict write access to sensitive system directories.
