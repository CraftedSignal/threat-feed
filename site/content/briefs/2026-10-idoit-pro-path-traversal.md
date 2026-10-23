---
brief_id: brief-2026-10-23-idoit-pro-path-traversal
event_id: brief-2026-10-23-idoit-pro-path-traversal
revision: 1
activity_at: "2026-10-23T15:37:55Z"
title: 'i-doit Pro: Path traversal vulnerability (CVE-2023-37739)'
slug: 2026-10-idoit-pro-path-traversal
description: i-doit Pro version 25 and below is susceptible to a path traversal vulnerability in the file_manager parameter, allowing authenticated attackers to read sensitive files via manipulated HTTP requests.
date: "2026-10-23T15:37:55Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:i-doit:i-doit_pro:*:*:*:*:*:*:*:*
  - cpe:2.3:a:i-doit:i-doit:*:*:*:*:pro:*:*:*
vendors:
  - synetics GmbH
products:
  - i-doit Pro (<= 25)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: i-doit Pro 25 and below are vulnerable to Path Traversal vulnerability.
    confidence_band: high
cves:
  - id: CVE-2023-37739
    cvss: 6.5
    epss: 0.01328
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-LEEKENGHWA-CVE-2023-37739---PATH-TRAVERSAL-IN-I-DOIT-PRO-25-AND-BELOW
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-LEEKENGHWA-CVE-2023-37739---PATH-TRAVERSAL-IN-I-DOIT-PRO-25-AND-BELOW&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2023-37739 Exploitation - Path Traversal in i-doit Pro
    description: Detects attempts to exploit CVE-2023-37739 by identifying path traversal sequences in the file parameter of the file_manager component.
    platform: sigma
    severity: medium
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to identify attempted exploitation
      owner: Detection Engineering
      due: 24h
      evidence: Public exploit PoC available
  hunt_leads:
    - lead: Search web logs for anomalous access to /index.php or /?moduleID with traversal strings
      technique_id: T1190
      data_needed:
        - Web server access logs (cs-uri-query)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Public PoC demonstrates direct access to sensitive files via GET parameters
  mitigation_plan:
    - priority: immediate
      action: Upgrade i-doit Pro to a version beyond 25 or apply vendor-provided security patches
      owner: IT Operations
      addresses: CVE-2023-37739
      evidence: Vulnerability confirmed in i-doit Pro <= 25
---

i-doit Pro versions 25 and below contain a path traversal vulnerability. An authenticated attacker, regardless of privilege level, can exploit this flaw by manipulating the 'file' parameter within the 'file_manager' component to access unauthorized files on the underlying filesystem.

## Attack Chain
1. Attacker authenticates to the i-doit Pro application with valid, potentially low-privileged, credentials.
2. Attacker identifies a target file on the host system to retrieve.
3. Attacker crafts an HTTP GET request to the application, specifically targeting the /index.php or /?moduleID endpoints.
4. Attacker injects path traversal sequences (e.g., ../../../) into the 'file' parameter of the 'file_manager' component.
5. The application fails to sanitize the input, allowing the traversal to escape the intended directory.
6. The application returns the contents of the requested file in the HTTP response.

## Impact
Successful exploitation allows authenticated attackers to read sensitive system files, potentially leading to information disclosure of configuration files, credentials, or internal application logic.

## Recommendation
1. Inventory all instances of i-doit Pro to identify versions 25 or below.
2. Apply security updates provided by synetics GmbH to remediate CVE-2023-37739.
3. Until patched, restrict access to the i-doit Pro administrative interface to trusted networks only.
4. Monitor web access logs for requests containing suspicious path traversal sequences (e.g., '../') directed at the 'file_manager' parameter.
