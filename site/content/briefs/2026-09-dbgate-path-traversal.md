---
title: CVE-2026-101066 Path Traversal in Dbgate
slug: 2026-09-dbgate-path-traversal
description: Dbgate versions up to 7.3.1 contain a path traversal vulnerability in the archive link creation component, allowing remote unauthenticated attackers to access arbitrary files on the filesystem via the linkedFolder parameter.
date: "2026-09-28T14:14:49Z"
lastmod: "2026-09-28T14:15:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:dbgate:dbgate:*:*:*:*:*:*:*:*
vendors:
  - dbgate
products:
  - dbgate (<= 7.3.1)
  - Dbgate (up to 6.8.1, 7.0.2, 7.1.8, 7.2.5, 7.3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be initiated remotely.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: This manipulation of the argument linkedFolder causes path traversal.
    confidence_band: high
cves:
  - id: CVE-2026-101066
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101066
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101067
rules:
  - title: Detects CVE-2026-101067 Exploitation - Path Traversal in Dbgate
    description: Detects exploitation attempts against the Dbgate save-uploaded-file endpoint by monitoring for directory traversal sequences in the filePath or fileName parameters.
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to Dbgate via firewall/proxy
      owner: IT Operations
      due: 24h
      evidence: Remotely exploitable vulnerability
  mitigation_plan:
    - priority: immediate
      action: Monitor web logs for directory traversal signatures
      owner: SOC
      addresses: CVE-2026-101066
      evidence: Source confirms path traversal in linkedFolder parameter
updates:
  - at: "2026-09-28T14:15:00Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-101067 Exploitation - Path Traversal in Dbgate'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101067
---

Dbgate versions up to 7.3.1 are vulnerable to a path traversal vulnerability identified as CVE-2026-101066. The issue exists within the createLink function located in packages/api/src/controllers/archive.js. An attacker can manipulate the linkedFolder argument to break out of the intended directory structure and access sensitive files on the host server. This vulnerability is remotely exploitable without authentication and is currently subject to public disclosure with no available vendor patch. Given the nature of Dbgate as a database management tool, successful exploitation could lead to the exposure of database configuration files, credentials, and other sensitive system information stored on the host running the application.

## Impact

Successful exploitation allows remote attackers to read unauthorized files from the filesystem where Dbgate is installed. This can lead to full system compromise if configuration files containing database credentials are exfiltrated. The vulnerability affects all deployments of Dbgate versions 7.3.1 and earlier, regardless of the underlying operating system.

## Recommendation

Prioritized actions for security teams:
- Identify all instances of Dbgate deployed within the environment and audit their exposure to the internet.
- Apply network-level access control lists (ACLs) to restrict access to Dbgate interfaces to trusted management subnets until a patch is released.
- Monitor web server access logs for requests containing directory traversal patterns such as "../" in the linkedFolder parameter targeting the archive controller.
- Implement file integrity monitoring (FIM) on critical application configuration files to detect unauthorized access attempts.
