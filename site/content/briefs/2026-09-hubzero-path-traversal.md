---
title: Path Traversal Vulnerability in HUBzero CMS
slug: 2026-09-hubzero-path-traversal
description: Authenticated users can exploit a path traversal vulnerability in HUBzero CMS project file upload handlers to achieve arbitrary file writes, potentially leading to remote code execution.
date: "2026-09-17T15:59:42Z"
lastmod: "2026-09-17T16:00:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hubzero:hubzero_cms:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cve-2026-92970
  - path-traversal
  - web-application
  - session-fixation
  - authentication
vendors:
  - HUBzero
products:
  - HUBzero CMS (<= 2.2.32)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Attackers can supply traversal sequences in upload parameters to write files to attacker-chosen paths with web server privileges, potentially enabling code execution.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1185
    technique_name: Browser Session Hijacking
    evidence: Attackers can obtain a valid session identifier, send victims a crafted link containing it, and replay the identifier after the victim authenticates to hijack their account and access.
    confidence_band: high
cves:
  - id: CVE-2026-92970
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92970
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92984
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for traversal attempts in web logs
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-92970
  mitigation_plan:
    - priority: immediate
      action: Monitor for and apply upcoming vendor patches for CVE-2026-92970
      owner: IT Operations
      addresses: CVE-2026-92970
      evidence: NVD vulnerability disclosure
updates:
  - at: "2026-09-17T16:00:17Z"
    level: L2
    summary: added coverage for HUBzero CMS (<= 2.2.32)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-92984
---

HUBzero CMS versions up to and including 2.2.32 are vulnerable to a path traversal flaw within their project file upload handlers. An authenticated project member can craft malicious input containing directory traversal sequences (e.g., ../) within the upload parameters. When processed by the application, these sequences allow the user to bypass intended storage constraints and write files to arbitrary locations on the underlying host filesystem. Because the application performs these operations with the privileges of the web server process, this vulnerability can be leveraged to place malicious scripts or configuration files into executable directories, facilitating remote code execution. Given the impact on system integrity and the potential for full server compromise, organizations running affected versions should prioritize mitigation.

## Impact

Successful exploitation allows an authenticated attacker to gain arbitrary file write access to the host server. This can lead to full system compromise if an attacker is able to overwrite critical configuration files or upload web shells to reachable web directories. The vulnerability affects all deployments of HUBzero CMS version 2.2.32 and earlier.

## Recommendation

Prioritize upgrading to a patched version of HUBzero CMS once the vendor releases a security update addressing CVE-2026-92970. Until a patch is applied, implement strict access controls for project file management, restrict user upload privileges, and monitor web server logs for suspicious POST requests containing directory traversal sequences in file upload parameters.

## Rules

title: "Detect Path Traversal Attempt in HUBzero CMS File Upload"
description: "Detects potential path traversal exploitation targeting CVE-2026-92970 by identifying directory traversal sequences in file upload parameters."
logsource:
 category: "webserver"
detection:
 selection:
 cs-method: "POST"
 cs-uri-stem|contains: "/project/upload"
 cs-uri-query|contains:
 - "../"
 - "..\\"
 filter:
 sc-status|startswith: "4"
 condition: selection and not filter
level: "high"
tags:
 - "attack.initial_access"
 - "attack.execution"
 - "attack.t1505.002"
falsepositives:
 - "Legitimate administrative tools or plugins that use traversal sequences for folder navigation"
tests:
 positive:
 - name: "Upload request containing path traversal sequence"
 data:
 - cs-method: "POST"
 cs-uri-stem: "/project/upload"
 cs-uri-query: "filename=../../etc/passwd"
 sc-status: "200"
 negative:
 - name: "Standard file upload"
 data:
 - cs-method: "POST"
 cs-uri-stem: "/project/upload"
 cs-uri-query: "filename=data.csv"
 sc-status: "200"
