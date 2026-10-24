---
brief_id: brief-2026-10-24-aiohttp-path-traversal
event_id: brief-2026-10-24-aiohttp-path-traversal
revision: 1
activity_at: "2026-10-24T09:07:36Z"
title: 'aiohttp: Path traversal vulnerability (CVE-2024-23334)'
slug: 2026-10-aiohttp-path-traversal
description: CVE-2024-23334 is a path traversal vulnerability in aiohttp versions prior to 3.9.2 that allows attackers to access arbitrary files via malicious file uploads.
date: "2026-10-24T09:07:36Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against CVE and reported exploit metadata.
cpes:
  - cpe:2.3:a:aiohttp:aiohttp:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*
products:
  - aiohttp (< 3.9.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Endpoint for uploading files; can be used to upload a compressed archive containing a symlink to /etc/shadow.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1006
    technique_name: Direct Volume Access
    evidence: can be used to upload a compressed archive containing a symlink to /etc/shadow.
    confidence_band: high
cves:
  - id: CVE-2024-23334
    cvss: 5.9
    epss: 0.76875
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SXYRXYY-AIOHTTP-EXPLOIT-CVE-2024-23334-CERTSTREAM
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SXYRXYY-AIOHTTP-EXPLOIT-CVE-2024-23334-CERTSTREAM&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all applications utilizing aiohttp < 3.9.2 and deploy patches.
      owner: IT Operations
      due: 48h
      evidence: Source identifies vulnerability in aiohttp < 3.9.2.
  hunt_leads:
    - lead: Search webserver access logs for POST requests to upload endpoints containing path traversal characters (../) or unusual filename patterns in archived upload parameters.
      technique_id: T1190
      data_needed:
        - Webserver access logs (POST request methods, request bodies/query params)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Endpoint for uploading files; can be used to upload a compressed archive containing a symlink.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to aiohttp 3.9.2 or later.
      owner: IT Operations
      addresses: CVE-2024-23334
      evidence: Affected aiohttp versions < 3.9.2.
---

CVE-2024-23334 is a path traversal vulnerability affecting aiohttp versions earlier than 3.9.2. An attacker can exploit this vulnerability by uploading a compressed archive containing a symbolic link that points to sensitive files, such as /etc/shadow. This allows the attacker to read arbitrary files on the system outside of the intended directory. Publicly available exploit scripts are currently circulating, which automate the discovery of vulnerable hosts and attempt exploitation.

## Impact
Successful exploitation allows for unauthorized read access to arbitrary files on the filesystem, potentially exposing sensitive system information or credentials depending on the application context and permissions of the service running aiohttp.

## Recommendation
- Upgrade aiohttp to version 3.9.2 or later to mitigate the vulnerability.
- Implement strict validation on uploaded file contents and reject archives containing symbolic links.
- Identify all internet-facing services utilizing the aiohttp library and prioritize patching for those instances.
- Monitor web application logs for file upload requests containing path traversal sequences or attempts to traverse outside of designated upload directories.
