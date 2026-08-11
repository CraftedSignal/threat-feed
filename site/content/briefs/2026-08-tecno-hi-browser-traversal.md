---
title: Path Traversal Vulnerability in TECNO Hi Browser
slug: 2026-08-tecno-hi-browser-traversal
description: TECNO Hi Browser version 2.23.1.1 is vulnerable to path traversal via malicious Content-Disposition headers, allowing arbitrary file writes outside the intended download directory.
date: "2026-08-11T16:07:45Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - TECNO
products:
  - Hi Browser (2.23.1.1)
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: The browser trusted an attacker-controlled Content-Disposition filename and joined it onto the download directory without sanitising path separators or canonical-path checking the result.
    confidence_band: high
cves:
  - id: CVE-2026-18907
    cvss: 7.5
    epss: 0.00586
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18907
  - https://security.tecno.com/SRC/blogdetail/448?lang=en_US
  - https://www.hunt-benito.com/blog/two-dots-and-a-slash-cve-2026-18907-tecno-hi-browser-download-path-traversal/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Deploy latest browser updates across managed devices.
      owner: IT Operations
      due: 48h
      evidence: 'Status: fixed in the latest version of Hi Browser (per TECNO advisory).'
  mitigation_plan:
    - priority: immediate
      action: Update Hi Browser to the version addressing CVE-2026-18907.
      owner: IT Operations
      addresses: CVE-2026-18907
      evidence: Vendor advisory (TECNO SRC)
---

TECNO Hi Browser version 2.23.1.1 contains a path traversal vulnerability (CVE-2026-18907) in its download management functionality. The application fails to sanitize the 'filename' parameter provided in the 'Content-Disposition' HTTP response header. When a user downloads a file from a malicious server, the browser joins the attacker-provided filename directly to the target download directory path. An attacker can use directory traversal sequences, such as '../', within the filename to escape the designated storage area and write files to arbitrary locations accessible by the browser's storage permissions. This behavior poses a significant risk as it allows for the potential overwriting of application data or other files on the device. The issue has been addressed by the vendor in updated versions of the browser.

## Impact

Successful exploitation allows an attacker to write files outside of the authorized download directory on the user's Android device. If targeted effectively, this could lead to the modification of sensitive files, application hijacking, or the placement of malicious payloads in locations that could be executed or processed by the system, depending on the browser's storage permissions and device environment.

## Recommendation

1. Update TECNO Hi Browser to the latest version immediately to patch CVE-2026-18907.
2. Implement network-level egress filtering to restrict browser access to untrusted or newly registered domains if the environment requires strict control over mobile device traffic.
3. Security teams should perform periodic audits of mobile application download handlers to ensure they use basename sanitization and canonical path verification to prevent path traversal.
