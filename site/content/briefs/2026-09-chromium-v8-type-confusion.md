---
title: Active Exploitation of Google Chromium V8 Type Confusion Vulnerability
slug: 2026-09-chromium-v8-type-confusion
description: A type confusion vulnerability in the Google Chromium V8 engine is being actively exploited in the wild, allowing remote attackers to achieve arbitrary code execution within the sandbox environment via crafted HTML pages.
date: "2026-09-04T18:00:22Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - vulnerability
  - chromium
  - browser-security
vendors:
  - Google
  - Microsoft
  - Opera
products:
  - Chromium V8
  - Google Chrome (< 152.0.7977.82)
  - Microsoft Edge
  - Opera
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Google Chromium V8 contains a type confusion vulnerability that allows a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page.
    confidence_band: high
cves:
  - id: CVE-2026-85046
    cvss: 8.8
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-85046
  - https://chromereleases.googleblog.com/2026/09/stable-channel-update-for-desktop_01882797386.html
  - https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85046
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Deploy stable channel updates for Chrome, Edge, and Opera to all workstations and servers.
      owner: IT Operations
      due: "2026-09-18"
      evidence: CISA BOD 26-04 requirement for CVE-2026-85046
  mitigation_plan:
    - priority: immediate
      action: Upgrade Chromium V8 to 152.0.7977.82 or later
      owner: IT Operations
      addresses: CVE-2026-85046
      evidence: Chromium Stable Channel Update release note
---

CVE-2026-85046 is a type confusion vulnerability residing within the Google Chromium V8 engine. This flaw enables a remote attacker to gain control over the browser environment by tricking a user into navigating to a malicious or compromised webpage. Successful exploitation allows for arbitrary code execution within the browser's sandbox. Given the ubiquity of the Chromium engine, the impact extends across multiple major web browsers including Google Chrome, Microsoft Edge, and Opera. CISA has added this CVE to the Known Exploited Vulnerabilities (KEV) catalog due to evidence of in-the-wild exploitation. Defenders must prioritize patching according to BOD 26-04 requirements to mitigate the risk of remote code execution on endpoint devices.

## Impact

The vulnerability poses a severe risk to end-user systems across all sectors, as web browsers are primary interfaces for business operations. Exploitation allows attackers to gain code execution within the browser sandbox, which can serve as a precursor to further system compromise, information theft, or the deployment of additional malicious payloads. Organizations failing to patch browsers utilizing affected versions of the Chromium V8 engine remain at high risk of remote exploitation.

## Recommendation

- Patch Google Chrome, Microsoft Edge, and Opera immediately to the versions addressing CVE-2026-85046 as specified in the vendor stable channel update notes.
- Implement the vulnerability management requirements outlined in CISA BOD 26-04, prioritizing assets with high internet exposure.
- Review CISA’s Forensics Triage Requirements to ensure appropriate log collection is enabled for detecting potential post-exploitation activity on endpoints.
