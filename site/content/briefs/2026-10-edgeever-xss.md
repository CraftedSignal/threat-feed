---
title: Stored XSS Vulnerability in EdgeEver setMemoDragPreview
slug: 2026-10-edgeever-xss
description: EdgeEver versions 1.112.0 and earlier contain a stored XSS vulnerability in the setMemoDragPreview function that allows for session token theft via malicious notebook or memo titles.
date: "2026-10-12T22:42:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:edgeever:edgeever:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - injection
  - session-hijacking
vendors:
  - EdgeEver
products:
  - EdgeEver (<= 1.112.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Attackers can set malicious names via MCP create_notebook, rename_notebook or create_memo tools, running script on drag with access to the desktop bridge's session token.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: EdgeEver through 1.112.0 contains a stored cross-site scripting vulnerability in setMemoDragPreview that allows attackers to inject script through notebook names or memo titles.
    confidence_band: high
cves:
  - id: CVE-2026-109557
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109557
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade EdgeEver to version > 1.112.0
      owner: IT Operations
      due: 48h
      evidence: Source states EdgeEver through 1.112.0 is vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Upgrade EdgeEver software to the latest patched release
      owner: IT Operations
      addresses: CVE-2026-109557
      evidence: NVD vulnerability disclosure
---

EdgeEver versions 1.112.0 and earlier are affected by a stored cross-site scripting (XSS) vulnerability located in the setMemoDragPreview function. This vulnerability allows an authenticated attacker to inject arbitrary JavaScript into the application by creating or renaming notebook names and memo titles. The malicious script is stored by the application and subsequently executed when a user initiates a drag-and-drop action on the affected element. Due to the architecture of the application, the execution context includes access to the desktop bridge session token, which could be exfiltrated by an attacker to facilitate session hijacking.

## Impact

Successful exploitation allows for the execution of arbitrary code within the context of the user's session. This poses a significant risk of session token theft, potentially leading to full account compromise. Users of the EdgeEver desktop application across Windows, macOS, and Linux are susceptible if they interact with malicious notebooks or memos created or renamed by an attacker.

## Recommendation

- Upgrade the EdgeEver desktop application to a version greater than 1.112.0 immediately once a vendor patch is released.
- Implement content security policies (CSP) at the application level to restrict the execution of untrusted scripts.
- Monitor logs for the use of notebook creation or renaming tools that contain non-standard or script-like character patterns in their titles or names.
