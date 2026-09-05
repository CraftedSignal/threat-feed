---
title: Cross-Site Scripting Vulnerability in AVideo YPTSocket Plugin
slug: 2026-09-avideo-xss
description: An unauthenticated XSS vulnerability in the AVideo YPTSocket plugin allows attackers to execute arbitrary JavaScript in victim browsers via crafted websocket callback messages.
date: "2026-09-05T13:32:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:avideo:avideo:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - injection
vendors:
  - AVideo
products:
  - AVideo (YPTSocket plugin enabled)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: An unauthenticated attacker can send malicious socket messages containing callback names that trigger the execution of arbitrary JavaScript within the context of a victim's browser session.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows unauthenticated attackers to execute arbitrary JavaScript in other users' browsers via the websocket callback mechanism.
    confidence_band: high
cves:
  - id: CVE-2026-86188
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86188
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Disable the YPTSocket plugin on all internet-facing AVideo deployments.
      owner: IT Operations
      due: 24h
      evidence: Source identifies the YPTSocket plugin as the vector for CVE-2026-86188.
  mitigation_plan:
    - priority: immediate
      action: Upgrade AVideo to a version containing a patch for CVE-2026-86188 once released.
      owner: IT Operations
      addresses: CVE-2026-86188
      evidence: Standard remediation for NVD vulnerability reports.
---

AVideo, an open-source video platform, contains a critical cross-site scripting (XSS) vulnerability (CVE-2026-86188) within its YPTSocket plugin. The vulnerability stems from insecure handling of websocket callback messages. An unauthenticated attacker can send a crafted socket message to the platform, specifying a callback name that triggers existing global functions, such as 'avideoConfirmHTML'. These functions improperly process untrusted data by assigning it directly to the innerHTML property of an element within the Document Object Model (DOM).

Because this process occurs via the websocket interface, an attacker can trigger this execution in the browser of any user connected to the AVideo instance without requiring authentication or user interaction. Successful exploitation leads to arbitrary script execution within the victim's origin, potentially allowing session hijacking, unauthorized actions, or further compromise of the user's session. Defenders should prioritize updating or disabling the YPTSocket plugin until a vendor-supplied patch is applied.

## Impact

The vulnerability allows unauthenticated attackers to achieve arbitrary JavaScript execution in the context of any user's browser session. This can lead to full compromise of the user's session on the AVideo platform, including the ability to perform actions on behalf of the user, exfiltrate sensitive data, or redirect the user to malicious sites. The scope of impact includes any deployment of AVideo where the YPTSocket plugin is active and reachable by an attacker.

## Recommendation

* Identify and audit all AVideo instances to determine if the YPTSocket plugin is enabled.
* Disable the YPTSocket plugin if it is not business-critical to prevent exploitation of CVE-2026-86188.
* Monitor webserver access logs for anomalous websocket connection attempts or unexpected patterns in request parameters targeting the YPTSocket API.
* Patch AVideo to the latest version provided by the vendor once an update addressing CVE-2026-86188 is available.
