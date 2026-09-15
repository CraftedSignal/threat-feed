---
title: Cross-Site Scripting Vulnerability in Governikus AusweisApp2
slug: 2026-09-governikus-xss
description: A vulnerability in the Governikus AusweisApp2 software allows a remote, unauthenticated attacker to execute a Cross-Site Scripting (XSS) attack.
date: "2026-09-15T13:05:17Z"
type: threat
types:
  - threat
severities:
  - low
exploited: true
tags:
  - web-vulnerability
  - xss
vendors:
  - Governikus
products:
  - AusweisApp2
affected_os:
  - Windows
  - macOS
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in Governikus AusweisApp2 ausnutzen, um einen Cross-Site Scripting Angriff durchzuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3356
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  mitigation_plan:
    - priority: medium_term
      action: Monitor for and apply future security updates for AusweisApp2 provided by Governikus.
      owner: IT Operations
      addresses: XSS vulnerability in AusweisApp2
      evidence: Source advisory recommends monitoring for security updates.
---

A Cross-Site Scripting (XSS) vulnerability exists in the Governikus AusweisApp2 software, allowing a remote, unauthenticated attacker to inject and execute malicious scripts. XSS attacks generally target the client-side session of a user by injecting scripts into a trusted application's context. This vulnerability potentially allows an attacker to steal session cookies, capture user input, or perform actions on behalf of the authenticated user within the AusweisApp2 interface. The risk is considered low, but users are advised to monitor for updates from Governikus to address this security flaw.

## Impact

Successful exploitation could allow unauthorized script execution within the context of the AusweisApp2 application on a victim's machine. This may lead to the compromise of user-specific data managed by the application or unauthorized interaction with the identity services the software facilitates. No specific victim statistics or active exploitation reports are provided in the source documentation.

## Recommendation

1. Monitor official Governikus update channels for patches addressing this XSS vulnerability in AusweisApp2.
2. Ensure the application is updated to the latest available version once a fix is released.
3. Restrict execution of untrusted external content or links while the application is active if possible.
