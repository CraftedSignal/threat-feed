---
title: RustDesk Information Disclosure Vulnerability
slug: 2026-09-rustdesk-info-disclosure
description: A vulnerability in RustDesk allows a remote authenticated attacker to gain unauthorized access to sensitive information.
date: "2026-09-28T10:13:51Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - RustDesk
products:
  - RustDesk
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: A vulnerability exists in RustDesk that allows a remote, authenticated attacker to perform information disclosure.
    confidence_band: med
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3589
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all RustDesk installations and prepare for version update
      owner: IT Operations
      due: 72h
      evidence: General security best practice for unpatched software
  mitigation_plan:
    - priority: medium_term
      action: Upgrade RustDesk software to the latest secure version once released by the vendor
      owner: IT Operations
      addresses: RustDesk information disclosure vulnerability
      evidence: BSI advisory recommendation
---

A security advisory from the BSI reports a vulnerability in the RustDesk remote desktop application that permits an information disclosure. The vulnerability can be exploited by a remote, authenticated attacker to access sensitive information maintained or processed by the application. Because the attacker must already possess authentication credentials to leverage this flaw, the impact is primarily focused on lateral movement, the potential exfiltration of configuration secrets, or unauthorized access to remote session metadata. RustDesk is a cross-platform remote support and desktop software; this vulnerability affects deployments across Windows, Linux, and macOS environments. Organizations utilizing RustDesk should monitor for vendor updates and apply patches once released.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive information managed by the RustDesk application. This could lead to the exposure of connection credentials, session logs, or configuration data, potentially facilitating further unauthorized access or reconnaissance within the host environment. The vulnerability impacts all environments where RustDesk is deployed, including enterprise remote support infrastructure.

## Recommendation

Prioritize the identification and inventory of all RustDesk instances across the organization. Monitor the official RustDesk security update channel and apply the security patches immediately upon availability. Given that this vulnerability requires authentication, ensure that robust multi-factor authentication (MFA) is enforced for all RustDesk user accounts to minimize the risk of a malicious actor reaching the authenticated state necessary to exploit this flaw.
