---
title: Privilege Escalation in F5 BIG-IP TMUI via CVE-2026-66842
slug: 2026-09-f5-bigip-tmui-privesc
description: An authenticated user with any role can exploit a vulnerability in the F5 BIG-IP Traffic Management User Interface to create arbitrary administrative accounts.
date: "2026-09-02T17:15:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:f5:big_ip:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - network-security
  - f5
vendors:
  - F5
products:
  - BIG-IP
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078.002
    technique_name: 'Valid Accounts: Domain Accounts'
    evidence: An authenticated user of any role may be able to create administrative user accounts through an undisclosed request to Traffic Management User Interface (TMUI).
    confidence_band: high
cves:
  - id: CVE-2026-66842
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66842
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review TMUI access logs for unauthorized account creation attempts
      owner: SOC
      due: 24h
      evidence: Source documents privilege escalation via TMUI account creation
  mitigation_plan:
    - priority: immediate
      action: Apply patches provided by F5 for CVE-2026-66842
      owner: IT Operations
      addresses: CVE-2026-66842
      evidence: NVD/Vendor advisory
---

CVE-2026-66842 identifies a security flaw within the F5 BIG-IP Traffic Management User Interface (TMUI). This vulnerability allows an attacker who already possesses an authenticated account on the system, regardless of their assigned role, to create new administrative accounts. The exploitation of this flaw is limited to the device's control plane; there is no identified exposure through the data plane. The primary requirement for exploitation is network access to the management interface of the BIG-IP system. This allows low-privilege users to effectively escalate their permissions to full administrative control, posing a significant risk to the integrity and confidentiality of the network infrastructure. F5 has noted that versions of BIG-IP that have reached their End of Technical Support (EoTS) have not been evaluated for this vulnerability.

## Impact

Successful exploitation of this vulnerability enables an attacker to gain full administrative access to the BIG-IP appliance. This grants the attacker complete control over network traffic management, policy enforcement, and configuration settings. Given the central role F5 BIG-IP devices play in enterprise networks, such unauthorized escalation could lead to widespread disruption, interception of traffic, or the exfiltration of sensitive data protected by these devices.

## Recommendation

- Restrict network access to the BIG-IP management interface to only trusted internal IP addresses or jump servers.
- Audit existing administrative accounts for unauthorized additions created recently.
- Monitor logs for unusual account creation activity within the TMUI management interface.
- Review official F5 security bulletins for patches corresponding to CVE-2026-66842 and apply them to all supported versions of BIG-IP.
