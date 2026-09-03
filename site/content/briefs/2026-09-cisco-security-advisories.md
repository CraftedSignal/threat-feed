---
title: Cisco Releases Patches for Critical Infrastructure Vulnerabilities
slug: 2026-09-cisco-security-advisories
description: Cisco has issued security advisories for unpatched S/MIME vulnerabilities in Secure Email and critical RCE and authentication bypass flaws across its IOS XR, Nexus, and VoIP phone product lines.
date: "2026-09-03T10:52:08Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - vulnerability
  - network-security
  - patch-management
  - informational
vendors:
  - Cisco
products:
  - Secure Email (<= 16.5.0)
  - IOS XR
  - Nexus 9000 Series Switches
  - Desk Phone 9800
  - IP Phone 7800
  - IP Phone 8800
  - Video Phone 8875
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Nexus 9000 vulnerability allows remote attackers to connect to by-default accessible TCP ports and execute code with root privileges.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: Insufficient validation of message integrity can allow an attacker to intercept and modify traffic between email gateways using a man-in-the-middle technique.
    confidence_band: high
cves:
  - id: CVE-2026-20354
    cvss: 5.9
  - id: CVE-2026-20355
    cvss: 5.9
  - id: CVE-2026-20274
    cvss: 9.8
  - id: CVE-2026-20279
    cvss: 9.8
  - id: CVE-2026-20281
    cvss: 7.5
references:
  - https://www.securityweek.com/cisco-warns-of-unpatched-secure-email-flaws-patches-critical-switch-vulnerabilities/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Security
  immediate_actions:
    - action: Patch all Cisco IOS XR and Nexus 9000 switches immediately upon receipt of official firmware updates
      owner: Network Security
      due: 72h
      evidence: CVE-2026-20274, CVE-2026-20279, CVE-2026-20212 are critical RCE/Auth Bypass vulnerabilities
  mitigation_plan:
    - priority: immediate
      action: Restrict TCP port access on Nexus 9000 series switches to trusted management subnets
      owner: Network Security
      addresses: CVE-2026-20212
      evidence: Source notes the vulnerability allows remote attackers to connect to by-default accessible TCP ports
---

Cisco has released a series of security advisories detailing multiple vulnerabilities across its enterprise product portfolio. Two unpatched, publicly disclosed medium-severity vulnerabilities (CVE-2026-20354 and CVE-2026-20355) affect the S/MIME decryption functionality in Secure Email running AsyncOS version 16.5.0 or earlier. These flaws permit man-in-the-middle (MitM) attacks by failing to properly validate message integrity, potentially exposing encrypted email content.

Simultaneously, Cisco has addressed several critical-severity vulnerabilities in networking and communication hardware. This includes remote code execution (RCE) and authentication bypass flaws in IOS XR and Nexus 9000 series switches (CVE-2026-20274, CVE-2026-20279, CVE-2026-20212). The Nexus 9000 vulnerability is particularly severe, allowing unauthenticated remote attackers to execute code with root privileges by connecting to accessible TCP ports. Additionally, a high-severity denial-of-service (DoS) vulnerability (CVE-2026-20281) affects multiple models of Cisco Desk and IP phones using the Session Initiation Protocol (SIP). While no active exploitation is currently observed, the public disclosure of these flaws increases the risk to enterprise networks.

## Impact

Successful exploitation of these vulnerabilities could lead to full system compromise of core networking equipment, unauthorized access to sensitive internal email communications, and significant denial-of-service impacts on telecommunications hardware. These products are foundational in enterprise environments, and compromise could facilitate lateral movement, data exfiltration, and operational disruption.

## Recommendation

1. Prioritize the application of vendor-provided patches for all affected Cisco hardware, specifically targeting critical-severity CVE-2026-20274, CVE-2026-20279, and CVE-2026-20212.
2. Implement strict network access controls to limit exposure of management interfaces and TCP ports on Nexus 9000 series switches to trusted internal networks only.
3. Monitor for unusual traffic patterns between email gateways, as the unpatched S/MIME flaws in Secure Email may allow for interception of encrypted traffic.
4. Review the official Cisco security advisories for the specific patch release versions associated with each listed CVE to ensure comprehensive remediation.
