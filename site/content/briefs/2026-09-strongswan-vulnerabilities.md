---
title: Multiple Vulnerabilities in strongSwan
slug: 2026-09-strongswan-vulnerabilities
description: Multiple vulnerabilities, including remote code execution and security policy bypass, have been disclosed in strongSwan versions prior to 6.1.0.
date: "2026-09-08T13:34:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:strongswan:strongswan:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - network-security
  - patch-management
vendors:
  - strongSwan
products:
  - strongSwan (< 6.1.0)
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1129/
  - https://www.strongswan.org/blog/2026/09/07/strongswan-vulnerability-(cve-2026-78127).html
  - https://www.strongswan.org/blog/2026/09/07/strongswan-vulnerability-(cve-2026-78129).html
  - https://www.strongswan.org/blog/2026/09/07/strongswan-vulnerability-(cve-2026-78130).html
  - https://www.strongswan.org/blog/2026/09/07/strongswan-vulnerability-(cve-2026-78131).html
  - https://www.strongswan.org/blog/2026/09/07/strongswan-vulnerability-(cve-2026-78132).html
  - https://www.strongswan.org/blog/2026/09/07/strongswan-vulnerability-(cve-2026-78133).html
  - https://www.strongswan.org/blog/2026/09/07/strongswan-vulnerability-(cve-2026-78134).html
  - https://www.strongswan.org/blog/2026/09/07/strongswan-vulnerability-(cve-2026-78135).html
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade all instances of strongSwan to 6.1.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends version 6.1.0 as the solution.
  mitigation_plan:
    - priority: immediate
      action: Patching to 6.1.0
      owner: IT Operations
      addresses: CVE-2026-78127 through CVE-2026-78135
      evidence: ANSSI advisory CERTFR-2026-AVI-1129
---

The French National Cybersecurity Agency (ANSSI) has released an advisory regarding multiple critical vulnerabilities affecting the strongSwan IPsec VPN suite. These vulnerabilities, identified as CVE-2026-78127, CVE-2026-78129, CVE-2026-78130, CVE-2026-78131, CVE-2026-78132, CVE-2026-78133, CVE-2026-78134, and CVE-2026-78135, impact all versions of strongSwan prior to 6.1.0. Depending on the specific flaw, an unauthenticated remote attacker could potentially trigger arbitrary remote code execution, perform denial-of-service attacks, or bypass existing security policy configurations. Organizations utilizing strongSwan for secure network connectivity are advised to review the vendor-provided security bulletins and apply updates immediately. Given the nature of these vulnerabilities, the potential for service disruption or compromise of network security boundaries is high for internet-facing VPN gateways.

## Impact

Successful exploitation of these vulnerabilities can lead to full system compromise via remote code execution, persistent denial-of-service, or the subversion of network security policies. This poses a significant risk to organizations relying on strongSwan to secure sensitive data in transit, potentially allowing unauthorized access to internal network resources or the total loss of VPN gateway availability.

## Recommendation

Prioritize patching all strongSwan instances to version 6.1.0 or later immediately. Refer to the official strongSwan security blog for specific remediation instructions for each CVE ID: CVE-2026-78127, CVE-2026-78129, CVE-2026-78130, CVE-2026-78131, CVE-2026-78132, CVE-2026-78133, CVE-2026-78134, and CVE-2026-78135.
