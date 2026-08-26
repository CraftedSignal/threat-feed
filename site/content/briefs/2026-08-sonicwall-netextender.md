---
title: Security Policy Bypass Vulnerabilities in SonicWall NetExtender
slug: 2026-08-sonicwall-netextender
description: Multiple vulnerabilities, CVE-2026-66152 and CVE-2026-66153, in SonicWall NetExtender Linux Client versions prior to 10.3.6 allow attackers to bypass security policy enforcement.
date: "2026-08-26T13:59:08Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - SonicWall
products:
  - NetExtender Linux Client
affected_os:
  - Linux
cves:
  - id: CVE-2026-66152
  - id: CVE-2026-66153
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1084/
  - https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0013
  - https://www.cve.org/CVERecord?id=CVE-2026-66152
  - https://www.cve.org/CVERecord?id=CVE-2026-66153
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all Linux assets running SonicWall NetExtender and deploy version 10.3.6
      owner: IT Operations
      due: 72h
      evidence: Vendor security bulletin SNWLID-2026-0013
  mitigation_plan:
    - priority: immediate
      action: Upgrade NetExtender Linux Client to 10.3.6
      owner: IT Operations
      addresses: CVE-2026-66152, CVE-2026-66153
      evidence: CERT-FR advisory CERTFR-2026-AVI-1084
---

The French National Cybersecurity Agency (ANSSI) has published an advisory regarding multiple security vulnerabilities impacting the SonicWall NetExtender Linux Client. Identified by the vendor as SNWLID-2026-0013, these flaws are tracked as CVE-2026-66152 and CVE-2026-66153. The vulnerabilities affect all versions of the NetExtender Linux Client prior to 10.3.6. These flaws allow an attacker to bypass established security policy controls, potentially granting unauthorized access to internal network segments or bypassing restrictions enforced by the VPN client. Organizations utilizing the NetExtender Linux client must upgrade to version 10.3.6 or later to mitigate the risk of policy circumvention.

## Impact

Successful exploitation allows an attacker to bypass security policies enforced by the NetExtender client. This may result in unauthorized access to restricted network resources or the circumvention of traffic-filtering rules usually applied to remote VPN sessions. The scope of impact is limited to environments where the vulnerable NetExtender Linux Client is deployed.

## Recommendation

- Upgrade the SonicWall NetExtender Linux Client to version 10.3.6 or later on all impacted endpoints to resolve CVE-2026-66152 and CVE-2026-66153.
- Audit logs for unexpected network connections or policy access denials originating from endpoints running vulnerable versions of the NetExtender client prior to patching.
