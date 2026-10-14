---
title: Microsoft.AspNetCore.Authentication.Negotiate Elevation of Privilege Vulnerability
slug: 2026-10-aspnet-core-eop
description: An elevation of privilege vulnerability in the Microsoft.AspNetCore.Authentication.Negotiate package allows an attacker to misassociate an authenticated identity with an unintended LDAP principal due to improper validation of Kerberos principal SIDs.
date: "2026-10-14T00:30:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:microsoft:aspnetcore:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - elevation-of-privilege
  - dotnet
vendors:
  - Microsoft
products:
  - Microsoft.AspNetCore.Authentication.Negotiate (>= 10.0.0, <= 10.0.12)
  - Microsoft.AspNetCore.Authentication.Negotiate (>= 8.0.0, <= 8.0.31)
  - Microsoft.AspNetCore.Authentication.Negotiate (>= 9.0.0, <= 9.0.20)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
    evidence: The component fails to correctly verify the LDAP result against the Kerberos principal SID, allowing an authenticated identity to be incorrectly associated with an unintended LDAP principal.
    confidence_band: high
cves:
  - id: CVE-2026-70179
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-vrrp-6v32-2p8g
  - https://github.com/dotnet/announcements/issues/458
  - https://www.cve.org/CVERecord?id=CVE-2026-70179
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade Microsoft.AspNetCore.Authentication.Negotiate package to versions 10.0.13, 8.0.32, or 9.0.21
      owner: Application Security
      due: 72h
      evidence: Advisory recommends updating package references to patched versions
  mitigation_plan:
    - priority: immediate
      action: Recompile and redeploy all self-contained applications using affected package versions
      owner: IT Operations
      addresses: CVE-2026-70179
      evidence: Advisory states self-contained applications must be recompiled and redeployed
---

Microsoft has disclosed a high-severity elevation of privilege vulnerability (CVE-2026-70179) impacting the Microsoft.AspNetCore.Authentication.Negotiate package within .NET applications. The flaw manifests when LDAP claim resolution is enabled, as the library fails to properly verify the LDAP result against the Kerberos principal SID during authentication. This failure allows a user or attacker to gain the identity context of an unintended LDAP principal, potentially leading to unauthorized access to application resources and functions. The vulnerability affects .NET deployments on Windows, Linux, and macOS platforms. Successful exploitation requires an attacker to already possess a level of authenticated access within the environment, from which they can then elevate privileges to target sensitive LDAP principals. Defenders should prioritize updating the vulnerable package versions in all .NET projects to the patched releases (10.0.13, 8.0.32, or 9.0.21) and ensuring all affected self-contained applications are recompiled and redeployed.

## Impact

The vulnerability carries a CVSS score of 7.5 and affects any .NET enterprise application utilizing Negotiate LDAP authentication with claim resolution enabled. If exploited, an attacker can bypass intended security boundaries by assuming the identity of other LDAP principals, leading to unauthorized data access, administrative actions, or lateral movement within the application context. The impact is significant for applications that rely on LDAP identity resolution to manage sensitive user roles and access controls.

## Recommendation

- Identify all .NET projects in the environment using the Microsoft.AspNetCore.Authentication.Negotiate package via the `dotnet --info` command or by auditing project files.
- Upgrade the Microsoft.AspNetCore.Authentication.Negotiate package to the patched versions: 10.0.13, 8.0.32, or 9.0.21.
- Recompile and redeploy all self-contained applications utilizing the affected versions to ensure the security fix is embedded in the application runtime.
- Review authentication logs and LDAP access patterns for unusual identity claims that do not align with the established Kerberos principal SID for the associated user sessions.
