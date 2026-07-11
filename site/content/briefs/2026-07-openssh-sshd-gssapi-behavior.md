---
title: OpenSSH sshd GSSAPI Behavior Vulnerability CVE-2026-59998
slug: 2026-07-openssh-sshd-gssapi-behavior
description: CVE-2026-59998 describes an undocumented security-relevant behavior in sshd, a component of OpenSSH, specifically in versions prior to 10.4, where the GSSAPIStrictAcceptorCheck setting reportedly has no value when the server is operating within a Windows Active Directory environment.
date: "2026-07-11T07:33:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - openssh
  - gssapi
  - active-directory
  - windows
  - misconfiguration
vendors:
  - OpenSSH
  - Microsoft
products:
  - sshd in OpenSSH < 10.4
  - Active Directory
cves:
  - id: CVE-2026-59998
    cvss: 4.8
    epss: 0.00177
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59998
---

CVE-2026-59998 identifies an undocumented security-relevant behavior in `sshd`, the OpenSSH server daemon, affecting versions prior to 10.4. This vulnerability manifests when `sshd` operates within a Windows Active Directory environment, specifically concerning the `GSSAPIStrictAcceptorCheck` configuration setting. In this scenario, the setting is rendered ineffective, meaning it "has no value." This undocumented behavior could lead to an unexpected weakening of GSSAPI authentication strictness, potentially allowing for authentication bypasses or unintended access if the security posture relies on this particular check being enforced. The vulnerability was published on July 11, 2026, and impacts organizations using OpenSSH `sshd` integrated with Active Directory for authentication. This is not an active exploit but a behavioral flaw that could be leveraged.

## Impact

The primary impact of CVE-2026-59998 is a potential degradation of the intended security posture for OpenSSH servers integrated with Windows Active Directory via GSSAPI. If administrators have configured `GSSAPIStrictAcceptorCheck` expecting it to enforce stricter validation of GSSAPI credentials, this vulnerability means those checks are not being performed. This could allow an attacker to bypass specific GSSAPI security mechanisms, leading to unauthorized access or authentication with less stringent requirements than intended. While no specific incidents of exploitation or victim counts are available, the risk lies in the unexpected authentication behavior that could be exploited in specific Active Directory configurations.

## Recommendation

* Patch OpenSSH deployments to version 10.4 or later to address the undocumented behavior identified in CVE-2026-59998.
* Review and reassess the security configurations of OpenSSH servers utilizing GSSAPI authentication in Windows Active Directory environments, specifically understanding the implications of `GSSAPIStrictAcceptorCheck`'s ineffectiveness as described in CVE-2026-59998.
