---
title: Multiple Vulnerabilities in Progress MOVEit Transfer
slug: 2026-07-moveit-vulnerabilities
description: Multiple vulnerabilities, including remote XSS and security policy bypass, have been identified in Progress MOVEit Transfer versions prior to 2026.0.3, enabling potential unauthorized access and session-based script execution.
date: "2026-07-31T15:28:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - moveit
vendors:
  - Progress
products:
  - MOVEit Transfer
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: De multiples vulnérabilités ont été découvertes dans Progress MOVEit Transfer. Elles permettent à un attaquant de provoquer une injection de code indirecte à distance (XSS) et un contournement de la politique de sécurité.
    confidence_band: high
cves:
  - id: CVE-2026-10697
    cvss: 7.5
    epss: 0.00292
  - id: CVE-2026-15966
    cvss: 7.5
    epss: 0.00204
  - id: CVE-2026-15967
    cvss: 7.5
    epss: 0.00204
  - id: CVE-2026-15968
    cvss: 7.1
    epss: 0.00181
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0951/
  - https://docs.progress.com/bundle/moveit-transfer-release-notes-2026/page/Fixed-Issues-in-2026.0.3.html
  - https://www.cve.org/CVERecord?id=CVE-2026-10697
  - https://www.cve.org/CVERecord?id=CVE-2026-15966
  - https://www.cve.org/CVERecord?id=CVE-2026-15967
  - https://www.cve.org/CVERecord?id=CVE-2026-15968
---

Progress has disclosed multiple critical vulnerabilities affecting MOVEit Transfer versions prior to 2026.0.3. These vulnerabilities, identified as CVE-2026-10697, CVE-2026-15966, CVE-2026-15967, and CVE-2026-15968, allow remote attackers to perform indirect cross-site scripting (XSS) attacks and bypass established security policies. These flaws reside within the application's web interface handling and security control logic. Successful exploitation can lead to unauthorized access, session hijacking, or the execution of malicious scripts within the context of a legitimate user session. Given the role of MOVEit as a managed file transfer solution, these vulnerabilities pose a significant risk to data integrity and confidentiality for organizations handling sensitive information.

## Impact

Successful exploitation of these vulnerabilities allows remote, unauthenticated or authenticated attackers to bypass security controls or execute arbitrary scripts in the victim's browser session. Potential consequences include unauthorized data exfiltration, account takeover, and persistent unauthorized access to the file transfer platform. These vulnerabilities affect all instances of MOVEit Transfer running versions earlier than 2026.0.3.

## Recommendation

- Upgrade all MOVEit Transfer instances to version 2026.0.3 or later immediately, as documented in the Progress security bulletin.
- Review web server access logs for anomalous patterns such as injected script tags or unusual parameters in requests directed at the MOVEit Transfer web portal.
- Monitor for unauthorized configuration changes or security policy modifications within the MOVEit administrative console.
- Restrict access to the MOVEit Transfer web interface to trusted IP ranges to limit the attack surface while the upgrade is being deployed.
