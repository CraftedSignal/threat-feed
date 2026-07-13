---
title: Rejetto HFS Vulnerability Allows Remote Code Execution via Session Forgery (CVE-2026-61500)
slug: 2026-07-rejetto-hfs-session-key
description: A remote attacker can exploit a critical vulnerability, CVE-2026-61500, in Rejetto HFS versions 3.0.0 through 3.2.0 by recovering the session-cookie signing key due to poor randomness, forging an administrator session, and achieving remote code execution.
date: "2026-07-13T18:17:56Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-vulnerability
  - rce
  - session-hijacking
vendors:
  - Rejetto
products:
  - HFS (versions 3.0.0 through 3.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Rejetto HFS ... derives its session-cookie signing key from ... and discloses outputs of the same generator to unauthenticated clients during login. A remote attacker can collect a small number of login responses, reconstruct the generator's state, recover the signing key, and forge a valid administrator session cookie, leading to full administrative access and remote code execution via the server_code configuration feature.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: A remote attacker can ... reconstruct the generator's state, recover the signing key, and forge a valid administrator session cookie
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: recover the signing key, and forge a valid administrator session cookie, leading to full administrative access
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: leading to full administrative access and remote code execution via the server_code configuration feature.
    confidence_band: high
cves:
  - id: CVE-2026-61500
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61500
---

CVE-2026-61500 details a critical vulnerability affecting Rejetto HFS, a popular HTTP File Server, specifically versions 3.0.0 through 3.2.0. The vulnerability stems from the application's use of a non-cryptographic `Math.random()` generator to derive its session-cookie signing key. Compounding this issue, outputs from this same predictable generator are inadvertently disclosed to unauthenticated clients during login responses. A sophisticated remote attacker can leverage this weakness by collecting a limited number of login responses, subsequently reconstructing the `Math.random()` generator's internal state. This allows the attacker to recover the session-cookie signing key, forge a valid administrator session cookie, and ultimately gain full administrative access. This administrative control can then be weaponized to achieve remote code execution via the server's `server_code` configuration feature, posing a severe risk to the compromised system.

## Attack Chain

1. A remote attacker identifies a vulnerable Rejetto HFS instance running versions 3.0.0 through 3.2.0.
2. The attacker makes multiple requests to the HFS login endpoint to collect a sufficient number of `Math.random()` outputs, which are implicitly disclosed in login responses.
3. Using the collected `Math.random()` outputs, the attacker reconstructs the internal state of the non-cryptographic `Math.random()` generator.
4. From the reconstructed generator state, the attacker derives the session-cookie signing key, which is directly dependent on `Math.random()`'s output.
5. With the recovered session-cookie signing key, the attacker forges a valid administrator session cookie.
6. The attacker uses the forged session cookie to authenticate to the Rejetto HFS instance with full administrative privileges.
7. Leveraging administrative access, the attacker utilizes the `server_code` configuration feature to inject and execute arbitrary commands or code on the underlying server.
8. This results in remote code execution on the compromised system, allowing for complete control over the server.

## Impact

Successful exploitation of CVE-2026-61500 grants an attacker full administrative access to the Rejetto HFS instance. This level of access enables remote code execution on the underlying server, allowing the attacker to completely compromise the system. The consequences can include data exfiltration, deployment of further malicious payloads (e.g., ransomware or cryptominers), establishment of persistence, or use of the compromised server as a pivot point for lateral movement within the network. This vulnerability poses a severe risk, as it permits unauthenticated attackers to gain complete control over the affected server.

## Recommendation

* Patch CVE-2026-61500 by upgrading Rejetto HFS to a version beyond 3.2.0 as soon as a fix is available, or apply any vendor-provided security updates immediately.
* Monitor web server logs for Rejetto HFS for any unusual patterns of login attempts, especially those preceding unexpected changes to `server_code` configurations or remote code execution attempts.
* Implement a Web Application Firewall (WAF) to detect and potentially block anomalous HTTP requests that may indicate exploitation attempts related to session cookie forgery or attempts to manipulate the `server_code` feature.
