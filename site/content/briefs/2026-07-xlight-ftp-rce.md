---
title: Pre-Authentication Remote Code Execution in Xlight FTP Server
slug: 2026-07-xlight-ftp-rce
description: Xlight FTP Server versions prior to 3.9.5 contain a pre-authentication stack buffer overflow vulnerability triggered by malformed SSH packets, potentially leading to remote code execution.
date: "2026-07-29T16:18:31Z"
lastmod: "2026-07-29T16:21:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - buffer-overflow
  - ftp
vendors:
  - Xlight
products:
  - Xlight FTP Server
  - Xlight FTP Server (< 3.9.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Xlight FTP Server before 3.9.5 contains a pre-authentication stack buffer overflow vulnerability that allows unauthenticated attackers to corrupt stack memory.
    confidence_band: high
cves:
  - id: CVE-2026-67192
    cvss: 8.1
  - id: CVE-2026-67191
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67192
  - https://www.vulncheck.com/advisories/xlight-ftp-server-pre-auth-stack-buffer-overflow-via-ssh-gcm-cipher
  - https://www.xlightftpd.com/whatsnew.htm
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67191
updates:
  - at: "2026-07-29T16:21:02Z"
    level: L2
    summary: added CVE-2026-67191; xlight ftp server version < 3.9.5
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-67191
---

Xlight FTP Server versions prior to 3.9.5 are susceptible to a pre-authentication stack-based buffer overflow vulnerability (CVE-2026-67192). The vulnerability exists within the SSH implementation of the server, specifically when handling GCM (Galois/Counter Mode) cipher negotiation. An unauthenticated attacker can send a maliciously crafted SSH packet containing an unvalidated length field to the GCM decryption routine. This oversight allows the attacker to corrupt the stack memory, specifically overwriting the stack cookie and the return address. Successful exploitation permits the attacker to achieve remote code execution before the authentication process is ever completed. This flaw poses a high risk as it requires no credentials and can be triggered during the initial stages of an SSH session.

## Attack Chain

1. An attacker establishes an unauthenticated TCP connection to the Xlight FTP Server on the configured SSH port.
2. The attacker initiates the SSH version exchange and key exchange (KEX) process.
3. The attacker requests the use of a GCM cipher suite during the SSH negotiation phase.
4. The attacker sends a specially crafted SSH packet containing a manipulated length field that exceeds expected boundaries.
5. The Xlight FTP Server's GCM decryption function processes the unvalidated length field, resulting in a stack buffer overflow.
6. The overflow overwrites critical stack memory, including the stack canary and the function return address.
7. The function execution returns to an attacker-controlled address or a gadget chain.
8. The attacker achieves arbitrary code execution on the server host with the privileges of the FTP service.

## Impact

Successful exploitation of CVE-2026-67192 allows unauthenticated remote attackers to gain code execution on affected Xlight FTP servers. This compromises the integrity and confidentiality of the entire server environment, potentially allowing for data exfiltration, lateral movement within the network, or the installation of persistent backdoors. Organizations running exposed Xlight FTP services prior to version 3.9.5 are at risk of complete system compromise.

## Recommendation

* Immediately upgrade Xlight FTP Server to version 3.9.5 or later to remediate CVE-2026-67192.
* Until patching is possible, restrict network access to the Xlight FTP server to trusted IP addresses using a firewall.
* Deploy network-based intrusion detection signatures capable of inspecting SSH KEX packets for anomalous length values or malformed GCM negotiation structures.
* Monitor server logs for unexpected crashes or service restarts which may indicate failed or repeated exploitation attempts.
