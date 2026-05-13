---
title: Exim Mail Transfer Agent User-After-Free Remote Code Execution Vulnerability (CVE-2026-45185)
slug: 2026-05-exim-rce
description: CVE-2026-45185, a user-after-free vulnerability in Exim versions 4.97 through 4.99.2, allows an unauthenticated remote attacker to execute arbitrary code by sending crafted SMTP traffic with BDAT chunking during TLS shutdown.
date: "2026-05-13T20:24:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - exim
  - rce
  - vulnerability
  - cve-2026-45185
  - user-after-free
  - gnutls
vendors:
  - Exim
  - Debian
  - Ubuntu
products:
  - Exim (4.97 to 4.99.2)
affected_os:
  - Debian
  - Ubuntu
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-45185
    cvss: 9.8
references:
  - https://www.bleepingcomputer.com/news/security/new-critical-exim-mailer-flaw-allows-remote-code-execution/
  - CVE-2026-45185
rules:
  - title: Detect Exim CVE-2026-45185 Exploitation Attempt via SMTP BDAT
    description: Detects CVE-2026-45185 exploitation attempt via network traffic by monitoring for SMTP connections using STARTTLS and BDAT commands.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect Exim CVE-2026-45185 Exploitation - Process Creation
    description: Detects CVE-2026-45185 exploitation by monitoring for suspicious process creation events originating from the Exim process.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-45185, affects Exim mail transfer agent versions 4.97 through 4.99.2 when built with the default GNU Transport Layer Security (GnuTLS) library. This user-after-free (UAF) flaw is triggered during the TLS shutdown process while handling BDAT chunked SMTP traffic. An unauthenticated remote attacker can exploit this vulnerability to execute arbitrary code on the server. Exim is a widely deployed open-source mail transfer agent used on Linux and Unix servers, including shared hosting environments, enterprise mail systems, and Debian- and Ubuntu-based distributions where it has historically been the default mail server. The vulnerability impacts Exim versions 4.97 through 4.99.2 on builds compiled with GnuTLS that have STARTTLS and CHUNKING advertised. A fix is available in Exim version 4.99.3.

## Attack Chain

1.  The attacker establishes a connection to the Exim server over SMTP.
2.  The attacker initiates a TLS handshake using the STARTTLS command, which is supported by the server.
3.  The attacker sends SMTP traffic with BDAT chunking.
4.  During the TLS shutdown process, Exim incorrectly frees a TLS transfer buffer due to the user-after-free vulnerability (CVE-2026-45185).
5.  Exim continues to use stale callback references, attempting to write data into the freed memory region.
6.  The attacker leverages this memory corruption to overwrite critical data structures, gaining control of program execution.
7.  The attacker executes arbitrary commands on the server with the privileges of the Exim process.
8.  The attacker can then access Exim data and emails, and potentially pivot further into the environment depending on server permissions and configuration.

## Impact

Successful exploitation of CVE-2026-45185 allows an unauthenticated remote attacker to execute arbitrary code on the Exim server. This could lead to complete system compromise, including unauthorized access to sensitive data such as emails, and the ability to pivot to other systems within the network. Given Exim's widespread deployment, a successful attack could impact numerous organizations, particularly those using Debian and Ubuntu-based Linux distributions.

## Recommendation

*   Apply the available Exim updates (v4.99.3) through your package managers on Ubuntu and Debian-based Linux distributions to patch CVE-2026-45185.
*   Monitor network traffic for suspicious SMTP connections using STARTTLS and BDAT chunking to detect potential exploitation attempts. Use the "Detect Exim CVE-2026-45185 Exploitation Attempt via SMTP BDAT" Sigma rule.
*   Consider disabling STARTTLS or CHUNKING features in Exim if immediate patching is not feasible, but be aware of the potential impact on email functionality.
*   Enable process creation logging on Exim servers to assist in detecting potential attacker-initiated processes post-exploitation, as covered by the "Detect Exim CVE-2026-45185 Exploitation - Process Creation" Sigma rule.
