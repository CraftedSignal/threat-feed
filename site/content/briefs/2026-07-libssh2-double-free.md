---
title: CVE-2026-66032 - libssh2 SFTP Double-Free Vulnerability
slug: 2026-07-libssh2-double-free
description: A double-free vulnerability, CVE-2026-66032, in libssh2 versions through 1.11.1 allows a malicious SSH server to corrupt the heap of an authenticated client opening an SFTP session, potentially leading to arbitrary code execution.
date: "2026-07-24T17:20:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssh
  - sftp
  - double-free
  - vulnerability
  - libssh2
  - memory-corruption
  - rce
vendors:
  - libssh2
products:
  - libssh2 <= 1.11.1
affected_os:
  - Linux
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: a malicious SSH server to corrupt the heap of any authenticated client opening an SFTP session... enabling tcache dup conditions on glibc systems that allow overlapping allocations and function pointer overwrites.
    confidence_band: high
cves:
  - id: CVE-2026-66032
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66032
---

A critical double-free vulnerability, identified as CVE-2026-66032, exists in libssh2 versions up to and including 1.11.1. This flaw resides within the `sftp_open()` function in `src/sftp.c` and can be exploited by a malicious SSH server. When an authenticated client attempts to open an SFTP session to such a server, the server can trigger a heap corruption on the client side. This occurs if the server responds to an `SSH_FXP_OPEN` request with an `SSH_FXP_STATUS` containing `FX_OK`, causing the response data buffer to be freed. If a subsequent `sftp_packet_require()` call then returns a specific error like `LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED`, the same pointer is freed a second time. On glibc systems, this double-free condition can lead to tcache dup, enabling overlapping memory allocations and ultimately function pointer overwrites, which could result in arbitrary code execution on the vulnerable client system.

## Attack Chain

1. A malicious SSH server is configured to exploit the libssh2 vulnerability.
2. An authenticated client using a vulnerable version of libssh2 attempts to connect to the malicious SSH server and initiates an SFTP session via the `sftp_open()` function.
3. The malicious server responds to the client's `SSH_FXP_OPEN` request with an `SSH_FXP_STATUS` packet that includes `FX_OK`.
4. The client-side `sftp_open()` function processes this initial response, leading to the first deallocation of the response data buffer.
5. During subsequent processing, or due to a crafted response from the malicious server, a call to `sftp_packet_require()` for the same buffer returns a specific error, such as `LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED`.
6. The `sftp_open()` function attempts to free the already freed response data buffer for a second time, triggering the double-free condition.
7. On client systems running glibc, this double-free vulnerability can be leveraged to achieve tcache dup, allowing for controlled overlapping memory allocations.
8. An attacker can then manipulate these memory allocations to overwrite function pointers, ultimately leading to arbitrary code execution on the vulnerable client system.

## Impact

Successful exploitation of CVE-2026-66032 can lead to heap corruption and function pointer overwrites on the authenticated client system. This memory corruption can be escalated to arbitrary code execution, allowing the malicious SSH server to execute commands with the privileges of the SFTP client process. This poses a significant risk to systems that connect to untrusted SSH servers using vulnerable libssh2 versions, potentially compromising data integrity, confidentiality, and system availability. No specific victim numbers or targeted sectors are currently available.

## Recommendation

* Patch CVE-2026-66032 immediately by upgrading libssh2 to a version beyond 1.11.1, specifically one that includes commit `5e47761` or later.
* Implement host-based intrusion detection systems (HIDS) capable of detecting memory corruption anomalies or unusual process behavior following SFTP connections.
* Restrict SFTP client connections to trusted SSH servers only, especially for clients running vulnerable libssh2 versions.
* Enable verbose logging for SSH/SFTP client activities and monitor for unexpected client application crashes or unauthorized process launches.
