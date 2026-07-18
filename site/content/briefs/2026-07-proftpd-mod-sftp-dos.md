---
title: ProFTPD mod_sftp Heap Overflow Allows Authenticated Denial of Service (CVE-2026-53994)
slug: 2026-07-proftpd-mod-sftp-dos
description: An authenticated SFTP user can trigger a heap-based buffer overflow in ProFTPD's mod_sftp module (CVE-2026-53994) by sending a malformed SFTP packet, leading to an integer underflow, an undersized buffer allocation, and subsequent heap corruption, which results in a reliable remote denial of service.
date: "2026-07-18T20:18:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - denial-of-service
  - sftp
  - linux-server
vendors:
  - ProFTPD
products:
  - ProFTPD mod_sftp
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Service Stop
    evidence: An authenticated user can crash the per-connection ProFTPD session child on demand with a single malformed SFTP packet
    confidence_band: high
cves:
  - id: CVE-2026-53994
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53994
---

CVE-2026-53994 impacts ProFTPD's `mod_sftp` module, enabling an authenticated SFTP user to trigger a heap-based buffer overflow. The vulnerability stems from the `fxp_packet_read()` function, which accepts an attacker-controlled 32-bit big-endian SFTP packet length without adequate sanity checks. Specifically, a zero-value packet length causes an unsigned integer underflow elsewhere in the read path, leading to an attempt to allocate approximately 4 GB of memory. Due to a type conversion issue, a much smaller buffer (approximately 544 bytes) is actually allocated. Subsequent attacker-controlled data streaming then overwrites heap memory beyond this small buffer, resulting in a reliable remote denial of service by crashing the ProFTPD session child process. This flaw was published on 2026-07-18 and allows for immediate disruption of SFTP services.

## Attack Chain

1. An authenticated attacker establishes an SFTP connection to a vulnerable ProFTPD server running `mod_sftp`.
2. The attacker sends a specially crafted SFTP packet to the server, targeting the `fxp_packet_read()` function.
3. This packet intentionally sets the 32-bit big-endian length field to a value of 0.
4. Within the `read` path, an unsigned subtraction operation with the zero length causes an integer underflow, resulting in a computed size of approximately 4 GB (0x100000000).
5. The core memory allocator is requested to allocate memory for this oversized request, but due to a 32-bit integer conversion, `new_block()` returns an actual allocation of a significantly smaller block (approximately 544 bytes).
6. The subsequent fill loop attempts to write attacker-controlled bytes into the buffer, assuming the previously reported 4 GB allocation, leading to a heap buffer overflow that writes past the end of the 544-byte allocated memory.
7. This heap overflow corrupts adjacent memory, causing the ProFTPD session child process to crash.
8. The attacker achieves reliable authenticated remote denial of service for the connected user, with potential for further heap metadata corruption.

## Impact

Successful exploitation of CVE-2026-53994 leads to a reliable remote denial of service (DoS) for authenticated users. An attacker can crash the per-connection ProFTPD session child process on demand, disrupting SFTP services provided by the server. While the primary observed impact is DoS, the underlying heap buffer overflow mechanism could potentially lead to heap metadata corruption, which might theoretically open avenues for more severe consequences like arbitrary code execution, though only denial of service is demonstrated by the supplied proof of concept. The number of potentially affected organizations is substantial, given ProFTPD's widespread use in Linux environments for secure file transfer services.

## Recommendation

* Immediately patch ProFTPD servers running `mod_sftp` to a version that addresses CVE-2026-53994.
* Monitor ProFTPD server logs for abnormal termination events or restarts of `proftpd` child processes, as these may indicate exploitation attempts of CVE-2026-53994.
