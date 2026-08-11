---
title: Out-of-Bounds Memory Corruption in FreeRDP
slug: 2026-08-freerdp-oob
description: FreeRDP versions before 3.30.0 are vulnerable to memory corruption in the kerberos_DecryptMessage function, allowing a malicious peer to perform out-of-bounds read and write operations via crafted GSS Wrap tokens during authentication.
date: "2026-08-11T14:03:03Z"
lastmod: "2026-08-11T14:03:11Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - FreeRDP
products:
  - FreeRDP
  - FreeRDP (< 3.30.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote client can send a Capabilities PDU instead of the required Authentication Request PDU; rdstls_process_capabilities() returns success without ever setting resultCode, so the server responds with an AUTHRSP carrying resultCode SUCCESS and treats the session as authenticated.
    confidence_band: high
cves:
  - id: CVE-2026-72745
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72745
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72746
updates:
  - at: "2026-08-11T14:03:11Z"
    level: L2
    summary: added coverage for FreeRDP (< 3.30.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72746
---

FreeRDP versions prior to 3.30.0 contain a critical memory safety vulnerability in the `kerberos_DecryptMessage` function located within `winpr/libwinpr/sspi/Kerberos/kerberos.c`. The vulnerability arises from improper validation of the 16-bit EC (extra count) field within a GSS Wrap token as defined in RFC 4121. While the implementation validates the RRC field and the total buffer length, it fails to perform bounds checking on the EC field before using it in pointer arithmetic to calculate encrypted regions within the buffer.

An attacker acting as a malicious peer (either client or server) can provide a specially crafted EC value up to 0xFFFF during the CredSSP or NLA authentication handshake. This causes the decryption logic to compute memory offsets outside the allocated ~60-byte token buffer. Because the library performs in-place decryption for AES-CTS-HMAC enctypes before verifying the HMAC integrity, the vulnerability allows for both out-of-bounds reads and writes. This can result in denial of service, sensitive information disclosure, or potential arbitrary code execution through memory corruption.

## Impact

Successful exploitation allows a malicious peer to trigger memory corruption on a system running an affected version of FreeRDP. This impacts any environment using FreeRDP-based clients or servers for remote access. Potential outcomes include crash-based denial of service, leakage of sensitive memory contents, or potential escalation to arbitrary code execution, depending on the memory layout and attacker capabilities. This vulnerability affects cross-platform deployments given FreeRDP's usage on Linux, macOS, and Windows.

## Recommendation

1. Upgrade all instances of FreeRDP to version 3.30.0 or higher immediately to address the missing bounds check in the kerberos_DecryptMessage function.
2. Inventory all services and applications within the environment that utilize the FreeRDP library or the WinPR component to ensure comprehensive patching.
3. Monitor system logs for frequent crashes or unexpected termination of RDP-related processes, which may indicate attempted exploitation of this memory corruption vulnerability.
