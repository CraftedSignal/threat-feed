---
title: Improper Certificate Validation in MsQuic OpenSSL Backend
slug: 2026-10-msquic-tls-validation
description: The MsQuic library using OpenSSL or QuicTLS backends fails to perform proper TLS hostname verification, enabling on-path attackers to perform man-in-the-middle (MITM) attacks and spoof server identities.
date: "2026-10-07T00:44:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:microsoft:msquic:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - tls
  - quic
  - mitm
vendors:
  - Microsoft
products:
  - MsQuic (< 2.4.20, 2.5.0-2.5.10, 2.6.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: The vulnerability allows an on-path attacker to conduct a man-in-the-middle (MITM) attack by spoofing the server identity.
    confidence_band: high
cves:
  - id: CVE-2026-105794
references:
  - https://github.com/advisories/GHSA-w5f4-fx9m-m4q7
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Update Microsoft.Native.Quic.MsQuic.OpenSSL to version 2.4.20, 2.5.11, or 2.6.1
      owner: IT Operations
      addresses: CVE-2026-105794
      evidence: Source advisory recommends upgrading to 2.6.1, 2.5.11, or 2.4.20
---

MsQuic, a cross-platform implementation of the IETF QUIC protocol, contains a vulnerability in its certificate validation logic when using the OpenSSL or QuicTLS TLS backends. The flaw, tracked as CVE-2026-105794, arises from improper TLS hostname verification. This issue affects specific versions of the Microsoft.Native.Quic.MsQuic.OpenSSL NuGet package, including versions below 2.4.20, those between 2.5.0 and 2.5.10, and those between 2.6.0 and 2.6.0. 

When an application utilizing an affected version of MsQuic initiates a QUIC connection, the library fails to ensure that the certificate presented by the remote peer matches the expected hostname. This vulnerability allows an on-path attacker to intercept QUIC traffic and present a fraudulent certificate that the client will accept as valid, thereby facilitating a man-in-the-middle (MITM) attack. The Schannel backend is confirmed to be unaffected. Defenders should prioritize updating applications that bundle or dynamically link against the impacted MsQuic versions to the patched releases: 2.4.20, 2.5.11, or 2.6.1.

## Impact

Successful exploitation allows a man-in-the-middle attacker to intercept, inspect, or modify encrypted traffic between the client and the server. This compromises the integrity and confidentiality of the QUIC-based communications, potentially leading to the theft of sensitive session data, credentials, or other payloads transmitted over the connection. The impact is significant for any enterprise application relying on MsQuic for secure, performance-critical QUIC transport.

## Recommendation

Prioritize updating all applications and services utilizing the vulnerable Microsoft.Native.Quic.MsQuic.OpenSSL NuGet package to the patched versions: 2.4.20, 2.5.11, or 2.6.1. Perform a software composition analysis (SCA) scan to identify instances of the vulnerable package within your environment.
