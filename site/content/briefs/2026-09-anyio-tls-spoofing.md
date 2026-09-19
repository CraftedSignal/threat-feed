---
title: AnyIO TLS Certificate Spoofing via IDNA 2003 Encoding
slug: 2026-09-anyio-tls-spoofing
description: AnyIO versions prior to 4.14.2 are vulnerable to TLS certificate spoofing when using IDNA 2003 encoded internationalized domain names, allowing an attacker who redirects traffic to present a domain-validated certificate that the client incorrectly trusts.
date: "2026-09-18T19:48:05Z"
lastmod: "2026-09-19T07:44:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - vulnerability
  - python
  - linux
vendors:
  - AnyIO
products:
  - AnyIO (< 4.14.2)
  - AnyIO (4.14.0, 4.14.1)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This is a POSIX privilege-dropping correctness issue for applications that rely on AnyIO subprocess helpers to launch less-privileged child processes.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-82r6-8w77-94w6
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-63374
  - https://github.com/advisories/GHSA-3w57-8xmc-8v26
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-63349
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade anyio package to version 4.14.2 or later
      owner: IT Operations
      due: 48h
      evidence: The vulnerability will be patched in v4.14.2.
  mitigation_plan:
    - priority: immediate
      action: Manually encode internationalized host names using the idna package
      owner: Application Security
      addresses: CVE-2026-63374
      evidence: Encode host names via the idna package prior to connecting.
updates:
  - at: "2026-09-19T07:44:57Z"
    level: L2
    summary: added coverage for AnyIO (4.14.0, 4.14.1)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-3w57-8xmc-8v26
---

AnyIO (CVE-2026-63374) contains a vulnerability in its TLSStream implementation related to the handling of internationalized domain names (IDNs). The library incorrectly relies on the deprecated IDNA 2003 standard for host name encoding. If an application uses AnyIO's `connect_tcp()` or `TLSStream.wrap()` to connect to an internationalized domain, an attacker capable of hijacking or redirecting the network connection can exploit this discrepancy. By obtaining a legitimate TLS certificate using the IDNA 2003 encoding of the intended host name, the attacker can present this certificate to the AnyIO client. The client, utilizing the same outdated encoding logic, validates the malicious certificate as authentic for the intended domain. This vulnerability facilitates potential man-in-the-middle (MITM) attacks for services relying on AnyIO for outbound connections to internationalized domains.

## Impact

The vulnerability poses a critical risk to applications using AnyIO that perform outbound connections to internationalized host names. Successful exploitation allows for the complete bypass of TLS certificate validation, enabling attackers to intercept, inspect, or modify sensitive data transmitted between the client and the intended server. Organizations operating services that communicate with diverse global domains are at the highest risk.

## Recommendation

* Upgrade the `anyio` package to version 4.14.2 or later immediately.
* As a temporary workaround, manually encode host names using the modern `idna` package prior to passing them to AnyIO connection methods to ensure compatibility with modern standards.
* Audit application code to identify calls to `connect_tcp()` or `TLSStream.wrap()` that handle user-provided or dynamic internationalized host names.
