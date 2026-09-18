---
title: AnyIO TLS Certificate Spoofing via IDNA 2003 Encoding
slug: 2026-09-anyio-tls-spoofing
description: AnyIO versions prior to 4.14.2 are vulnerable to TLS certificate spoofing when using IDNA 2003 encoded internationalized domain names, allowing an attacker who redirects traffic to present a domain-validated certificate that the client incorrectly trusts.
date: "2026-09-18T19:48:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - AnyIO
products:
  - AnyIO (< 4.14.2)
references:
  - https://github.com/advisories/GHSA-82r6-8w77-94w6
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-63374
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
---

AnyIO (CVE-2026-63374) contains a vulnerability in its TLSStream implementation related to the handling of internationalized domain names (IDNs). The library incorrectly relies on the deprecated IDNA 2003 standard for host name encoding. If an application uses AnyIO's `connect_tcp()` or `TLSStream.wrap()` to connect to an internationalized domain, an attacker capable of hijacking or redirecting the network connection can exploit this discrepancy. By obtaining a legitimate TLS certificate using the IDNA 2003 encoding of the intended host name, the attacker can present this certificate to the AnyIO client. The client, utilizing the same outdated encoding logic, validates the malicious certificate as authentic for the intended domain. This vulnerability facilitates potential man-in-the-middle (MITM) attacks for services relying on AnyIO for outbound connections to internationalized domains.

## Impact

The vulnerability poses a critical risk to applications using AnyIO that perform outbound connections to internationalized host names. Successful exploitation allows for the complete bypass of TLS certificate validation, enabling attackers to intercept, inspect, or modify sensitive data transmitted between the client and the intended server. Organizations operating services that communicate with diverse global domains are at the highest risk.

## Recommendation

* Upgrade the `anyio` package to version 4.14.2 or later immediately.
* As a temporary workaround, manually encode host names using the modern `idna` package prior to passing them to AnyIO connection methods to ensure compatibility with modern standards.
* Audit application code to identify calls to `connect_tcp()` or `TLSStream.wrap()` that handle user-provided or dynamic internationalized host names.
