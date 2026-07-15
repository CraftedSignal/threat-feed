---
title: Vulnerability in ESET Inspect Connector Allowing Privilege Escalation
slug: 2026-07-eset-inspect-connector-privesc
description: A vulnerability, CVE-2026-6423, in ESET Inspect Connector versions prior to 3.1.6017.0 for Windows allows an attacker to achieve privilege escalation on affected systems.
date: "2026-07-15T14:37:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - endpoint-security
vendors:
  - ESET
products:
  - ESET Inspect Connector (versions prior to 3.1.6017.0)
affected_os:
  - Windows
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0882/
  - https://support-feed.eset.com/link/15370/17380063/ca8970
  - https://www.cve.org/CVERecord?id=CVE-2026-6423
---

A vulnerability tracked as CVE-2026-6423 has been discovered in ESET Inspect Connector, a component of ESET's Endpoint Detection and Response (EDR) solution. This flaw affects all versions of ESET Inspect Connector for Windows prior to 3.1.6017.0. The vulnerability allows a local attacker to achieve privilege escalation on systems where the affected software is installed. While the specific mechanism of exploitation is not detailed, successful exploitation would grant higher system privileges to an adversary, potentially leading to full system compromise or enabling further malicious activities that require elevated permissions. Defenders should prioritize patching to mitigate this risk.

## Impact

Successful exploitation of CVE-2026-6423 can lead to a local attacker gaining elevated privileges on a compromised Windows system. This can bypass security controls, enable the installation of persistent malware, exfiltrate sensitive data, or disrupt system operations. While the advisory does not specify observed attacks or victim sectors, privilege escalation vulnerabilities are frequently chained with other attack vectors, such as initial access through phishing, to achieve comprehensive system control.

## Recommendation

* Patch CVE-2026-6423 on all affected ESET Inspect Connector installations immediately by updating to version 3.1.6017.0 or later, as recommended in the ESET security bulletin referenced below.
