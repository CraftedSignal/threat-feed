---
title: phpseclib OID Amplification DoS Vulnerability
slug: 2024-05-phpseclib-dos
description: A vulnerability exists in phpseclib when loading untrusted ASN1 files, potentially leading to an OID amplification denial-of-service (DoS) in the ASN1::decodeOID() function.
date: "2024-05-06T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - asn1
  - phpseclib
vendors:
  - phpseclib
products:
  - phpseclib (>= 0.0.11, <= 1.0.28)
  - phpseclib (>= 2.0.0, <= 2.0.53)
  - phpseclib (>= 3.0.0, <= 3.0.51)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-3qpq-r242-jqj7
  - https://github.com/phpseclib/phpseclib/commit/d53d2021bcb9f6a04d5d44ec99e6bbef219a71bc
rules:
  - title: Detect High CPU Usage by PHP
    description: Detects sustained high CPU usage by PHP processes, potentially indicating a DoS attack exploiting CVE-2026-44167.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect PHP process loading ASN1 files
    description: Detects PHP processes loading ASN1 files, could be related to CVE-2026-44167
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A denial-of-service vulnerability exists in the phpseclib library, affecting versions 0.0.11 through 1.0.28, 2.0.0 through 2.0.53, and 3.0.0 through 3.0.51. The vulnerability stems from improper handling of ASN.1 files, specifically during the `decodeOID()` function. When an application using a vulnerable version of phpseclib loads a crafted, malicious ASN.1 file (e.g., an X.509 certificate or RSA PKCS8 key), it can trigger excessive resource consumption, leading to a denial-of-service condition. This is due to the OID amplification. Successful exploitation can prevent legitimate users from accessing the affected service or application. Defenders should upgrade to the patched versions of phpseclib to mitigate this risk.

## Attack Chain

1. An attacker crafts a malicious ASN.1 file containing an overly complex or deeply nested OID structure.
2. The attacker delivers the crafted ASN.1 file to a system running a vulnerable application that uses phpseclib for ASN.1 parsing. This could be achieved through various means, such as uploading the file to a web server, emailing it as an attachment, or injecting it into a database.
3. The vulnerable application loads the crafted ASN.1 file using phpseclib.
4. phpseclib's `ASN1::decodeOID()` function is called to parse the OID within the ASN.1 file.
5. Due to the overly complex structure of the malicious OID, the `decodeOID()` function consumes excessive CPU and memory resources.
6. The excessive resource consumption degrades the performance of the application and the underlying system.
7. Repeated attempts to load the malicious ASN.1 file further exacerbate the resource exhaustion, leading to a denial-of-service condition.
8. Legitimate users are unable to access the application or service, causing disruption.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition, rendering applications relying on phpseclib unavailable. The impact is high, as affected applications could be critical infrastructure or business-critical services. The number of potential victims is significant, as phpseclib is a widely used library in PHP-based applications. This vulnerability is particularly concerning for applications that handle untrusted ASN.1 files, such as those involved in certificate validation or cryptographic key management.

## Recommendation

*   Upgrade the `composer/phpseclib/phpseclib` package to a patched version (later than 1.0.28, 2.0.53, and 3.0.51) to remediate CVE-2026-44167.
*   Monitor web server logs (category `webserver`) for unusual patterns of ASN.1 file uploads or processing that may indicate an attempted exploitation.
*   Deploy the Sigma rule `Detect High CPU Usage by PHP` to identify potential DoS attacks related to this vulnerability.
