---
title: Phpseclib ASN.1 Integer Overflow Vulnerability (CVE-2023-49316)
slug: 2024-01-phpseclib-asn1-integer-overflow
description: Phpseclib versions 3.0.0 before 3.0.34 are vulnerable to an integer overflow when loading untrusted ASN.1 files, such as X.509 certificates and RSA PKCS8 keys, potentially leading to denial of service or remote code execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:phpseclib:phpseclib:*:*:*:*:*:*:*:*
tags:
  - integer-overflow
  - asn1
  - php
  - CVE-2023-49316
vendors:
  - phpseclib
products:
  - phpseclib/phpseclib (>= 3.0.0, < 3.0.34)
cves:
  - id: CVE-2023-49316
    cvss: 7.5
    epss: 0.00149
references:
  - https://github.com/advisories/GHSA-2f25-pfq3-c7h8
  - https://github.com/phpseclib/phpseclib/commit/964d78101a70305df33f442f5490f0adb3b7e77f
  - https://www.usenix.org/system/files/usenixsecurity25-shi-bing.pdf
rules:
  - title: Detect Suspicious Phpseclib ASN1 Parsing
    description: Detects CVE-2023-49316 exploitation — suspicious PHP process parsing ASN1 data, potentially indicating an integer overflow attack.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious File Uploads with ASN1 Content
    description: Detects suspicious file uploads containing ASN.1 content, potentially indicating an attempt to exploit CVE-2023-49316.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Phpseclib, a pure-PHP secure communications library, is susceptible to an integer overflow vulnerability (CVE-2023-49316) affecting versions 3.0.0 through 3.0.33. This flaw arises during the parsing of ASN.1 files containing large binaryfield integers. Attackers can exploit this vulnerability by crafting malicious ASN.1 structures, such as X.509 certificates or RSA PKCS8 keys, which, when processed by a vulnerable Phpseclib installation, trigger an integer overflow. Successful exploitation could lead to denial of service due to excessive memory consumption or, potentially, remote code execution. This poses a risk to applications that rely on Phpseclib for secure communication and cryptographic operations, particularly those handling untrusted or externally sourced ASN.1 data.

## Attack Chain

1.  Attacker crafts a malicious ASN.1 file (e.g., X.509 certificate, RSA PKCS8 key) containing a large binaryfield integer.
2.  The malicious ASN.1 file is delivered to a vulnerable system, potentially through user upload, network transfer, or injection into a database.
3.  The vulnerable application uses Phpseclib to parse the malicious ASN.1 file.
4.  Phpseclib's ASN.1 parser encounters the large binaryfield integer.
5.  During the processing of the integer, an integer overflow occurs due to insufficient bounds checking.
6.  The integer overflow leads to memory corruption or excessive memory allocation.
7.  If memory corruption occurs, the application may crash, or the attacker may gain control of program execution.
8.  If excessive memory allocation occurs, the system may experience a denial of service due to resource exhaustion.

## Impact

Successful exploitation of CVE-2023-49316 can result in a denial-of-service condition, disrupting applications relying on Phpseclib. In more severe scenarios, the integer overflow could lead to memory corruption and potentially allow for remote code execution. This vulnerability affects any application using Phpseclib versions 3.0.0 to 3.0.33 that handles untrusted ASN.1 data. The impact is especially significant for applications dealing with sensitive data, such as cryptographic keys or certificates.

## Recommendation

*   Upgrade Phpseclib to version 3.0.34 or later to patch CVE-2023-49316.
*   Deploy the Sigma rule "Detect Suspicious Phpseclib ASN1 Parsing" to identify potential exploitation attempts.
*   Implement input validation and sanitization to prevent the processing of untrusted ASN.1 files with abnormally large integer values.
*   Monitor web server logs for unusual activity related to ASN.1 file uploads or processing.
