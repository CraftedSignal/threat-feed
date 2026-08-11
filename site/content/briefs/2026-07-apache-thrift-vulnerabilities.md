---
title: Multiple Vulnerabilities Identified in Apache Thrift
slug: 2026-07-apache-thrift-vulnerabilities
description: Multiple vulnerabilities, including decompression bombs (CVE-2026-48586, CVE-2026-49158), an integer overflow (CVE-2026-55969), and a heap out-of-bounds read (CVE-2026-58023), affect Apache Thrift prior to version 0.24.0, potentially leading to denial of service, memory corruption, or arbitrary code execution, and require immediate patching.
date: "2026-07-28T14:35:38Z"
lastmod: "2026-08-11T10:41:46Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:apache:thrift:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - apache
  - library
vendors:
  - Apache
products:
  - Apache Thrift (Prior to 0.24.0)
  - Thrift
cves:
  - id: CVE-2026-48586
    cvss: 7.5
    epss: 0.01074
  - id: CVE-2026-49158
    cvss: 7.5
    epss: 0.01097
  - id: CVE-2026-55969
    cvss: 7.5
    epss: 0.01097
  - id: CVE-2026-58023
    cvss: 9.1
    epss: 0.01083
references:
  - https://cyber.gc.ca/en/alerts-advisories/apache-security-advisory-av26-749
  - https://lists.apache.org/thread/p008svsjf9p6bj47wyyf5dgglq5z7xoq
  - https://lists.apache.org/thread/fmjl8l415tj9zwlob8v2dr5hq1d0hts7
  - https://lists.apache.org/thread/xmkgd107k795hyrg5kf97mny30sgl5bo
  - https://lists.apache.org/thread/z2myopbovxngfvchdz8hddots9p5ffbt
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55969
updates:
  - at: "2026-08-11T10:41:46Z"
    level: L1
    summary: new product
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55969
---

The Canadian Centre for Cyber Security (CCCS) has issued an advisory regarding multiple critical vulnerabilities affecting Apache Thrift, a framework for scalable cross-language services development. These vulnerabilities, identified as CVE-2026-48586, CVE-2026-49158, CVE-2026-55969, and CVE-2026-58023, impact all versions of Apache Thrift prior to 0.24.0. The issues include decompression size limits and bomb vulnerabilities in TZlibTransport and Ruby THeaderTransport, an integer overflow within TProtocol::checkReadBytesAvailable(), and a heap out-of-bounds read in the c_glib transport. While specific exploitation details are not provided, such vulnerabilities typically allow attackers to cause denial of service, corrupt memory, or potentially achieve arbitrary code execution. Organizations utilizing Apache Thrift are urged to update their installations to version 0.24.0 or later to mitigate these risks.

## Attack Chain

The provided advisory describes vulnerabilities within the Apache Thrift library but does not detail a specific attack chain or observed exploitation in the wild. Exploitation would likely involve an attacker sending specially crafted input to an application utilizing the vulnerable Apache Thrift library, triggering one of the described flaws. For example, a malicious client could send compressed data designed to trigger a decompression bomb, leading to resource exhaustion, or a malformed request that causes an integer overflow or heap out-of-bounds read, which might lead to a crash, memory corruption, or even arbitrary code execution.

## Impact

Successful exploitation of these vulnerabilities could lead to significant impact depending on the specific flaw and its context within an application. Decompression bombs (CVE-2026-48586, CVE-2026-49158) can cause denial of service by exhausting system resources (CPU, memory), making affected applications unavailable. Integer overflow (CVE-2026-55969) and heap out-of-bounds read (CVE-2026-58023) vulnerabilities can lead to application crashes, memory corruption, or in severe cases, remote code execution. This could allow an attacker to gain unauthorized control over the affected system, exfiltrate sensitive data, or further compromise the network. The broad use of Apache Thrift across various services means many applications could be at risk if not updated.

## Recommendation

* Review the Apache security advisories for CVE-2026-48586, CVE-2026-49158, CVE-2026-55969, and CVE-2026-58023 immediately.
* Upgrade all instances of Apache Thrift to version 0.24.0 or later to address the identified vulnerabilities.
* Consult the provided reference links for detailed patching instructions and further information.
