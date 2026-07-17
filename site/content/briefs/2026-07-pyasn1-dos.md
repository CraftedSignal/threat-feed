---
title: 'CVE-2026-59884: pyasn1 BER/CER/DER Decoder Denial of Service Vulnerability'
slug: 2026-07-pyasn1-dos
description: A high-severity denial-of-service vulnerability, CVE-2026-59884, exists in the pyasn1 library's BER/CER/DER decoder due to unbounded long-form tag IDs, which could allow an unauthenticated attacker to trigger resource exhaustion, rendering affected applications unresponsive or unavailable.
date: "2026-07-17T07:07:43Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - library-vulnerability
  - python
vendors:
  - pyasn1 project
products:
  - pyasn1
cves:
  - id: CVE-2026-59884
    cvss: 7.5
    epss: 0.00354
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59884
---

A significant denial-of-service vulnerability, tracked as CVE-2026-59884, has been identified in the `pyasn1` library, specifically within its BER/CER/DER decoding functionality. This flaw arises from the decoder's inability to properly handle unbounded long-form tag IDs. An attacker could craft a specially malformed BER/CER/DER encoded message containing such an ID. When a vulnerable application attempts to process this message using `pyasn1`, the decoding operation will consume excessive system resources, leading to resource exhaustion, memory leaks, or an infinite loop. This resource depletion ultimately causes the affected application to become unresponsive or crash, resulting in a denial of service to legitimate users. While no specific attack campaigns are detailed in the initial disclosure, the ease of exploitation for such DoS vulnerabilities makes patching critical for any system processing untrusted ASN.1 data.

## Attack Chain

1. An attacker identifies an internet-facing application that uses the `pyasn1` library to process BER/CER/DER encoded data.
2. The attacker crafts a malicious BER/CER/DER message specifically designed to exploit the unbounded long-form tag ID vulnerability.
3. The crafted message includes a malformed tag ID structure intended to cause excessive parsing and resource consumption.
4. The attacker transmits this malicious BER/CER/DER message to a public-facing input endpoint of the vulnerable application.
5. The application receives the input and attempts to decode the malicious message using the vulnerable `pyasn1` BER/CER/DER decoder.
6. During the decoding process, the `pyasn1` library encounters the unbounded long-form tag ID.
7. The decoder enters a state of excessive resource consumption, leading to high CPU usage, memory exhaustion, or an infinite loop.
8. The application becomes unresponsive or crashes, resulting in a denial of service for legitimate users.

## Impact

Successful exploitation of CVE-2026-59884 primarily leads to a denial of service (DoS) for applications utilizing the vulnerable `pyasn1` library. Attackers can render an affected system or service completely unresponsive or unavailable, disrupting business operations and user access. The immediate consequence for victims is a loss of availability for critical services, which can lead to reputational damage, operational downtime, and potential financial losses. The scope of impact depends on the criticality of the application using `pyasn1` and its exposure to untrusted data.

## Recommendation

* Upgrade the `pyasn1` library to a patched version immediately to remediate CVE-2026-59884.
* Review all applications that process BER/CER/DER encoded data, especially those exposed to untrusted external input, to identify `pyasn1` dependencies.
* Implement robust input validation and sanitization for all BER/CER/DER data processed by your applications to mitigate risks from similar parsing vulnerabilities.
* Monitor application logs for sudden spikes in CPU or memory usage, particularly after processing external data, which could indicate a denial of service attempt related to CVE-2026-59884.
