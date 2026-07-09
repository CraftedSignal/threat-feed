---
title: CVE-2026-60109 - Zeek Kerberos Protocol Analyzer Null Pointer Dereference
slug: 2026-07-zeek-kerberos-dos
description: A null pointer dereference vulnerability (CVE-2026-60109) exists in Zeek's Kerberos protocol analyzer before version 8.0.9, allowing unauthenticated remote attackers to crash a Zeek sensor by sending a specially crafted KRB_ERROR message with error-code 25 and specific PA-DATA elements, leading to a denial-of-service condition.
date: "2026-07-09T15:20:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - network
  - dos
  - zeek
  - kerberos
vendors:
  - Zeek Project
products:
  - Zeek (< 8.0.9)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: allows unauthenticated remote attackers to crash the sensor
    confidence_band: high
cves:
  - id: CVE-2026-60109
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-60109
---

A critical denial-of-service vulnerability, identified as CVE-2026-60109, impacts Zeek versions prior to 8.0.9. This flaw resides within Zeek's Kerberos protocol analyzer, specifically due to a null pointer dereference. Unauthenticated remote attackers can exploit this vulnerability by sending a meticulously crafted `KRB_ERROR` message. The malicious message must contain `error-code 25` (KDC_ERR_PREAUTH_REQUIRED) and include a `PA-DATA` element with `padata-type 2, 3, 11, or 19`. This specific combination triggers a mismatch between the parser and analyzer states, leading `proc_padata()` to dereference an uninitialized `pa_data_element` field. The exploitation requires only a single UDP or TCP packet sent to port 88, without requiring any credentials or prior authentication, and results in the Zeek sensor crashing, effectively causing a denial of service.

## Attack Chain

1. An unauthenticated remote attacker crafts a specialized Kerberos `KRB_ERROR` message.
2. The crafted message includes `error-code 25`, which corresponds to `KDC_ERR_PREAUTH_REQUIRED`.
3. Within the `KRB_ERROR` message, a `PA-DATA` element is embedded with a `padata-type` specifically set to `2, 3, 11, or 19`.
4. The attacker sends this single, malformed UDP or TCP packet to a vulnerable Zeek sensor's port 88.
5. The Zeek sensor's Kerberos protocol analyzer, `proc_padata()`, attempts to process the incoming `KRB_ERROR` message.
6. Due to an internal parser and analyzer state mismatch, `proc_padata()` incorrectly dereferences an uninitialized `pa_data_element` field.
7. This dereference of a null pointer causes a critical error within the Zeek application.
8. The Zeek sensor application crashes entirely, resulting in a denial-of-service condition for network monitoring and analysis.

## Impact

The successful exploitation of CVE-2026-60109 leads directly to a denial-of-service (DoS) for the affected Zeek sensor. This means that organizations relying on Zeek for network security monitoring, intrusion detection, or forensic analysis will temporarily lose visibility into their network traffic from the crashed sensor. The impact can be severe for organizations with critical network infrastructure or strict compliance requirements, as it can create blind spots for threat detection and incident response, potentially allowing other malicious activities to go unnoticed while the sensor is offline.

## Recommendation

* Prioritize patching Zeek instances to version 8.0.9 or later immediately to remediate CVE-2026-60109.
* Monitor network traffic for unusual Kerberos `KRB_ERROR` messages specifically targeting port 88 with `error-code 25` and `PA-DATA` elements containing `padata-type 2, 3, 11, or 19`. While detailed detection requires deep packet inspection, anomalous traffic patterns can be indicators.
