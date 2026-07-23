---
title: Libunbound Denial of Service via unwanted-reply-threshold
slug: 2026-07-libunbound-dos
description: CVE-2026-44621 describes a vulnerability in Libunbound applications where, when configured with the 'unwanted-reply-threshold' option, they can be abruptly terminated, leading to a denial of service.
date: "2026-07-23T07:28:10Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - libunbound
vendors:
  - NLnet Labs
products:
  - Libunbound
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: CVE-2026-44621 describes a vulnerability affecting Libunbound applications. When these applications are configured with the 'unwanted-reply-threshold' option, they can eventually be abruptly terminated, leading to a denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-44621
    cvss: 5.9
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44621
---

CVE-2026-44621 details a denial-of-service vulnerability impacting applications that leverage the Libunbound DNS resolver library. This issue specifically arises when Libunbound applications are configured with the `unwanted-reply-threshold` option. Under certain conditions, processing maliciously crafted or unusual DNS replies can lead to the gradual degradation of the application's stability, eventually causing it to terminate abruptly. This vulnerability, disclosed by the Microsoft Security Response Center, highlights a potential risk to the availability and stability of services relying on affected Libunbound versions for DNS resolution. The public advisory does not detail the precise trigger mechanisms or the volume or nature of replies required for successful exploitation, but the consequence is a critical disruption to the application's function. Defenders should prioritize identifying Libunbound deployments within their infrastructure and monitoring for updates.

## Impact

Successful exploitation of CVE-2026-44621 leads to an abrupt termination of the affected Libunbound application. This results in a denial-of-service condition, rendering services dependent on Libunbound's DNS resolution unavailable or unreliable. Organizations using vulnerable versions of Libunbound, particularly those with the `unwanted-reply-threshold` configured, face a risk of service interruption, which could lead to operational downtime, loss of revenue, and reputational damage depending on the criticality of the affected application.

## Recommendation

* Monitor the official channels of NLnet Labs and Microsoft Security Response Center for further details and security updates related to CVE-2026-44621.
* Review configurations of all Libunbound applications within your environment to identify instances utilizing the `unwanted-reply-threshold` option.
* Consider disabling the `unwanted-reply-threshold` option if its operational impact outweighs the risk of this denial-of-service vulnerability, after proper assessment and testing.
