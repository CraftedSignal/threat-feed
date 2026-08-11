---
title: Denial of Service Vulnerability in libarchive
slug: 2026-08-libarchive-dos
description: A vulnerability in the libarchive library allows remote, anonymous attackers to trigger a denial-of-service condition through malicious archive processing.
date: "2026-08-11T01:28:08Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - libarchive
products:
  - libarchive
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in libarchive ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2710
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  mitigation_plan:
    - priority: medium_term
      action: Audit software inventory for applications using libarchive and prepare for patching
      owner: IT Operations
      addresses: libarchive
      evidence: Source advisory confirms library vulnerability
---

The BSI has reported a vulnerability in the libarchive library, a widely used open-source library for reading and writing various archive formats. The vulnerability allows an unauthenticated, remote attacker to trigger a denial-of-service (DoS) condition. This issue stems from improper handling of specific archive structures, which causes the library to consume excessive resources or crash when processing a crafted input. Because libarchive is a dependency for numerous operating system utilities, file archivers, and web application components, the scope of impact is potentially broad. Defenders should assess their software supply chain to identify applications utilizing libarchive and monitor for updates from their respective software vendors.

## Impact

Successful exploitation results in the disruption of services that rely on libarchive for processing archive files. This can lead to application crashes or process hangs, requiring manual intervention or service restarts. While the vulnerability is currently characterized as a DoS, it highlights the risks posed by improper input validation in high-performance parsing libraries.

## Recommendation

Prioritize the identification of applications within your environment that link against libarchive. Monitor vendor security bulletins for updates to operating systems and third-party software that integrate libarchive (e.g., bsdtar, various backup solutions, or compression utilities). Ensure that package managers are configured to pull the latest security patches once they are made available by distribution maintainers.
