---
title: Multiple Vulnerabilities in IBM App Connect Enterprise
slug: 2026-10-ibm-ace-vulnerabilities
description: IBM App Connect Enterprise contains multiple vulnerabilities including CVE-2024-45063, CVE-2024-45064, and CVE-2024-45065, which may allow attackers to bypass security, conduct denial-of-service, or disclose sensitive information.
date: "2026-10-09T12:59:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:freebsd:freebsd:*:*:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:13.3:*:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:13.4:beta3:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:14.0:*:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:14.1:*:*:*:*:*:*:*
  - cpe:2.3:a:st:x-cube-azrt-h7rs:1.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:st:x-cube-azrtos-f4:1.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:st:x-cube-azrtos-f7:1.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:st:x-cube-azrtos-g0:1.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:st:x-cube-azrtos-g4:2.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:st:x-cube-azrtos-h7:3.3.0:*:*:*:*:*:*:*
  - cpe:2.3:a:st:x-cube-azrtos-l4:2.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:st:x-cube-azrtos-l5:2.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:st:x-cube-azrtos-wb:2.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:st:x-cube-azrtos-wl:2.0.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ibm
  - app-connect-enterprise
vendors:
  - IBM
products:
  - App Connect Enterprise
cves:
  - id: CVE-2024-45063
    cvss: 8.8
    epss: 0.00521
  - id: CVE-2024-45064
    cvss: 8.5
    epss: 0.01106
  - id: CVE-2024-45065
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3831
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade IBM App Connect Enterprise to the latest version as specified in IBM security advisories.
      owner: IT Operations
      addresses: CVE-2024-45063, CVE-2024-45064, CVE-2024-45065
      evidence: Source indicates multiple vulnerabilities require patching.
---

IBM has disclosed multiple security vulnerabilities affecting IBM App Connect Enterprise. These vulnerabilities, identified as CVE-2024-45063, CVE-2024-45064, and CVE-2024-45065, present significant risks to organizational infrastructure. An unauthenticated remote attacker could leverage these flaws to bypass established security controls, execute a denial-of-service attack against the application, or perform unauthorized information disclosure. Given the critical role of App Connect Enterprise in integration and workflow automation, successful exploitation could compromise sensitive business data flows or lead to application downtime. Organizations currently running IBM App Connect Enterprise are advised to review the official IBM security bulletins to determine specific version vulnerability and apply the necessary patches provided by the vendor.

## Impact

Successful exploitation of these vulnerabilities could lead to a complete denial of service for integration services, unauthorized exposure of internal configuration or application data, and the circumvention of security authentication measures. This poses a risk to organizations relying on IBM App Connect Enterprise for critical middleware operations, potentially affecting data integrity and service availability across the enterprise landscape.

## Recommendation

* Review current IBM App Connect Enterprise deployments against the list of affected versions provided by IBM in the official security bulletins for CVE-2024-45063, CVE-2024-45064, and CVE-2024-45065.
* Apply available security updates or patches immediately as recommended by IBM to mitigate the risk of remote exploitation.
* Monitor enterprise application logs for anomalous traffic patterns or unexpected service instability that could indicate exploitation attempts related to these CVEs.
