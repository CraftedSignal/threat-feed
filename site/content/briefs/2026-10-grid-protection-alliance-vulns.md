---
title: Critical Vulnerabilities in Grid Protection Alliance openPDC and openHistorian
slug: 2026-10-grid-protection-alliance-vulns
description: Grid Protection Alliance openPDC and openHistorian contain multiple critical vulnerabilities, including insecure deserialization and missing authentication, allowing unauthenticated remote attackers to execute code, exfiltrate system data, or manipulate data streams.
date: "2026-10-08T17:06:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Grid Protection Alliance
products:
  - openPDC (< 2.9.482)
  - openPDC Docker image (< 2.9.482)
  - openHistorian (< 2.8.585)
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-281-02
---

Grid Protection Alliance has disclosed multiple high-severity vulnerabilities affecting openPDC and openHistorian software, widely used in the energy sector for phasor data management and historian functions. The vulnerabilities include CVE-2026-104629, CVE-2026-100730, CVE-2026-105281, CVE-2026-85479, CVE-2026-101022, and CVE-2026-105278. 

The most critical flaw (CVE-2026-100730) involves insecure deserialization within the service console interface, which, in deployments without Windows Authentication, allows unauthenticated network attackers to achieve remote code execution (RCE) with the privileges of the service account. Other flaws include missing authentication on data publishing interfaces (CVE-2026-105281, CVE-2026-85479), which enable unauthorized access to system topology and measurement data. These vulnerabilities pose a significant threat to industrial control environments, as they may allow attackers to gain persistent access or manipulate grid monitoring data.

## Impact

Successful exploitation could result in full system compromise, unauthorized exfiltration of sensitive energy grid measurement data, and potential disruption to monitoring capabilities. Organizations relying on these tools for critical infrastructure visibility are at risk of unauthorized access if internet-facing or unsegmented network interfaces remain exposed. There are no fixes planned for Docker image deployments, necessitating immediate mitigation for those instances.

## Recommendation

* Patch affected systems by upgrading openPDC to version 2.9.482 or later and openHistorian to version 2.8.585 or later.
* Audit network configurations to ensure internal data publisher interfaces are bound exclusively to the local loopback address. Existing installations do not automatically update this binding upon upgrade and require manual verification.
* Discontinue the use of published Docker images for production workloads, as the vendor does not provide security patches for these containers.
* Restrict network access to the service console interface and data publisher ports to trusted management subnets only.
* Enable Windows Authentication for services where supported to provide an additional layer of defense against unauthenticated access.
