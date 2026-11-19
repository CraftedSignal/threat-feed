---
brief_id: brief-2026-11-19-hitachi-energy-libexpat
event_id: brief-2026-11-19-hitachi-energy-libexpat
revision: 1
activity_at: "2026-11-19T01:27:06Z"
title: Hitachi Energy AFS, AFR, and AFF Product Vulnerabilities in libexpat
slug: 2026-11-hitachi-energy-libexpat
description: Hitachi Energy AFS, AFR, and AFF product families incorporate versions of the libexpat library containing use-after-free vulnerabilities that may lead to information disclosure or denial-of-service conditions.
date: "2026-11-19T01:27:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:libexpat_project:libexpat:*:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:vmware_vsphere:*:*
  - cpe:2.3:a:netapp:oncommand_workflow_automation:-:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:solidfire_\&_hci_management_node:-:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:36:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:37:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h300s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h410c_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h410s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h500s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h700s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:hci_compute_node_firmware:-:*:*:*:*:*:*:*
vendors:
  - Hitachi Energy
products:
  - AFF660/665
  - AFR67x
  - AFS65x
  - AFS660/665C
  - AFS660/665S
  - AFS670/675
  - AFS670v2
cves:
  - id: CVE-2022-40674
    cvss: 8.1
    epss: 0.02401
    kev_status: "false"
  - id: CVE-2022-43680
    cvss: 7.5
    epss: 0.03203
    kev_status: "false"
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-23-143-01
  - https://cveawg.mitre.org/api/cve/CVE-2022-40674
  - https://cveawg.mitre.org/api/cve/CVE-2022-43680
---

## Overview
Hitachi Energy's AFS65x, AFS67x, AFR67x, and AFF66x product families utilize the libexpat library. Two vulnerabilities, CVE-2022-40674 and CVE-2022-43680, affect these products due to their use of vulnerable libexpat versions.

## Attack Chain
- CVE-2022-40674: A use-after-free vulnerability exists in the doContent function in xmlparse.c in libexpat before 2.4.9.
- CVE-2022-43680: A use-after-free vulnerability exists in XML_ExternalEntityParserCreate in libexpat through 2.4.9, caused by the overeager destruction of a shared DTD in out-of-memory situations.

## Impact
Successful exploitation of these vulnerabilities may allow an attacker to disclose sensitive information, modify or add data, or cause a denial-of-service (DoS) condition.

## Recommendation
Hitachi Energy recommends that users apply general mitigation strategies, including implementing firewall configurations to restrict access to process control networks, maintaining physical security, isolating control systems from the internet, and scanning removable media for malware. Specific product remediation paths include:
- AFS660/665S, AFS660/665C, AFS670v2: Apply general mitigation strategies or update to upcoming 7.1.08 when available.
- AFS670/675 and AFR67x: Apply general mitigation strategies or update to 9.1.08.
- AFS65x: As an EoL product, apply the described general mitigation strategies; no remediation update is expected.
- AFF660/665: Apply general mitigation strategies or update to an upcoming release.
