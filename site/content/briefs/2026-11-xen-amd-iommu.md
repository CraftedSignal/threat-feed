---
brief_id: brief-2026-11-11-xen-amd-iommu
event_id: brief-2026-11-11-xen-amd-iommu
revision: 1
activity_at: "2026-11-11T00:38:46Z"
title: 'AMD IOMMU: Out-of-bounds device table read (CVE-2024-21963)'
slug: 2026-11-xen-amd-iommu
description: AMD has disclosed a vulnerability in certain IOMMUs where the hardware performs out-of-bounds reads from the Device Table beyond the size chosen by the OS or Hypervisor.
date: "2026-11-11T00:38:46Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: unknown
vendors:
  - AMD
products:
  - IOMMU
cves:
  - id: CVE-2024-21963
    kev_status: unknown
references:
  - https://xenbits.xen.org/xsa/advisory-524.html
  - https://seclists.org/oss-sec/2026/q4/639
---

AMD has disclosed a vulnerability (CVE-2024-21963 / XSA-524) in some IOMMUs. Under specific circumstances, the hardware reads beyond the size chosen by the OS or Hypervisor for the Device Table, which holds the configuration information for devices.
