---
brief_id: brief-2026-09-18-cisa-kev-update
event_id: brief-2026-09-18-cisa-kev-update
revision: 2
activity_at: "2026-11-19T18:13:06Z"
revision_history:
  - revision: 2
    at: "2026-11-19T18:13:06Z"
    checksum: sha256:5ed095679d95179517e011619fd5ed3e68654934430abd5a29d6b8be718a4ba4
    summary: exploited:true; KEV CVE-2025-39964; KEV CVE-2026-53266
    changed_fields:
      - affected_products
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: CISA Adds Two Exploited Linux Kernel Vulnerabilities to KEV Catalog
slug: 2026-09-cisa-kev-update
description: CISA has added CVE-2025-39964 and CVE-2026-53266, two actively exploited Linux kernel vulnerabilities, to its Known Exploited Vulnerabilities catalog.
date: "2026-09-18T18:33:02Z"
lastmod: "2026-11-19T18:12:21Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-09-18T00:00:00Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Verified against CISA KEV catalog source.
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:6.17:rc1:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:6.17:rc2:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:6.17:rc3:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:6.17:rc4:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:6.17:rc5:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:6.17:rc6:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:rc1:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:rc2:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:rc3:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:rc4:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:rc5:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:rc6:*:*:*:*:*:*
tags:
  - vulnerability-management
  - linux
  - kernel
  - cisa-kev
vendors:
  - Linux
products:
  - Kernel
  - Linux Kernel
cves:
  - id: CVE-2025-39964
    cvss: 7.8
    epss: 0.00323
    kev: true
    kev_status: "true"
  - id: CVE-2026-53266
    cvss: 8.8
    epss: 0.00121
    kev: true
    kev_status: "true"
references:
  - https://www.cisa.gov/news-events/alerts/2026/09/18/cisa-adds-two-known-exploited-vulnerabilities-catalog
  - https://www.cve.org/CVERecord?id=CVE-2025-39964
  - https://www.cve.org/CVERecord?id=CVE-2026-53266
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Vulnerability Management
  immediate_actions:
    - action: Patch all Linux systems to the latest kernel version available from the distribution provider to remediate CVE-2025-39964 and CVE-2026-53266.
      owner: IT Operations
      due: 24h
      evidence: CISA BOD 26-04 requirements and KEV listing.
  mitigation_plan:
    - priority: immediate
      action: Apply kernel security updates provided by the distribution vendor.
      owner: IT Operations
      addresses: CVE-2025-39964 and CVE-2026-53266
      evidence: CISA KEV catalog guidance.
updates:
  - at: "2026-09-18T19:03:43Z"
    level: L1
    summary: new product
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2025-39964
  - at: "2026-11-19T18:12:21Z"
    level: L3
    summary: exploited:true; KEV CVE-2025-39964; KEV CVE-2026-53266
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

On September 18, 2026, CISA updated its Known Exploited Vulnerabilities (KEV) Catalog to include two Linux kernel vulnerabilities that are currently being leveraged in active exploitation campaigns. The vulnerabilities include CVE-2025-39964, a race condition vulnerability, and CVE-2026-53266, an out-of-bounds write vulnerability. Both flaws reside within the core Linux kernel, making them high-risk entry points or escalation vectors for attackers seeking to gain unauthorized control over affected systems. Per Binding Operational Directive (BOD) 26-04, Federal Civilian Executive Branch (FCEB) agencies are required to prioritize the remediation of these vulnerabilities on internet-facing assets. CISA strongly recommends that all organizations, regardless of sector, apply the latest security updates provided by their Linux distribution maintainers to mitigate these risks.

## Impact

Successful exploitation of these Linux kernel vulnerabilities can grant attackers total control over the compromised asset. These flaws are high-risk because they enable low-privileged users or unauthenticated attackers to potentially elevate privileges or execute arbitrary code. The inclusion in the KEV Catalog confirms that these vulnerabilities are currently used in the wild, posing a significant risk to any organization running vulnerable Linux kernel versions.

## Recommendation

Prioritize patching for all Linux assets in the environment to the latest kernel versions provided by your vendor. Ensure that your vulnerability management program includes automated monitoring for the presence of CVE-2025-39964 and CVE-2026-53266. Agencies under BOD 26-04 must prioritize remediation on internet-facing assets immediately and perform historical log analysis to determine if compromise occurred prior to patch application.
