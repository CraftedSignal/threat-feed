---
brief_id: brief-2026-11-11-xen-transient-scheduler-attacks
event_id: brief-2026-11-11-xen-transient-scheduler-attacks
revision: 1
activity_at: "2026-11-11T03:38:42Z"
title: 'Xen Project and AMD: Transient Scheduler Attacks (CVE-2024-36350, CVE-2024-36357, CVE-2026-0004)'
slug: 2026-11-xen-transient-scheduler-attacks
description: The Xen Project has updated security advisory XSA-525 to address Transient Scheduler Attacks (TSA) on AMD Zen 5 processors and disclose a new TSA-Fill variant affecting x86 architectures.
date: "2026-11-11T03:38:42Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Advisory status confirmed; environment-specific mitigation validation required.
cpes:
  - cpe:2.3:a:xen:xen:*:*:*:*:*:*:*:*
  - cpe:2.3:h:amd:zen_3:*:*:*:*:*:*:*:*
  - cpe:2.3:h:amd:zen_4:*:*:*:*:*:*:*:*
  - cpe:2.3:h:amd:zen_5:*:*:*:*:*:*:*:*
vendors:
  - AMD
  - Xen Project
products:
  - Zen 3 CPUs
  - Zen 4 CPUs
  - Zen 5 CPUs
  - Xen Hypervisor
cves:
  - id: CVE-2024-36350
    cvss: 5.6
    epss: 0.00494
    kev_status: "false"
  - id: CVE-2024-36357
    cvss: 5.6
    epss: 0.00357
    kev_status: "false"
  - id: CVE-2026-0004
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/651
  - https://xenbits.xen.org/xsa/advisory-471.html
  - https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7073.html
  - https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3055.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Identify all Xen host systems utilizing AMD Zen 3, 4, or 5 CPUs.
      owner: IT Operations
      due: 48h
      evidence: Source notes vulnerabilities affect specific AMD Zen CPU architectures.
  mitigation_plan:
    - priority: immediate
      action: Apply relevant microcode updates from hardware vendors identified in AMD-SB-7073 and AMD-SB-3055.
      owner: IT Operations
      addresses: CVE-2024-36350, CVE-2024-36357, CVE-2026-0004
      evidence: AMD security bulletins for TSA mitigations.
---

The Xen Project, in coordination with AMD, has updated XSA-525 to provide information on Transient Scheduler Attacks (TSA). Previous assessments regarding Zen 5 CPUs have been corrected, confirming vulnerability to TSA-SQ and TSA-L1 variants (tracked under CVE-2024-36350 and CVE-2024-36357). Additionally, a new variant designated as TSA-Fill has been disclosed, tracked as CVE-2026-0004. These transient execution vulnerabilities may allow unauthorized information disclosure.

## Impact

Transient Scheduler Attacks leverage transient execution to potentially leak sensitive information across privilege boundaries within the hypervisor or between virtual machines.

## Recommendation

- Inventory infrastructure running Xen Hypervisor on AMD Zen 3, Zen 4, and Zen 5 processor architectures.
- Review AMD Security Bulletin AMD-SB-7073 and AMD-SB-3055 for microcode and mitigation requirements.
- Apply updated microcode and hypervisor patches provided by your server hardware vendor and the Xen Project as they become available to address these TSA variants.
