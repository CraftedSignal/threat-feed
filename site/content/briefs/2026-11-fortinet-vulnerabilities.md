---
brief_id: brief-2026-11-12-fortinet-vulnerabilities
event_id: brief-2026-11-12-fortinet-vulnerabilities
revision: 1
activity_at: "2026-11-12T16:25:54Z"
title: Fortinet Product Suite Multiple Vulnerabilities
slug: 2026-11-fortinet-vulnerabilities
description: Fortinet has disclosed a large set of vulnerabilities across the FortiOS, FortiManager, FortiAnalyzer, and FortiSandbox ecosystems that allow for arbitrary code execution, privilege escalation, and data compromise.
date: "2026-11-12T16:25:54Z"
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
  likelihood: very likely
tags:
  - vulnerability
  - network-security
  - fortinet
  - patch-management
vendors:
  - Fortinet
products:
  - FortiAnalyzer Cloud (7.2.x < 7.2.13, 7.4.x < 7.4.12, 7.6.x < 7.6.8, 8.0.x < 8.0.3)
  - FortiAnalyzer (7.2.x < 7.2.13, 7.4.x < 7.4.12, 7.6.x < 7.6.8, 8.0.x < 8.0.2)
  - FortiManager Cloud (7.2.x < 7.2.13, 7.4.x < 7.4.12, 7.6.x < 7.6.8, 8.0.x < 8.0.2)
  - FortiManager (7.2.x < 7.2.13, 7.4.x < 7.4.12, 7.6.x < 7.6.8, 8.0.x < 8.0.2)
  - FortiOS (7.2.x < 7.2.14, 7.4.x < 7.4.13, 7.6.x < 7.6.8, 8.0.x < 8.0.2)
  - FortiPAM (1.x)
  - FortiSandbox Cloud (5.0.4 < 5.0.6)
  - FortiSandbox PaaS (5.0.4 < 5.0.6)
  - FortiSandbox (4.4.x < 4.4.9, 5.0.x < 5.0.6)
  - FortiSASE (all versions)
cves:
  - id: CVE-2025-61625
    cvss: 8.1
    epss: 0.0072
    kev_status: "false"
  - id: CVE-2026-121528
    cvss: 8.1
    kev_status: "false"
  - id: CVE-2026-121530
    cvss: 6.6
    epss: 0.00686
    kev_status: "false"
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1499/
  - https://fortiguard.fortinet.com/psirt/FG-IR-26-142
  - https://www.cve.org/CVERecord?id=CVE-2025-61625
  - https://www.cve.org/CVERecord?id=CVE-2026-121528
  - https://www.cve.org/CVERecord?id=CVE-2026-121530
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Inventory and patch all affected Fortinet appliances to the versions specified in the relevant FG-IR bulletins.
      owner: IT Operations
      addresses: Multiple CVEs affecting FortiAnalyzer, FortiManager, and FortiOS
      evidence: Source lists specific version ranges to be upgraded to remediate identified vulnerabilities.
---

On November 10, 2026, Fortinet released a series of security bulletins (FG-IR-26-142 through FG-IR-26-276) addressing a broad collection of vulnerabilities affecting multiple products. These vulnerabilities, which include CVE-2025-61625, CVE-2026-121528, and CVE-2026-121530, pose significant risks including arbitrary code execution, privilege escalation, cross-site scripting (XSS), SQL injection, server-side request forgery (SSRF), and denial-of-service conditions.

## Impact

The disclosed vulnerabilities impact the integrity and confidentiality of data within affected Fortinet systems. Attackers may achieve remote code execution or escalate privileges, potentially leading to a full system compromise. The scope covers major enterprise infrastructure components, including firewalls (FortiOS), centralized management platforms (FortiManager), logging solutions (FortiAnalyzer), and sandbox analysis environments.

## Recommendation

- Audit all internal and cloud-hosted Fortinet infrastructure against the identified vulnerable versions.
- Upgrade FortiAnalyzer, FortiManager, and FortiOS to the minimum patched versions listed in the vendor advisories immediately.
- Apply available patches for FortiSandbox and FortiPAM as detailed in the respective FG-IR bulletins.
- Review the comprehensive list of Fortinet PSIRT bulletins at https://fortiguard.fortinet.com/psirt/ to ensure specific product-version alignment.
