---
brief_id: brief-2026-11-12-hpe-p5g-vulnerabilities
event_id: brief-2026-11-12-hpe-p5g-vulnerabilities
revision: 1
activity_at: "2026-11-12T23:01:51Z"
title: 'HPE Networking Private 5G Core: Multiple vulnerabilities'
slug: 2026-11-hpe-p5g-vulnerabilities
description: HPE has disclosed multiple vulnerabilities affecting HPE Networking Private 5G Core versions 1.26.1.4 and earlier, necessitating review of security updates provided in bulletin HPESBNW05179.
date: "2026-11-12T23:01:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Content verified against the provided Cyber Centre advisory and vendor documentation.
vendors:
  - HPE
products:
  - HPE Networking Private 5G Core
product_versions:
  - product: HPE Networking Private 5G Core
    range: <= 1.26.1.4
references:
  - https://cyber.gc.ca/en/alerts-advisories/hpe-security-advisory-av26-1144
  - https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw05179en_us&docLocale=en_US#hpesbnw05179-rev-1-multiple-vulnerabilities-in-hpe-0
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit network environment for HPE Networking Private 5G Core deployments.
      owner: IT Operations
      due: 48h
      evidence: HPE security advisory (AV26-1144) identifies affected product scope.
  mitigation_plan:
    - priority: immediate
      action: Review and apply patches detailed in HPESBNW05179 rev.1.
      owner: IT Operations
      addresses: HPE Networking Private 5G Core (<= 1.26.1.4)
      evidence: Vendor bulletin HPESBNW05179 rev.1 provides remediation steps.
---

On November 10, 2026, Hewlett Packard Enterprise (HPE) identified multiple vulnerabilities impacting the HPE Networking Private 5G Core (P5G Core) software. The affected versions are 1.26.1.4 and earlier. HPE has released security bulletin HPESBNW05179 rev.1 to address these findings. As of the report date, specific CVE identifiers were not disclosed in the Cyber Centre advisory, and the technical details of the vulnerability classes remain limited to the vendor bulletin.

## Recommendation

- Inventory all instances of HPE Networking Private 5G Core to identify versions at or below 1.26.1.4.
- Review HPE security bulletin HPESBNW05179 rev.1 immediately for technical details and available patch versions.
- Apply the necessary security updates as recommended by HPE to mitigate the identified risks.
