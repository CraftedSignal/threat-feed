---
brief_id: brief-2026-10-27-moxa-advisory-f3ecdcaf
event_id: brief-2026-10-27-moxa-advisory-f3ecdcaf
revision: 1
activity_at: "2026-10-27T23:46:20Z"
title: Moxa Remote Connect Suite and OnCell G3150A-LTE Vulnerabilities
slug: 2026-10-moxa-advisory-f3ecdcaf
description: Moxa has released security updates addressing three vulnerabilities in the Remote Connect Suite (MRC Client) and the OnCell G3150A-LTE Series.
date: "2026-10-27T23:46:20Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:moxa:remote_connect_suite:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ot-security
  - patch-management
vendors:
  - Moxa
products:
  - Remote Connect Suite (MRC Client) (<= v4.2.0)
cves:
  - id: CVE-2026-111459
    kev_status: "false"
  - id: CVE-2026-111460
    kev_status: unknown
  - id: CVE-2026-111461
    kev_status: unknown
references:
  - https://cyber.gc.ca/en/alerts-advisories/control-systems-moxa-security-advisory-av26-1089
  - https://www.moxa.com/en/support/product-support/security-advisory/mpsa-269510-cve-2026-111459-cve-2026-111460-cve-2026-111461-vulnerabilities-in-moxa-remote-connect-suite-mrc-client
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory and patch affected Moxa systems upon release of vendor firmware
      owner: IT Operations
      due: 72h
      evidence: Moxa security advisory MPSA-269510
  hunt_leads:
    - lead: Identify unauthorized access attempts to remote management or configuration interfaces on OnCell G3150A-LTE hardware
      data_needed:
        - Firewall logs
        - Device audit logs
      priority: medium
      confidence: medium
      disposition: monitor-only
      evidence: Advisory identifies all firmware versions as vulnerable
  mitigation_plan:
    - priority: immediate
      action: Isolate affected OnCell G3150A-LTE devices from public internet access
      owner: IT Operations
      addresses: OnCell G3150A-LTE Series
      evidence: Vulnerability disclosure for all firmware versions
---

Moxa has issued a security advisory (MPSA-269510) covering vulnerabilities identified as CVE-2026-111459, CVE-2026-111460, and CVE-2026-111461. The issues impact the Moxa Remote Connect Suite (MRC Client) versions up to and including 4.2.0, as well as all firmware versions of the OnCell G3150A-LTE Series. Technical details regarding the exploit path and vulnerability classes remain undisclosed in the vendor advisory. Administrators should monitor the official Moxa security portal for firmware release availability and apply patches as a priority.

## Recommendation

- Inventory all deployments of Moxa Remote Connect Suite and OnCell G3150A-LTE Series within the operational technology (OT) and information technology (IT) environment.
- Review the official Moxa security advisory MPSA-269510 to verify if specific firmware updates or mitigations are currently available for the affected versions.
- Restrict network access to the management interfaces of OnCell G3150A-LTE devices to authorized management subnets only until patches are applied.
