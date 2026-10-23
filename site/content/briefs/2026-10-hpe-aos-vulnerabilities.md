---
brief_id: brief-2026-10-23-hpe-aos-vulnerabilities
event_id: brief-2026-10-23-hpe-aos-vulnerabilities
revision: 1
activity_at: "2026-10-23T15:00:46Z"
title: HPE Networking Wireless Operating System Multiple Vulnerabilities
slug: 2026-10-hpe-aos-vulnerabilities
description: HPE has addressed multiple vulnerabilities affecting various versions of its Networking Wireless Operating Systems (AOS-10 and AOS-8) that require firmware updates.
date: "2026-10-23T15:00:46Z"
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
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - vulnerability
  - networking
  - patch-management
  - informational
vendors:
  - HPE
products:
  - HPE Networking Wireless Operating Systems (AOS-10 < 10.8.1.2, 10.7.2.7, 10.4.1.14; AOS-8 < 8.13.3.1, 8.10.0.24)
references:
  - https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw05162en_us&docLocale=en_US
  - https://support.hpe.com/connect/s/securitybulletinlibrary?language=en_US
  - https://cyber.gc.ca/en/alerts-advisories/hpe-security-advisory-av26-1079
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade HPE Networking Wireless Operating Systems to versions 10.8.1.2, 10.7.2.7, 10.4.1.14, 8.13.3.1, 8.10.0.24 or later.
      owner: IT Operations
      addresses: HPE Networking Wireless Operating System vulnerabilities
      evidence: HPE security advisory HPESBNW05162
---

HPE has released a security advisory (HPESBNW05162) addressing multiple vulnerabilities affecting HPE Networking Wireless Operating Systems, specifically AOS-10 and AOS-8 releases. The vulnerabilities affect versions prior to 10.8.1.2, 10.7.2.7, 10.4.1.14, 8.13.3.1, and 8.10.0.24. Administrators should consult the linked security bulletin for specific remediation paths and patch availability.

## Recommendation

- Identify all instances of HPE Networking Wireless Operating Systems (AOS-10 and AOS-8) within the network environment.
- Upgrade firmware to the following versions or later: 10.8.1.2, 10.7.2.7, 10.4.1.14, 8.13.3.1, or 8.10.0.24.
- Monitor the HPE Security Bulletin Library for any additional disclosures or updates related to these advisory revisions.
