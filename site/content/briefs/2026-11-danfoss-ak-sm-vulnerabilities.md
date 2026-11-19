---
brief_id: brief-2026-11-19-danfoss-ak-sm-vulnerabilities
event_id: brief-2026-11-19-danfoss-ak-sm-vulnerabilities
revision: 1
activity_at: "2026-11-19T01:24:48Z"
title: Multiple Vulnerabilities in Danfoss AK-SM 8xxA Series
slug: 2026-11-danfoss-ak-sm-vulnerabilities
description: Danfoss AK-SM 8xxA Series controllers are impacted by authentication, command injection, and denial of service vulnerabilities, with patches available to address these issues.
date: "2026-11-19T01:24:48Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:danfoss:ak_sm_8xxa_series:*:*:*:*:*:*:*:*
vendors:
  - Danfoss
products:
  - AK-SM 8xxA Series
product_versions:
  - product: AK-SM 8xxA Series
    range: < 4.2
cves:
  - id: CVE-2025-41450
    cvss: 8.2
    epss: 0.00965
    kev_status: "false"
  - id: CVE-2025-41451
    epss: 0.04462
    kev_status: "false"
  - id: CVE-2025-41452
    epss: 0.0093
    kev_status: "false"
references:
  - https://cveawg.mitre.org/api/cve/CVE-2025-41450
  - https://cveawg.mitre.org/api/cve/CVE-2025-41451
  - https://cveawg.mitre.org/api/cve/CVE-2025-41452
  - https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03
---

## Overview
Multiple vulnerabilities have been identified in the Danfoss AK-SM 8xxA Series:

- CVE-2025-41450: An improper authentication vulnerability in the Danfoss AK-SM 8xxA Series. This issue affects versions prior to 4.2.
- CVE-2025-41451: Improper neutralization of alarm-to-mail configuration fields used in an OS shell command injection in Danfoss AK-SM 8xxA Series prior to version 4.3.1, leading to potential post-authenticated remote code execution.
- CVE-2025-41452: A post-authenticated external control of system web interface configuration setting vulnerability exists in the Danfoss AK-SM 8xxA Series prior to version 4.3.1, which could allow for a denial of service attack.

## Attack Chain
These vulnerabilities are reachable via the network. CVE-2025-41451 and CVE-2025-41452 require high attack complexity, active user interaction, and prior authentication.

## Impact
Successful exploitation could enable a remote attacker to bypass authentication, remotely execute arbitrary code, or trigger a denial of service condition.

## Recommendation
- Upgrade to version 4.2 to address CVE-2025-41450.
- Upgrade to version 4.3.1 to address CVE-2025-41451 and CVE-2025-41452 using the AK-SM 800A Software Upgrade Process.
- Minimize network exposure by ensuring devices are not accessible from the internet, using firewalls, and utilizing secure remote access methods such as VPNs.
