---
brief_id: brief-2026-11-19-danfoss-ak-sm-vulnerabilities
event_id: brief-2026-11-19-danfoss-ak-sm-vulnerabilities
revision: 2
activity_at: "2026-11-25T23:01:46Z"
revision_history:
  - revision: 2
    at: "2026-11-25T23:01:46Z"
    checksum: sha256:86547769467ac24b5cc9bb27152287b180684b394fcadfbdb8ccb9e43a988107
    summary: exploited:true; KEV CVE-2025-41450
    changed_fields:
      - affected_products
      - cpes
      - cve_verification
      - cves
      - exploitation_evidence
      - lastmod
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2025-41450
title: Multiple Vulnerabilities in Danfoss AK-SM 8xxA Series
slug: 2026-11-danfoss-ak-sm-vulnerabilities
description: Danfoss AK-SM 8xxA Series controllers are impacted by authentication, command injection, and denial of service vulnerabilities, with patches available to address these issues.
date: "2026-11-19T01:24:48Z"
lastmod: "2026-11-25T23:00:36Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-11-19T01:24:48Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:danfoss:ak_sm_8xxa_series:*:*:*:*:*:*:*:*
  - cpe:2.3:o:danfoss:ak-sm_800a_firmware:*:*:*:*:*:*:*:*
vendors:
  - Danfoss
products:
  - AK-SM 800A Series
  - AK-SM 8xxA Series
product_versions:
  - product: AK-SM 8xxA Series
    range: < 4.2
cve_verification:
  CVE-2025-41450:
    status: verified
    source: nvd
    checked_at: 2026-11-25T23:00:33.20175975Z
  CVE-2025-41451:
    status: verified
    source: nvd
    checked_at: 2026-11-25T23:00:34.947017607Z
  CVE-2025-41452:
    status: verified
    source: nvd
    checked_at: 2026-11-25T23:00:36.257821542Z
cves:
  - id: CVE-2025-41450
    cvss: 8.2
    epss: 0.00513
    kev: true
    kev_status: "true"
  - id: CVE-2025-41451
    epss: 0.01521
    kev_status: "false"
  - id: CVE-2025-41452
    epss: 0.00528
    kev_status: "false"
references:
  - https://cveawg.mitre.org/api/cve/CVE-2025-41450
  - https://cveawg.mitre.org/api/cve/CVE-2025-41451
  - https://cveawg.mitre.org/api/cve/CVE-2025-41452
  - https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03
  - https://www.cve.org/CVERecord?id=CVE-2025-41450
updates:
  - at: "2026-11-25T23:00:36Z"
    level: L3
    summary: exploited:true; KEV CVE-2025-41450
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2025-41450
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
