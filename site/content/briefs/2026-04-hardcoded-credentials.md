---
title: Hardcoded Storage Credentials in Mobile App and Device Firmware (CVE-2025-10681)
slug: 2026-04-hardcoded-credentials
description: CVE-2025-10681 describes a vulnerability where hardcoded storage credentials in a mobile app and device firmware, with inadequate permission limits and lack of expiration, could lead to unauthorized access to production storage containers.
date: "2026-04-03T21:17:08Z"
severities:
  - high
tags:
  - cve-2025-10681
  - hardcoded-credentials
  - ics-cert
  - ot
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-10681
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-10681
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-055-03.json
  - https://mygardyn.com/security/
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-055-03
rules:
  - title: Detect Hardcoded Credentials in Mobile App/Firmware Unpacking
    description: Detects attempts to unpack or analyze mobile application binaries or device firmware images, which may be a precursor to extracting hardcoded credentials.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1001
    data_sources:
      - process_creation
      - windows
  - title: Detect Unusual Authentication to Storage Resources
    description: Detects authentication attempts to storage resources using unusual user agents or originating from unusual IP addresses, potentially indicating compromised credentials.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1078
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2025-10681 exposes a critical vulnerability stemming from the presence of hardcoded storage credentials within a mobile application and its corresponding device firmware. These credentials, unfortunately, lack sufficient restrictions on end-user permissions and are not configured to expire after a reasonable period. The affected systems are not explicitly mentioned, but the advisory was published by ICS-CERT implying the vulnerability exists within an Industrial Control System or similar…
