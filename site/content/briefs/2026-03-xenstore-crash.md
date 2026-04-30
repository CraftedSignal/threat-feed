---
title: Xenstore Crash Vulnerability via Malicious Node Path Access (CVE-2026-23555)
slug: 2026-03-xenstore-crash
description: A guest VM issuing a Xenstore command with the node path '/local/domain/' can crash xenstored (CVE-2026-23555), or, if NDEBUG is defined, cause denial of service by consuming all CPU resources.
date: "2026-03-23T07:16:07Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - xen
  - xenstore
  - denial-of-service
  - CVE-2026-23555
  - hypervisor
  - vulnerability
  - linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-23555
rules:
  - title: Detect Xenstore Access to Illegal Node Path
    description: Detects attempts to access the /local/domain/ node path in Xenstore commands, potentially indicating an exploitation attempt of CVE-2026-23555.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect High CPU Usage by Xenstored
    description: Detects high CPU usage by the xenstored process, which could indicate a denial-of-service condition related to CVE-2026-23555 when NDEBUG is defined.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-23555 details a vulnerability within the Xenstore component of the Xen hypervisor. A malicious or compromised guest virtual machine (VM) can trigger this vulnerability by issuing a Xenstore command that attempts to access a specific, illegal node path: `/local/domain/`. This improper node path verification leads to a clobbered error indicator within the xenstored process, ultimately causing it to crash due to a failing assert() statement.
