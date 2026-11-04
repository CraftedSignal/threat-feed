---
brief_id: brief-2026-11-04-apt-flaw
event_id: brief-2026-11-04-apt-flaw
revision: 1
activity_at: "2026-11-04T20:11:55Z"
title: 'APT Package Manager: Man-in-the-Middle Arbitrary Code Execution (CVE-2026-109518)'
slug: 2026-11-apt-flaw
description: A critical vulnerability in the APT package manager allows man-in-the-middle attackers to perform package substitution and achieve root-level code execution by exploiting download retry logic.
date: "2026-11-04T20:11:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - vulnerability
  - supply-chain
  - linux
vendors:
  - Debian
  - Canonical
products:
  - APT (Advanced Package Tool)
affected_os:
  - Debian 11
  - Debian 12
  - Ubuntu 14.04
  - Ubuntu 20.04
  - Ubuntu 22.04
  - Ubuntu 24.04
  - Ubuntu 26.04
  - Ubuntu 26.10
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: Compromise Software Supply Chain
    evidence: A flaw in APT, the package manager for Debian and Ubuntu, allows an attacker who can modify package downloads to swap a checked package for their own.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The attacker's code then runs as root, according to advisories that Debian, Ubuntu, and APT's developers published on November 4.
    confidence_band: high
cves:
  - id: CVE-2026-109518
    kev_status: "false"
references:
  - https://thehackernews.com/2026/11/debian-and-ubuntu-apt-flaw-lets-mitm.html
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch APT on all Linux endpoints to the vendor-provided fixed versions.
      owner: IT Operations
      due: 24h
      evidence: Debian has released fixed versions of APT for the flaw, CVE-2026-109518.
  hunt_leads:
    - lead: Identify systems with non-standard package mirror configurations or high volumes of package retry activity.
      technique_id: T1195.002
      data_needed:
        - APT configuration files
        - System logs showing package manager network errors/retries
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The attack needs APT to retry failed downloads, which it does by default from Debian 12 and Ubuntu 22.04 onward.
  mitigation_plan:
    - priority: immediate
      action: 'Upgrade APT to fixed versions identified in vendor bulletins (e.g., Ubuntu 22.04 LTS: 2.4.15ubuntu0.1).'
      owner: IT Operations
      addresses: CVE-2026-109518
      evidence: Ubuntu published new APT builds for four of its releases to its security archive at 14:25 UTC on November 4.
---

A critical vulnerability (CVE-2026-109518) in the Advanced Package Tool (APT) allows attackers to perform a man-in-the-middle (MitM) attack to swap legitimate packages for malicious ones. The attack is successful when APT attempts to retry a failed download, a process that occurs by default in Debian 12 and Ubuntu 22.04 or later, and potentially on earlier versions where users have explicitly enabled 'Acquire::Retries'. The malicious package executes with root privileges during the installation phase.

## Impact
Successful exploitation allows an unprivileged attacker capable of intercepting or modifying network traffic (e.g., malicious mirror, proxy) to execute arbitrary code as root on the target system during package installation.

## Recommendation
- Update APT to the patched versions provided by the vendor immediately.
- Audit system configuration files for the 'Acquire::Retries' setting in '/etc/apt/apt.conf.d/' or '/etc/apt/apt.conf'.
- Prioritize migration of legacy systems to supported distributions to ensure security patch availability.
