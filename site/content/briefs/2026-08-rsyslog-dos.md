---
title: Denial of Service Vulnerability in rsyslogd imptcp Module
slug: 2026-08-rsyslog-dos
description: An unauthenticated remote attacker can cause a denial-of-service condition in rsyslogd by sending a crafted input sequence that triggers an out-of-bounds read within the optional imptcp module.
date: "2026-08-12T22:53:04Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - linux
vendors:
  - Red Hat
products:
  - rsyslog
affected_os:
  - Red Hat Enterprise Linux 6
  - Red Hat Enterprise Linux 7
  - Red Hat Enterprise Linux 8
  - Red Hat Enterprise Linux 9
  - Red Hat Enterprise Linux 10
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A unauthenticated remote peer may lead rsyslogd to crash due to a flaw in the optional imptcp module.
    confidence_band: high
cves:
  - id: CVE-2026-19654
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19654
  - https://access.redhat.com/security/cve/CVE-2026-19654
  - https://github.com/rsyslog/rsyslog/security/advisories/GHSA-cj5r-wh2m-7w29
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory and patch rsyslogd across all RHEL environments
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-19654 vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Disable optional imptcp module if not required for logging operations
      owner: IT Operations
      addresses: CVE-2026-19654
      evidence: Source states flaw is specific to the optional imptcp module
---

A vulnerability (CVE-2026-19654) has been identified in the optional imptcp module of rsyslogd. An unauthenticated remote attacker can exploit this flaw by sending a specifically crafted input sequence during the oversize-frame recovery process. This manipulation results in an invalid internal message length calculation, which subsequently triggers an out-of-bounds read and causes the rsyslogd service to crash (Denial of Service). The vulnerability is confined to the imptcp module; standard imtcp configurations and default framing modes within imptcp remain unaffected. This issue impacts multiple versions of Red Hat Enterprise Linux and is documented under CWE-125. Defenders should note that this vulnerability does not allow for privilege escalation, code execution, or unauthorized information disclosure, but it poses a significant availability risk for centralized logging infrastructure.

## Impact

The vulnerability results in the disruption of logging services by causing the rsyslogd daemon to terminate unexpectedly. If successfully exploited, this forces a denial-of-service condition on systems relying on rsyslogd for log aggregation and transmission. The scope of impact is high given the critical role rsyslog plays in security monitoring, incident response, and compliance logging across enterprise environments using RHEL distributions.

## Recommendation

- Identify all systems running rsyslogd with the optional imptcp module enabled.
- Review configurations to determine if imptcp is necessary; if not, disable the module to mitigate the risk.
- Patch rsyslog packages on affected Red Hat Enterprise Linux 6, 7, 8, 9, and 10 systems immediately upon vendor release of security updates.
- Monitor system logs or infrastructure monitoring tools for unexpected rsyslogd process restarts or termination events.
