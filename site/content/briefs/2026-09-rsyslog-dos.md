---
title: Denial of Service Vulnerability in rsyslog
slug: 2026-09-rsyslog-dos
description: A vulnerability in rsyslog allows a remote, unauthenticated attacker to cause a denial-of-service condition through improper handling of network inputs.
date: "2026-09-21T13:51:35Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:o:netgear:r8500_firmware:1.0.2.160:*:*:*:*:*:*:*
  - cpe:2.3:o:netgear:xr300_firmware:1.0.3.78:*:*:*:*:*:*:*
  - cpe:2.3:o:netgear:r7000p_firmware:1.3.3.154:*:*:*:*:*:*:*
  - cpe:2.3:o:netgear:r6400v2_firmware:1.0.4.128:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - linux
vendors:
  - Rsyslog
products:
  - rsyslog
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An unauthenticated attacker can exploit a vulnerability in rsyslog to perform a denial of service attack.
    confidence_band: high
cves:
  - id: CVE-2024-52013
    cvss: 5.7
    epss: 0.00305
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3473
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-52013
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  hunt_leads:
    - lead: Search for unexpected rsyslog daemon crashes or service restart events in system logs
      technique_id: T1498
      data_needed:
        - System log files (e.g., /var/log/syslog, journald)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Service availability is the target of the vulnerability
  mitigation_plan:
    - priority: immediate
      action: Update rsyslog to the latest patched version addressing CVE-2024-52013
      owner: IT Operations
      addresses: CVE-2024-52013
      evidence: CVE-2024-52013 provided in the vulnerability advisory
---

The BSI has reported a vulnerability in rsyslog, a widely used logging system for Linux environments. The flaw allows a remote, unauthenticated attacker to trigger a denial of service (DoS) condition on affected systems. This issue, tracked as CVE-2024-52013, stems from improper validation and handling of specific network-based inputs processed by the rsyslog daemon. By sending malformed or specially crafted network requests to the rsyslog service, an attacker can crash the logging process, preventing the collection of system logs and potentially impacting downstream security monitoring or operational audit requirements. Defenders should prioritize updating to the latest stable release to mitigate the risk of service disruption.

## Impact

Successful exploitation results in the immediate termination of the rsyslog process. In enterprise environments, this impacts centralized log aggregation, security information and event management (SIEM) data ingestion, and the visibility of system events necessary for incident response and compliance monitoring. Organizations relying on rsyslog for infrastructure-wide logging are vulnerable to monitoring blindness if the service is successfully exploited.

## Recommendation

* Monitor system logs and process management logs for unexpected termination of the rsyslog process.
* Ensure rsyslog is updated to the latest vendor-supplied version that includes the fix for CVE-2024-52013.
* Restrict network access to rsyslog listeners to trusted management subnets using host-based firewalls (iptables/nftables).
