---
title: Denial of Service in gnome-remote-desktop via Connection Throttling Bypass
slug: 2026-07-gnome-remote-desktop-dos
description: A vulnerability in gnome-remote-desktop allows an unauthenticated remote attacker to exhaust system resources by bypassing connection throttling when RDP is enabled in system mode on Red Hat Enterprise Linux.
date: "2026-07-31T13:38:31Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - denial-of-service
  - linux
  - rdp
  - cve-2026-18358
vendors:
  - Red Hat
products:
  - Red Hat Enterprise Linux
affected_os:
  - RHEL
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This can accumulate accepted sockets and pending routing-token operations until timeout, exhausting resources and preventing legitimate users from establishing RDP sessions.
    confidence_band: high
cves:
  - id: CVE-2026-18358
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18358
---

A vulnerability identified as CVE-2026-18358 exists within the gnome-remote-desktop daemon as implemented in Red Hat Enterprise Linux (RHEL). The flaw specifically impacts systems where the daemon is configured to run in system mode with RDP services enabled. The vulnerability stems from the incoming connection handler failing to enforce proper connection throttling. An unauthenticated attacker can exploit this oversight to initiate a large volume of parallel, pre-authentication RDP connections. By flooding the listener with these connection attempts, the attacker causes the system to accumulate numerous accepted sockets and pending routing-token operations. This sustained resource consumption results in a Denial of Service (DoS) state, preventing authorized users from establishing new RDP sessions. Notably, this flaw is limited to the Red Hat packaging of the software and does not affect upstream versions of gnome-remote-desktop.

## Impact

The vulnerability poses a significant risk to RHEL environments that rely on gnome-remote-desktop for remote administration or user access. Successful exploitation leads to a complete denial of service for RDP functionality on the affected host. Given that this requires no authentication, remote attackers with network access to the RDP port can persistently interrupt service availability, causing operational disruption for organizations relying on these remote access pathways.

## Recommendation

1. Audit current RHEL deployments to identify hosts running gnome-remote-desktop in system mode with RDP enabled.
2. Prioritize the application of Red Hat security patches addressing CVE-2026-18358 as they become available.
3. Implement network-level access control lists (ACLs) or firewall rules to restrict access to the RDP port (default TCP 3389) to known, trusted management segments until the vulnerability is patched.
4. Monitor system logs for anomalous spikes in incoming connection attempts to the gnome-remote-desktop process to identify active exploitation attempts.
