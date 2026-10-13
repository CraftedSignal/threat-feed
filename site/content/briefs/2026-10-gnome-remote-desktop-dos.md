---
title: Denial of Service in gnome-remote-desktop via VNC TLS I/O Loop
slug: 2026-10-gnome-remote-desktop-dos
description: A vulnerability in gnome-remote-desktop on Red Hat Enterprise Linux allows a remote attacker to trigger an infinite loop in VNC TLS I/O handlers, leading to high CPU consumption and service denial.
date: "2026-10-13T12:35:21Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:gnome:gnome-remote-desktop:*:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:*:*:*:*:*:*:*:*
vendors:
  - Red Hat
  - GNOME
products:
  - Red Hat Enterprise Linux
  - gnome-remote-desktop
affected_os:
  - RHEL
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote attacker who can reach an enabled VNC TLS listener can cause the event-loop thread to spin at high CPU with no forward progress, resulting in denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-109832
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109832
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify and inventory systems running gnome-remote-desktop with VNC listeners active
      owner: IT Operations
      due: 48h
      evidence: Service vulnerability identified in gnome-remote-desktop package
  mitigation_plan:
    - priority: immediate
      action: Restrict access to VNC TLS ports (default 5900+) to authorized source IPs
      owner: IT Operations
      addresses: CVE-2026-109832
      evidence: Vulnerability requires attacker to reach an enabled VNC TLS listener
---

A vulnerability (CVE-2026-109832) exists in the gnome-remote-desktop package as shipped in Red Hat Enterprise Linux (RHEL). The flaw stems from improper handling of specific GnuTLS return codes (GNUTLS_E_AGAIN and GNUTLS_E_INTERRUPTED) within the VNC TLS I/O handlers. Instead of yielding control back to the event loop, the application enters an unbounded busy loop. A remote attacker capable of connecting to an enabled VNC TLS listener can trigger this condition, causing the event-loop thread to pin at 100% CPU usage. This prevents the application from making forward progress, effectively resulting in a denial-of-service condition for the remote desktop session.

## Impact

The vulnerability results in a denial-of-service, preventing legitimate users from accessing or maintaining remote desktop sessions via the affected gnome-remote-desktop service. Targeted systems running RHEL with remote VNC access enabled are at risk of resource exhaustion on the event-loop thread, potentially impacting system stability depending on the configuration and threading model of the service.

## Recommendation

Prioritized actions for security and IT teams include:
- Monitor system logs for repeated or unexplained high CPU usage originating from the gnome-remote-desktop process.
- Identify all RHEL systems with gnome-remote-desktop enabled and VNC listeners exposed to the network.
- Patch CVE-2026-109832 by applying the security updates provided by Red Hat once available.
- Restrict access to VNC TLS listeners to trusted network segments to mitigate the risk of remote triggering by unauthorized actors.
