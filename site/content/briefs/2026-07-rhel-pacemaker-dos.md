---
title: Red Hat Enterprise Linux (pacemaker) Vulnerability Enables Denial of Service
slug: 2026-07-rhel-pacemaker-dos
description: A vulnerability in Red Hat Enterprise Linux (pacemaker) allows a remote, unauthenticated attacker to perform a Denial of Service attack, potentially disrupting the availability of affected systems.
date: "2026-07-15T10:17:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - linux
  - red-hat
vendors:
  - Red Hat
products:
  - Red Hat Enterprise Linux (pacemaker)
affected_os:
  - Red Hat Enterprise Linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in Red Hat Enterprise Linux ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2345
---

A critical vulnerability, identified as WID-SEC-2026-2345, exists within Red Hat Enterprise Linux, specifically affecting the `pacemaker` component. This flaw permits a remote, unauthenticated attacker to conduct a Denial of Service (DoS) attack. Published by CERT-Bund on July 15, 2026, this vulnerability could lead to the complete disruption of services and applications running on vulnerable systems. The unauthenticated and remote nature of the exploit makes it a high-risk concern, as it allows attackers to impact system availability without prior access or credentials. Organizations leveraging Red Hat Enterprise Linux with the `pacemaker` component are advised to address this vulnerability promptly to prevent severe operational downtime.

## Impact

Successful exploitation of this vulnerability would lead to a Denial of Service for Red Hat Enterprise Linux systems utilizing the `pacemaker` component. This means that essential services and applications hosted on these systems would become inaccessible, resulting in operational disruptions, potential data loss for ongoing processes, and significant financial repercussions for organizations dependent on these systems. Given the unauthenticated and remote attack vector, a wide array of Red Hat deployments are susceptible if left unpatched, allowing attackers to cause widespread unavailability.

## Recommendation

* Apply all available security updates for Red Hat Enterprise Linux, especially those pertaining to the `pacemaker` component, as soon as possible to mitigate WID-SEC-2026-2345.
* Monitor system logs, specifically for the Red Hat Enterprise Linux operating system, for any unusual activity or service disruptions that might indicate attempted or successful exploitation of this vulnerability.
