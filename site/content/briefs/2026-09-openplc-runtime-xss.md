---
title: Stored and Reflected XSS Vulnerability in OpenPLC Runtime v3
slug: 2026-09-openplc-runtime-xss
description: OpenPLC Runtime v3 contains a cross-site scripting vulnerability that allows attackers to hijack operator session cookies and issue unauthorized commands to industrial control processes.
date: "2026-09-22T17:46:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - ics
  - cve-2026-88020
  - critical-infrastructure
vendors:
  - Autonomy Logic
products:
  - OpenPLC Runtime v3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The affected product is susceptible to an improper neutralization of input during web page generation vulnerability when the web interface attempts to route the program based on a query string parameter with no encoding.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-09
  - https://www.cve.org/CVERecord?id=CVE-2026-88020
  - https://cwe.mitre.org/data/definitions/79.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all OpenPLC Runtime v3 instances to OpenPLC v4
      owner: IT Operations
      due: 72h
      evidence: 'Vendor fix: Autonomy Logic recommends users upgrade to OpenPLC v4'
  mitigation_plan:
    - priority: immediate
      action: Isolate OpenPLC Runtime v3 web interfaces from the internet
      owner: IT Operations
      addresses: CVE-2026-88020
      evidence: Minimize network exposure for all control system devices
---

OpenPLC Runtime v3, developed by Autonomy Logic, contains a vulnerability identified as CVE-2026-88020. The flaw stems from improper neutralization of input within the product's web interface, specifically when the application routes programs based on unencoded query string parameters. This cross-site scripting (XSS) vulnerability allows an attacker to inject malicious scripts into the web interface. 

If a logged-in operator visits a crafted link or navigates to a compromised page, the attacker can hijack active session cookies. By gaining control of an operator's session, an attacker can issue state-changing requests, potentially manipulating the programmable logic controller (PLC) and disrupting the physical industrial processes it manages. OpenPLC Runtime v3 has reached end-of-life status and will not receive security patches; the vendor advises all users to upgrade to OpenPLC v4 to remediate this issue.

## Impact

The vulnerability affects critical infrastructure sectors including energy, water, manufacturing, and transportation systems globally. Successful exploitation allows for session hijacking, enabling unauthorized control over physical industrial processes. If exploited, an attacker could potentially override safety logic or disrupt operational technology (OT) services, leading to physical damage or process outages.

## Recommendation

Prioritized actions for security operations and IT teams:
- Immediately migrate from OpenPLC v3 to OpenPLC v4, as v3 is end-of-life and will not be patched for CVE-2026-88020.
- Isolate all OpenPLC web interfaces from public internet access by placing them behind firewalls or utilizing VPNs for remote management.
- Implement strict network segmentation to ensure control system devices are not reachable from business or guest networks.
- Conduct an audit of existing industrial control system (ICS) exposure to identify and block unauthorized access to web-based management consoles.
