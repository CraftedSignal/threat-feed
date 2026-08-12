---
title: Information Disclosure Vulnerability in PAN-OS URL Filtering
slug: 2026-08-panos-url-filter-vuln
description: An information disclosure vulnerability (CVE-2026-0301) in Palo Alto Networks PAN-OS URL Filtering allows unauthenticated attackers to access sensitive memory data if custom response pages are enabled.
date: "2026-08-12T16:48:45Z"
type: threat
types:
  - threat
severities:
  - low
exploited: true
tags:
  - vulnerability
  - information-disclosure
  - pan-os
  - palo-alto
vendors:
  - Palo Alto Networks
products:
  - PAN-OS
  - Prisma Access
  - Cloud NGFW
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An information disclosure vulnerability in the URL Filtering feature of Palo Alto Networks PAN-OS software enables an unauthenticated user with network access to obtain sensitive information.
    confidence_band: high
references:
  - https://security.paloaltonetworks.com/CVE-2026-0301
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Review Device > Response Pages for custom HTML configurations
      owner: IT Operations
      due: 48h
      evidence: Required Configuration for Exposure section
  mitigation_plan:
    - priority: immediate
      action: Upgrade PAN-OS to patched versions
      owner: IT Operations
      addresses: CVE-2026-0301
      evidence: Vendor solution table
---

Palo Alto Networks has disclosed an information disclosure vulnerability (CVE-2026-0301) affecting the URL Filtering feature in PAN-OS. The flaw is rooted in an uninitialized resource usage (CWE-908) when the firewall is configured to display a custom HTML response page to users. An unauthenticated attacker with network access to the device can exploit this by triggering the display of these custom pages, potentially leading to the leakage of sensitive data residing in system memory. 

This issue specifically impacts firewalls running affected versions of PAN-OS 10.2, 11.1, and Prisma Access 10.2, provided that a non-standard, custom URL filtering response page has been imported. Predefined (default) response pages are not impacted by this flaw, as they do not utilize the vulnerable variables. Palo Alto Networks has confirmed there is no evidence of active exploitation in the wild as of August 2026.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive information potentially residing in system memory. While the severity is categorized as low, the exposure depends on the configuration of response pages and the sensitivity of data handled by the firewall. Victims include organizations using customized web-blocking interfaces on impacted PAN-OS devices.

## Recommendation

- Upgrade PAN-OS and Prisma Access devices to the patched versions specified in the vendor advisory (e.g., 10.2.8, 11.1.16-h1, 11.1.17, or 10.2.10 for Prisma Access).
- Inspect all custom URL Filtering response pages configured via the device management interface (Device > Response Pages).
- Limit the use of Response Page Variables to only those provided in the Predefined URL Filtering Response Pages (user, url, category, pan_form).
- Deploy the vendor-provided patches as the primary remediation step.
