---
title: CVE-2026-0308 Stored XSS in PAN-OS Web Interface
slug: 2026-09-panos-xss
description: A stored cross-site scripting (XSS) vulnerability in the PAN-OS web interface allows an authenticated administrator to execute arbitrary JavaScript within the context of the management interface.
date: "2026-09-09T18:58:08Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:o:palo_alto_networks:pan-os:12.1.2:*:*:*:*:*:*:*
  - cpe:2.3:o:palo_alto_networks:pan-os:11.2.13:*:*:*:*:*:*
  - cpe:2.3:o:palo_alto_networks:pan-os:11.1.16:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - pan-os
vendors:
  - Palo Alto Networks
products:
  - PAN-OS (12.1.2 - 12.1.9)
  - PAN-OS (11.2.0 - 11.2.13)
  - PAN-OS (11.1.0 - 11.1.16)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: A stored cross-site scripting (XSS) vulnerability in Palo Alto Networks PAN-OS software enables a malicious authenticated administrator to store or execute a JavaScript payload using the web interface.
    confidence_band: high
references:
  - https://security.paloaltonetworks.com/CVE-2026-0308
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade PAN-OS to fixed versions listed in the recommendation section
      owner: IT Operations
      due: 72h
      evidence: Vendor security advisory fix guidance
  mitigation_plan:
    - priority: immediate
      action: Restrict management interface access via ACLs or Jump Box
      owner: IT Operations
      addresses: CVE-2026-0308
      evidence: Vendor advisory risk reduction section
---

CVE-2026-0308 is a stored cross-site scripting (XSS) vulnerability affecting Palo Alto Networks PAN-OS software. The vulnerability resides in the web-based management interface, enabling a malicious authenticated administrator to inject and store arbitrary JavaScript payloads. When other users access the affected web interface, the stored payload executes in their browser context. The vulnerability is applicable to PA-Series and VM-Series firewalls, as well as Panorama management appliances. Although the vulnerability requires high privileges (authenticated administrator access), it is accessible over the network. Palo Alto Networks has confirmed that no malicious exploitation has been observed in the wild. Customers are advised to upgrade to the specified patched versions to remediate the vulnerability, as no workarounds are currently available.

## Impact

Successful exploitation of this vulnerability could allow an authenticated attacker to compromise the sessions of other administrators accessing the PAN-OS management interface. This may lead to unauthorized actions performed on behalf of legitimate administrators, potentially impacting the integrity of the firewall configuration or management operations. The severity is assessed as low by the vendor, and the vulnerability does not impact Cloud NGFW or Prisma Access.

## Recommendation

1. Upgrade all affected PA-Series, VM-Series, and Panorama appliances to the recommended fixed versions immediately:
 - For PAN-OS 12.1, upgrade to version 12.1.10 or later.
 - For PAN-OS 11.2, upgrade to version 11.2.13-h2 or later.
 - For PAN-OS 11.1, upgrade to version 11.1.16-h2 or later.
2. Implement network segmentation by restricting management interface access to a dedicated jump box or trusted management subnet to limit exposure.
3. If Threat Prevention is licensed, enable Threat ID 510040 and 510041 and ensure appropriate SSL decryption is configured for inbound management traffic to facilitate inspection.
