---
title: CVE-2026-0308 Stored XSS in PAN-OS Web Interface
slug: 2026-09-panos-xss
description: A stored cross-site scripting (XSS) vulnerability in the PAN-OS web interface allows an authenticated administrator to execute arbitrary JavaScript within the context of the management interface.
date: "2026-09-09T18:58:08Z"
lastmod: "2026-09-09T18:58:48Z"
type: threat
types:
  - threat
severities:
  - high
cpes:
  - cpe:2.3:o:palo_alto_networks:pan-os:12.1.2:*:*:*:*:*:*:*
  - cpe:2.3:o:palo_alto_networks:pan-os:11.2.13:*:*:*:*:*:*
  - cpe:2.3:o:palo_alto_networks:pan-os:11.1.16:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - pan-os
  - cve
  - rce
  - network-security
  - vulnerability
  - panos
vendors:
  - Palo Alto Networks
products:
  - PAN-OS (12.1.2 - 12.1.9)
  - PAN-OS (11.2.0 - 11.2.13)
  - PAN-OS (11.1.0 - 11.1.16)
  - PAN-OS (12.2 < 12.2.3)
  - PAN-OS (12.1 < 12.1.10)
  - PAN-OS (11.2 < 11.2.13-h2)
  - PAN-OS (11.1 < 11.1.16-h2)
  - PAN-OS (10.2 < 10.2.18-h10)
  - Panorama
  - VM-Series
  - PA-Series
  - Prisma Access
  - Cloud NGFW
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: A stored cross-site scripting (XSS) vulnerability in Palo Alto Networks PAN-OS software enables a malicious authenticated administrator to store or execute a JavaScript payload using the web interface.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: A command injection vulnerability in Palo Alto Networks PAN-OS software enables an authenticated administrator to bypass system restrictions and run arbitrary commands as a root user.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A buffer overflow vulnerability in the XML processing functionality of Palo Alto Networks PAN-OS software enables an unauthenticated attacker with network access to the management web or dataplane interface to cause a denial of service (DoS) condition on VM-Series firewalls or execute arbitrary code with root privileges on the PA-Series firewalls.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: execute arbitrary code with root privileges on the PA-Series firewalls.
    confidence_band: high
references:
  - https://security.paloaltonetworks.com/CVE-2026-0308
  - https://security.paloaltonetworks.com/CVE-2026-0309
  - https://security.paloaltonetworks.com/CVE-2026-0310
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
updates:
  - at: "2026-09-09T18:58:38Z"
    level: L1
    summary: added coverage for PAN-OS (12.2 < 12.2.3) +4 products
    sources:
      - palo-alto-networks
    source_urls:
      - https://security.paloaltonetworks.com/CVE-2026-0309
  - at: "2026-09-09T18:58:48Z"
    level: L2
    summary: added coverage for PAN-OS (12.2 < 12.2.3) +9 products
    sources:
      - palo-alto-networks
    source_urls:
      - https://security.paloaltonetworks.com/CVE-2026-0310
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
