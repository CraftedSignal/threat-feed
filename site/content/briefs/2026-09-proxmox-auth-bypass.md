---
title: Authentication Bypass in Proxmox Virtual Environment
slug: 2026-09-proxmox-auth-bypass
description: CVE-2023-54391 allows unauthenticated remote attackers to bypass authentication in Proxmox VE 7.0-8.0 by providing a crafted tfa-challenge parameter to the API login endpoint.
date: "2026-09-01T23:09:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:proxmox:virtual_environment:7.0:*:*:*:*:*:*:*
  - cpe:2.3:a:proxmox:virtual_environment:8.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - critical
vendors:
  - Proxmox
products:
  - Proxmox Virtual Environment (7.0 - 8.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An unauthenticated attacker can exploit this by sending a crafted POST request to the API login endpoint, providing an arbitrary value for the tfa-challenge parameter.
    confidence_band: high
cves:
  - id: CVE-2023-54391
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-54391
rules:
  - title: Detects CVE-2023-54391 Exploitation - Unauthorized API Access
    description: Detects exploitation attempts where an unauthenticated user provides a tfa-challenge parameter to the Proxmox login API
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1550.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all internet-facing Proxmox VE instances
      owner: SOC
      due: 24h
      evidence: Source confirms CVE-2023-54391 vulnerability exists in versions 7.0-8.0
  mitigation_plan:
    - priority: immediate
      action: Upgrade Proxmox VE to a supported version beyond 8.0.4
      owner: IT Operations
      addresses: CVE-2023-54391
      evidence: NVD vulnerability details regarding libpve-access-control
---

CVE-2023-54391 is an authentication bypass vulnerability affecting the Proxmox Virtual Environment (VE) 7.0 through 8.0, specifically within the libpve-access-control component versions prior to 8.0.4. The vulnerability stems from improper validation of the tfa-challenge parameter during the API login process. An unauthenticated attacker can supply an arbitrary value in this parameter to successfully authenticate as any enabled user, including the root account (root@pam), provided that user does not have a second factor configured. Successful exploitation results in full administrative control over the hypervisor and managed virtual machine environments. As all affected versions are documented as end-of-life, defenders must prioritize identifying vulnerable instances and migrating to supported versions, as patches for these specific releases may not be available.

## Impact

Successful exploitation allows for complete, unauthenticated administrative access to the Proxmox VE management interface. This permits the attacker to execute arbitrary code, manipulate virtual machines, access sensitive guest data, and potentially pivot into the underlying network infrastructure hosting the hypervisor.

## Recommendation

Prioritize the identification of internet-facing Proxmox VE instances running version 8.0.3 or earlier. Given that these versions are end-of-life, the primary mitigation is immediate migration to a supported, patched version of Proxmox VE. Monitor web server logs for high volumes of POST requests to the API ticket endpoint originating from unauthorized IP addresses, specifically looking for abnormal usage of the tfa-challenge parameter.
