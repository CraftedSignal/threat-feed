---
title: 'CVE-2026-110111: Improper Access Control in Xen Orchestra'
slug: 2026-10-xen-orchestra-privilege-escalation
description: Xen Orchestra versions prior to 6.9.0 are vulnerable to privilege escalation via prototype pollution in ESXi import methods, allowing authenticated users to gain global administrator rights.
date: "2026-10-14T04:36:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vates:xen_orchestra:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - remote-code-execution
  - web-application
  - xen-orchestra
vendors:
  - Vates
products:
  - Xen Orchestra (< 6.9.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated attacker can trigger a prototype pollution attack... which allows for privilege escalation to global administrator.
    confidence_band: high
cves:
  - id: CVE-2026-110111
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110111
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Xen Orchestra to version 6.9.0 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-110111 patching requirement
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Xen Orchestra 6.9.0 or later
      owner: IT Operations
      addresses: CVE-2026-110111
      evidence: NVD vulnerability disclosure
---

Xen Orchestra versions prior to 6.9.0 contain an improper access control vulnerability identified as CVE-2026-110111. The vulnerability exists within the 'vm.importFromEsxi' and 'vm.importMultipleFromEsxi' methods, which are used to import virtual machines. An authenticated attacker can exploit this flaw by pointing the 'xo-server' component to a malicious ESXi host controlled by the attacker. By serving a crafted '.vmx' file containing a '__proto__.permission' property, the attacker triggers a prototype pollution attack. This pollution forces 'Object.prototype' to inherit administrative permissions, effectively granting the authenticated user global administrator rights within the Xen Orchestra instance. This escalation can be further leveraged to achieve remote code execution. Given the impact on administrative access control, this vulnerability represents a significant risk for environments utilizing Xen Orchestra for management of virtual infrastructure.

## Attack Chain

1. Attacker obtains valid low-privileged authentication credentials for the target Xen Orchestra instance.
2. Attacker prepares a rogue ESXi host that hosts a specially crafted .vmx virtual machine definition file.
3. The .vmx file is injected with the malicious '__proto__.permission' property to facilitate prototype pollution.
4. Attacker invokes the 'vm.importFromEsxi' or 'vm.importMultipleFromEsxi' method via the Xen Orchestra API or web interface, specifying the attacker-controlled ESXi host.
5. The 'xo-server' component processes the malicious .vmx file, resulting in the successful pollution of 'Object.prototype'.
6. The application incorrectly validates user permissions against the polluted prototype, elevating the attacker's session to global administrator.
7. Attacker uses the elevated administrative privileges to execute arbitrary commands or configure the virtual infrastructure, resulting in full compromise.

## Impact

Successful exploitation allows any authenticated user to achieve global administrator privileges within the Xen Orchestra management platform. This bypass of access controls leads to a total loss of confidentiality and integrity of the managed virtual environment, as the attacker can perform unauthorized administrative actions, manipulate virtual machines, or achieve remote code execution on the server hosting the Xen Orchestra management software.

## Recommendation

* Upgrade Xen Orchestra to version 6.9.0 or later immediately to patch the vulnerable import methods.
* Restrict network access to the Xen Orchestra API and management interface to trusted administrative subnets only.
* Implement monitoring of API calls to 'vm.importFromEsxi' and 'vm.importMultipleFromEsxi' to detect attempts to reach unknown or non-standard ESXi management endpoints.
