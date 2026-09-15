---
title: Insufficiently Protected Credentials Vulnerability in Schneider Electric SCADAPack x70
slug: 2026-09-schneider-scadapack-vuln
description: Schneider Electric SCADAPack x70 series RTUs contain a vulnerability (CVE-2026-81861) in the legacy 'Secure Lock' functionality that could lead to unauthorized exposure of authentication information.
date: "2026-09-15T16:31:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - industrial-control-systems
  - critical-infrastructure
vendors:
  - Schneider Electric
products:
  - SCADAPack 47x
  - SCADAPack 47xi
  - SCADAPack 47xd
  - SCADAPack 470R
  - SCADAPack 57x
  - SCADAPack 3xx
  - SCADAPack 32
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: There is an insufficiently protected credentials vulnerability that could result in exposure of authentication information and unauthorized access to RTU functionality.
    confidence_band: high
cves:
  - id: CVE-2026-81861
    epss: 0.00384
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-04
  - https://www.cve.org/CVERecord?id=CVE-2026-81861
  - https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-251-03
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all SCADAPack RTUs in the environment and verify if legacy Secure Lock is enabled.
      owner: IT Operations
      due: 72h
      evidence: Mitigation instructions in ICSA-26-258-04.
  mitigation_plan:
    - priority: immediate
      action: Disable Secure Lock feature and implement RBAC per the SCADAPack Cybersecurity Guide.
      owner: IT Operations
      addresses: CVE-2026-81861
      evidence: Remediation section of ICSA-26-258-04.
---

Schneider Electric has identified an insufficiently protected credentials vulnerability, tracked as CVE-2026-81861, affecting multiple models in the SCADAPack x70 series of Remote Terminal Units (RTUs). This flaw resides within the legacy 'Secure Lock' feature, which was designed for backward compatibility with older deployments. If an attacker leverages this weakness, they could potentially gain unauthorized access to RTU configuration information, resulting in a loss of confidentiality. The vulnerability affects a wide range of devices, including the SCADAPack 47x, 47xi, 47xd, 470R, 57x, 3xx, and 32 models. Schneider Electric advises users to prioritize the transition to Role-Based Access Control (RBAC) mechanisms, which provide more robust security, and to restrict access to these devices through network segmentation and firewall implementation.

## Impact

The vulnerability poses a risk to critical infrastructure sectors, specifically Energy and Critical Manufacturing. Successful exploitation allows unauthorized parties to bypass intended access controls for RTU configuration, potentially leading to unauthorized visibility into sensitive operational control parameters. The impact is primarily categorized as a loss of confidentiality regarding the device configuration and authentication artifacts.

## Recommendation

- Prioritize migrating from the 'Secure Lock' feature to Role-Based Access Control (RBAC) as described in the SCADAPack Cybersecurity Guide.
- Implement strict network segmentation to isolate control system networks from untrusted business networks.
- Enable and configure the built-in RTU firewall service to minimize the attack surface of the affected devices.
- Ensure all SCADAPack devices are stored in physically secure, locked cabinets to prevent unauthorized local or peripheral access.
- Review the Schneider Electric security advisory SEVD-2026-251-03 for detailed hardening procedures and administrative security guidelines.
