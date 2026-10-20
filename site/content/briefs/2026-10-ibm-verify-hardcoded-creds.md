---
title: Privilege Escalation in IBM Verify Identity and Security Access via Hard-coded Credentials
slug: 2026-10-ibm-verify-hardcoded-creds
description: IBM Verify Identity Access 11.0.3.1 and IBM Security Verify Access 10.0.9.3 contain hard-coded credentials that allow a physically proximate attacker to gain elevated administrative privileges.
date: "2026-10-20T00:31:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ibm:verify_identity_access:11.0.3.1:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:security_verify_access:10.0.9.3:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - identity-management
  - hardware
vendors:
  - IBM
products:
  - Verify Identity Access (11.0.3.1)
  - Security Verify Access (10.0.9.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsafe Credentials
    evidence: IBM Verify Identity Access 11.0.3.1 and IBM Security Verify Access 10.0.9.3 Appliance could allow a physically proximate attacker to gain elevated privileges due to the use of hard-coded credentials.
    confidence_band: high
cves:
  - id: CVE-2026-109126
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109126
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch affected IBM Verify Identity Access and Security Verify Access appliances to the vendor-recommended version.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-109126 CVSS 8.8 indicates high risk
  mitigation_plan:
    - priority: immediate
      action: Enforce physical access restrictions for all data centers and server locations housing identity appliances.
      owner: Physical Security
      addresses: CVE-2026-109126
      evidence: Vulnerability requires physical proximity to exploit
---

IBM has identified a critical security vulnerability, CVE-2026-109126, affecting IBM Verify Identity Access version 11.0.3.1 and IBM Security Verify Access version 10.0.9.3. The vulnerability stems from the inclusion of hard-coded credentials within the appliance firmware. An attacker with physical access to the device can leverage these credentials to bypass authentication mechanisms and attain administrative-level privileges on the target appliance. This represents a significant risk for organizations managing these identity and access management solutions in physical data centers or branch locations. Defenders should note that while this attack requires physical proximity, it provides full control over the identity appliance, potentially allowing for the modification of authentication policies, the creation of unauthorized accounts, or the extraction of sensitive identity data.

## Impact

Successful exploitation of this vulnerability grants an unauthorized attacker administrative control over the target appliance. This can lead to total compromise of the identity and access management environment, potentially impacting downstream integrated systems that rely on these appliances for authentication and authorization. Given the high CVSS score of 8.8, immediate remediation is required for all affected deployments.

## Recommendation

Prioritize the identification of all IBM Verify Identity Access 11.0.3.1 and IBM Security Verify Access 10.0.9.3 instances within the environment. Apply the latest security patches provided by IBM to remove the hard-coded credentials. Because the attack requires physical access, ensure physical security controls for data centers and server rooms are audited and restricted to authorized personnel only. 
