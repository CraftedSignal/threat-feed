---
title: Unauthenticated Administrative Compromise in FreeIPA via OTP ACI Flaw
slug: 2026-09-freeipa-otp-bypass
description: An unauthenticated remote attacker can exploit a flaw in FreeIPA's self-managed OTP token access control instructions to create arbitrary Kerberos principals and grant them administrator group membership.
date: "2026-09-07T13:36:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:freeipa:freeipa:*:*:*:*:*:*:*:*
tags:
  - identity-management
  - authentication-bypass
  - privilege-escalation
  - ldap
vendors:
  - FreeIPA
products:
  - FreeIPA (all versions)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078.002
    technique_name: 'Valid Accounts: Domain Accounts'
    evidence: An unauthenticated LDAP client can exploit this... to create an arbitrary attacker-controlled Kerberos principal.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098.001
    technique_name: 'Account Manipulation: Additional Cloud or Domain Roles'
    evidence: have it added to the administrators group... obtain genuine FreeIPA administrator-group membership.
    confidence_band: high
cves:
  - id: CVE-2026-76578
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76578
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to the LDAP directory service to trusted subnets only
      owner: IT Operations
      due: 24h
      evidence: Exploit requires unauthenticated LDAP client access to the directory service
  hunt_leads:
    - lead: Identification of newly created principals added to the administrator group
      technique_id: T1098
      data_needed:
        - LDAP access logs
        - FreeIPA audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit results in unauthorized Kerberos principals added to the admin group
  mitigation_plan:
    - priority: immediate
      action: Apply vendor-supplied patches for CVE-2026-76578 to FreeIPA and 389 Directory Server
      owner: IT Operations
      addresses: CVE-2026-76578
      evidence: Source explicitly identifies CVE-2026-76578 as the vulnerability root cause
---

A critical vulnerability (CVE-2026-76578) exists within FreeIPA's self-managed OTP token mechanism. The Access Control Instructions (ACI) associated with self-managed tokens fail to enforce authentication requirements and do not validate attributes added alongside a token entry. An unauthenticated attacker can interact with the LDAP interface to inject arbitrary attributes. When chained with a related, independently tracked vulnerability in the underlying 389 Directory Server's ACI evaluation logic, the attacker can successfully create a malicious Kerberos principal and append it to the administrator group. This enables full administrative control over the FreeIPA environment, including directory management and potential impact on integrated IdM services in SID-enabled deployments. Because the attack originates from the network-accessible LDAP service without requiring prior authentication, it poses a severe risk to identity infrastructure.

## Attack Chain

1. Attacker performs network reconnaissance to identify accessible LDAP interfaces (port 389/636) on the target FreeIPA instance.
2. Attacker crafts a malicious LDAP packet targeting the self-managed OTP token endpoint.
3. Attacker bypasses missing authentication checks within the vulnerable OTP ACI implementation.
4. Attacker injects arbitrary attributes into the directory entry, bypassing existing input validation constraints.
5. Attacker leverages a secondary ACI evaluation vulnerability in the underlying directory server to elevate privileges for the injected principal.
6. Attacker creates an unauthorized Kerberos principal and associates it with the administrator group in the LDAP backend.
7. Attacker authenticates as the newly created administrative principal to obtain a legitimate Kerberos ticket-granting ticket (TGT).
8. Attacker performs administrative operations, such as user modification or full directory exfiltration, gaining total control over IdM services.

## Impact

Successful exploitation results in complete administrative compromise of the FreeIPA environment. An attacker can gain unauthorized membership in the administrator group, allowing them to modify sensitive identity records, access secret keys, and manage all IdM services. In deployments where SID mapping is enabled, this compromise may extend to integrated Windows environments and other services relying on the IdM instance, leading to large-scale credential theft and persistent unauthorized access.

## Recommendation

1. Immediately audit all FreeIPA and underlying 389 Directory Server installations to confirm version compatibility with patches for CVE-2026-76578.
2. Implement strict firewall rules to restrict network-based LDAP (389/636) access to authorized management subnets only.
3. Monitor directory server access logs for anomalous LDAP bind or entry modification attempts targeting OTP token attributes or unauthorized additions to the admin group.
4. Review administrative group membership logs for recently created or unknown Kerberos principals.
