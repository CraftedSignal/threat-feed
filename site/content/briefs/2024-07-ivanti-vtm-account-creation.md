---
title: Ivanti VTM Administrator Account Creation via CVE-2024-7593
slug: 2024-07-ivanti-vtm-account-creation
description: Unauthenticated remote attackers are exploiting CVE-2024-7593 in Ivanti Virtual Traffic Manager (vTM) to bypass authentication and create new administrator accounts, potentially leading to full system compromise.
date: "2024-07-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ivanti
  - cve-2024-7593
  - authentication-bypass
  - account-creation
vendors:
  - Ivanti
products:
  - Ivanti Virtual Traffic Manager
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2024-7593
    cvss: 9.8
    epss: 0.99987
references:
  - https://www.ivanti.com/security/security-advisories/ivanti-virtual-traffic-manager-vtm-cve-2024-7593
  - https://nvd.nist.gov/vuln/detail/CVE-2024-7593
rules:
  - title: Ivanti VTM New Account Creation
    description: Detects the creation of new administrator accounts without a source IP address, indicating potential exploitation of CVE-2024-7593.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
      - T1190
    data_sources:
      - application
      - ivanti
  - title: Ivanti VTM Suspicious Admin Account Creation
    description: Detects creation of administrator accounts with suspicious usernames potentially indicative of CVE-2024-7593 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
      - T1190
    data_sources:
      - application
      - ivanti
rules_count: 2
---

CVE-2024-7593 is an authentication bypass vulnerability affecting Ivanti Virtual Traffic Manager (vTM), a widely used application delivery controller. This vulnerability allows unauthenticated remote attackers to bypass the admin panel's authentication mechanisms and create new administrator accounts. Exploitation of this flaw enables attackers to gain complete control over the Ivanti vTM instance, potentially disrupting services, intercepting traffic, and compromising sensitive data. Public proof-of-concept exploit code exists, increasing the likelihood of widespread exploitation. Successful exploitation can lead to a complete compromise of the vTM instance and the services it manages. The targets are organizations using vulnerable versions of Ivanti vTM, which are primarily web-facing applications requiring load balancing and traffic management.

## Attack Chain

1.  An unauthenticated attacker sends a crafted HTTP request to the Ivanti vTM admin panel, exploiting CVE-2024-7593 to bypass authentication.
2.  The attacker leverages the authentication bypass to gain unauthorized access to the vTM admin interface.
3.  The attacker uses the exposed administrative functionality to create a new user account with "admin" privileges via the 'adduser' operation.
4.  The new administrator account lacks expected authentication details in the vTM audit logs, specifically showing IP="!!ABSENT!!".
5.  The attacker logs in to the Ivanti vTM admin panel using the newly created administrator account.
6.  Once authenticated, the attacker configures the vTM instance to redirect traffic to attacker-controlled servers.
7.  The attacker intercepts sensitive data, including credentials and session tokens, from the redirected traffic.
8.  The attacker uses the compromised data to gain access to backend systems and escalate their access within the network, potentially leading to data exfiltration or ransomware deployment.

## Impact

Successful exploitation of CVE-2024-7593 allows attackers to gain full administrative control over affected Ivanti vTM instances. This can result in service disruption, data interception, and complete compromise of the applications managed by the vTM. Organizations in various sectors utilizing Ivanti vTM for critical application delivery are at risk. The creation of rogue administrator accounts can lead to unauthorized configuration changes, potentially impacting hundreds or thousands of users accessing web applications. A successful attack can lead to significant financial losses, reputational damage, and regulatory penalties.

## Recommendation

*   Deploy the Sigma rule `Ivanti VTM New Account Creation` to detect unauthorized administrator account creation attempts based on the absence of IP addresses in the audit logs.
*   Ensure Ivanti vTM audit logs are properly ingested and monitored, focusing on events with `OPERATION="adduser"` and `MODGROUP="admin"` as described in the detection rule.
*   Review existing Ivanti vTM accounts and configurations for any unauthorized changes or additions that may indicate prior compromise.
*   Apply the security patches provided by Ivanti to address CVE-2024-7593 on all affected vTM instances. Refer to the Ivanti security advisory for patch availability.
*   Implement network segmentation and access controls to limit the potential impact of a compromised vTM instance, mitigating lateral movement as described in the attack chain.
*   Investigate any alerts generated by the `Ivanti VTM New Account Creation` Sigma rule, correlating with other security events to identify potentially compromised systems.
