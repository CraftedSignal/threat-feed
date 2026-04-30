---
title: Kerberos Authentication Relay via DNS CNAME Abuse (CVE-2026-20929)
slug: 2026-04-kerberos-relay-cname
description: An attacker exploits CVE-2026-20929 by manipulating DNS responses to redirect Kerberos authentication to attacker-controlled AD CS, enabling certificate enrollment for persistent access.
date: "2026-03-31T17:49:30Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - kerberos
  - relay
  - adcs
  - cve-2026-20929
  - credential-access
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
cves:
  - id: CVE-2026-20929
    cvss: 7.5
    epss: 0.00045
references:
  - https://www.crowdstrike.com/en-us/blog/detecting-kerberos-relay-attack-via-dns-cname-abuse/
rules:
  - title: Detect Kerberos Ticket Request for Unusual SPN via DNS CNAME
    description: Detects Kerberos ticket requests where the SPN resolves to an IP address different from the domain.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1558.004
    data_sources:
      - dns_query
      - windows
  - title: Detect Access to AD CS Web Enrollment Endpoint
    description: Detects HTTP requests to the AD CS web enrollment endpoint (/certsrv).
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1558.004
    data_sources:
      - webserver
      - windows
rules_count: 2
---

CVE-2026-20929, a vulnerability patched in January 2026, allows attackers to perform Kerberos authentication relay attacks by abusing DNS CNAME records. The attack involves manipulating DNS resolution to redirect a client's Kerberos authentication request to an attacker-controlled server. This server then relays the authentication to Active Directory Certificate Services (AD CS) to enroll certificates on behalf of the victim user. This technique allows the attacker to gain persistent access to the domain. The vulnerability has a CVSS score of 7.5. This attack is a Kerberos-based variant of the ESC8 attack, which traditionally relies on NTLM relay. By exploiting Kerberos, the attack can bypass environments where NTLM has been disabled. The primary target is the AD CS web enrollment endpoint (/certsrv).

## Attack Chain

1. The victim attempts to access a web server (e.g., web01.test.local).
2. A DNS query is initiated to resolve the hostname of the target web server.
3. The attacker intercepts the DNS query and responds with a crafted DNS response containing a CNAME record that redirects the original hostname (web01.test.local) to an attacker-controlled target (e.g., CA01.test.local), along with an A record pointing to the attacker's IP address.
4. The victim's system accesses the attacker-controlled web server.
5. The malicious web server sends a 401 HTTP response to initiate Kerberos authentication.
6. The victim requests a Kerberos service ticket for HTTP/CA01.test.local from the domain controller.
7. The domain controller issues a service ticket for the requested SPN.
8. The attacker relays the Kerberos ticket to the AD CS web enrollment endpoint (/certsrv) to request a certificate for the victim user, thereby achieving persistent access.

## Impact

Successful exploitation of CVE-2026-20929 allows an attacker to enroll certificates on behalf of domain users, granting them persistent access to the network. Certificates are often valid for extended periods (1+ years) and are less frequently monitored than password-based authentication. This attack can bypass controls that disable NTLM authentication, and web enrollment over HTTP prevents Channel Binding Token (CBT) protection, making AD CS web enrollment an attractive relay target. The number of potential victims depends on the number of vulnerable AD CS deployments.

## Recommendation

*   Monitor for anomalous certificate-based authentication events combined with unusual AD CS service access within a short time window, as highlighted in the "CrowdStrike has developed a correlation-based detection" statement in the overview.
*   Disable web enrollment over HTTP to enforce Channel Binding Token (CBT) protection, mitigating the risk of successful relay attacks, as mentioned in the "Why AD CS Web Enrollment Is an Attractive Relay Target" section.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect potential exploitation attempts.
*   Review and harden AD CS configurations based on recommendations from "Certified Pre-Owned" research to reduce the attack surface.
