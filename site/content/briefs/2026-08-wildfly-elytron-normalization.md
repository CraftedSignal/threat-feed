---
title: Credential Guessing Vulnerability via WildFly Elytron Unicode Normalization
slug: 2026-08-wildfly-elytron-normalization
description: A vulnerability in WildFly Elytron's password normalization logic allows attackers to bypass intended password character entropy, facilitating unauthorized access through dictionary-based credential guessing.
date: "2026-08-20T19:18:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - vulnerability
  - middleware
vendors:
  - Red Hat
products:
  - Red Hat build of Apache Camel 4 for Quarkus 3
  - Red Hat build of Debezium 3
  - Red Hat Build of Keycloak
  - Red Hat build of Quarkus
  - Red Hat Data Grid 8
  - Red Hat JBoss Enterprise Application Platform 7
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: A remote attacker can more easily guess affected passwords by using an ASCII-only dictionary against accounts whose passwords were intended to include those non-ASCII characters.
    confidence_band: high
cves:
  - id: CVE-2026-19611
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19611
  - https://access.redhat.com/security/cve/CVE-2026-19611
  - https://bugzilla.redhat.com/show_bug.cgi?id=2514568
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory affected Red Hat middleware deployments
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-19611 list of affected products
  mitigation_plan:
    - priority: immediate
      action: Monitor for brute-force patterns targeting authentication services
      owner: SOC
      addresses: CVE-2026-19611
      evidence: Technical description of password guessing vector
---

A vulnerability (CVE-2026-19611) exists within the WildFly Elytron framework, which is utilized across multiple Red Hat middleware and security products. The flaw stems from the password hashing and verification processes performing Unicode NFKC normalization on input. This process collapses specific fullwidth characters into their ASCII equivalents. Because the system treats these transformed characters as identical to standard ASCII characters, an attacker can bypass the intended complexity of passwords that include non-ASCII characters. By leveraging an ASCII-only wordlist, an attacker can more effectively guess the password for a targeted account, significantly reducing the search space required for a successful brute-force or credential-stuffing attack. This vulnerability affects numerous enterprise products, including Keycloak, JBoss EAP, and Quarkus-based builds, and requires organizations to audit their authentication flows for impact.

## Impact

The vulnerability carries a CVSS 3.1 score of 7.4 (High). If successfully exploited, an unauthorized actor could gain access to protected services and data by brute-forcing credentials that were previously considered strong due to their inclusion of non-ASCII characters. The scope of impact extends to any environment using affected Red Hat middleware for authentication, potentially exposing enterprise-grade identity and access management systems.

## Recommendation

- Identify all instances of affected Red Hat products within the infrastructure (e.g., Keycloak, Data Grid 8, JBoss EAP 7).
- Apply security patches provided by Red Hat as soon as they become available for the affected `wildfly-elytron-password-impl` package.
- Implement rate limiting and account lockout policies for all authentication endpoints to mitigate the risk of automated credential guessing attacks.
- Review authentication logs for anomalous spikes in failed login attempts, particularly those originating from single IP addresses, which may indicate automated dictionary-based attempts targeting this vulnerability.
