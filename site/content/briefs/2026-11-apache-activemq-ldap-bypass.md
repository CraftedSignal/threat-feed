---
brief_id: brief-2026-11-03-apache-activemq-ldap-bypass
event_id: brief-2026-11-03-apache-activemq-ldap-bypass
revision: 1
activity_at: "2026-11-03T22:15:25Z"
title: 'Apache ActiveMQ: LDAPAuthorizationMap authorization bypass (CVE-2026-108500)'
slug: 2026-11-apache-activemq-ldap-bypass
description: An input validation vulnerability in the LDAPAuthorizationMapPlugin allows authenticated attackers to bypass authorization controls via crafted destination names containing LDAP DN special characters.
date: "2026-11-03T22:15:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:apache:activemq:6.3.0:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:activemq:5.19.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - activemq
  - ldap
vendors:
  - Apache
products:
  - ActiveMQ (6.3.0 - 6.3.2)
  - ActiveMQ (5.19.0 - 5.19.11)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Input validation vulnerability in Apache ActiveMQ configured to use the LDAPAuthorizationMapPlugin allows an authenticated attacker to create or address a destination with a crafted name containing LDAP DN special characters
    confidence_band: high
cves:
  - id: CVE-2026-108500
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/491
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade vulnerable ActiveMQ installations to version 6.3.3 or 5.19.12
      owner: IT Operations
      due: 72h
      evidence: Source advisory identifies versions 6.3.3 and 5.19.12 as remediated
  hunt_leads:
    - lead: Monitor ActiveMQ broker logs for administrative actions or destination creation requests containing LDAP metacharacters
      technique_id: T1068
      data_needed:
        - ActiveMQ application logs
        - Audit logs for JMX/Web console operations
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability involves crafted destination names containing DN special characters
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 6.3.3 or 5.19.12
      owner: IT Operations
      addresses: CVE-2026-108500
      evidence: Source advisory indicates these versions resolve the LDAP DN injection vulnerability
---

Apache ActiveMQ is vulnerable to an authorization bypass issue (CVE-2026-108500) within the LDAPAuthorizationMapPlugin. An authenticated attacker can exploit this by creating or addressing a message destination using a name containing specific LDAP Distinguished Name (DN) special characters, such as commas, plus signs, equals signs, or backslashes. This allows the attacker to circumvent established authorization policies, potentially accessing or creating destinations they are not permitted to manage.

## Impact

Successful exploitation allows an authenticated attacker to bypass authorization constraints within the broker, leading to unauthorized message destination creation or access.

## Recommendation

* Identify and inventory all Apache ActiveMQ instances running affected versions (6.3.0 through 6.3.2, or 5.19.0 through 5.19.11).
* Upgrade Apache ActiveMQ 6.3.x instances to version 6.3.3 or later.
* Upgrade Apache ActiveMQ 5.19.x instances to version 5.19.12 or later.
* Review ActiveMQ audit logs for unexpected creation or interaction with destinations containing LDAP special characters (e.g., symbols like '+' or ',').
