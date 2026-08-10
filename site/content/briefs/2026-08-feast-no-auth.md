---
title: Unauthenticated RCE and Data Access in Feast via Default Configuration
slug: 2026-08-feast-no-auth
description: Feast and feast-operator contain a vulnerability due to a default 'no_auth' configuration, allowing unauthenticated attackers to achieve RCE via malicious User-Defined Functions and perform unauthorized cross-tenant data access.
date: "2026-08-10T21:39:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - authentication-bypass
vendors:
  - Feast
products:
  - Feast SDK
  - feast-operator
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The default configuration for both the Feast SDK and the feast-operator is no_auth, meaning no security manager is installed.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.002
    technique_name: 'Server Software Component: Transport Agent'
    evidence: A remote attacker, by exploiting this missing authentication, could achieve remote code execution (RCE) by storing a malicious User-Defined Function (UDF) on the feature-server.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: trigger a denial of service (DoS) by forcing re-materialization of all tenant features
    confidence_band: high
cves:
  - id: CVE-2026-18941
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18941
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Scan all internal infrastructure for Feast service endpoints exposed without authentication.
      owner: Security Engineering
      due: 24h
      evidence: CVE-2026-18941 documentation regarding default no_auth configuration.
  mitigation_plan:
    - priority: immediate
      action: Disable no_auth configuration and implement robust authentication/RBAC for all Feast endpoints.
      owner: IT Operations
      addresses: CVE-2026-18941
      evidence: Source advisory recommends addressing the no_auth configuration.
---

A security vulnerability (CVE-2026-18941) exists within the Feast feature store platform, specifically affecting both the Feast SDK and the feast-operator. The core of the issue lies in a default configuration setting labeled as "no_auth." Under this configuration, the platform fails to initialize a security manager, effectively leaving the feature-server, registry-server, and offline-server endpoints entirely unprotected. 

This misconfiguration enables unauthenticated and unauthorized remote attackers to interact directly with these sensitive API endpoints. The scope of impact is significant; beyond simple unauthorized data access, an attacker can store and execute arbitrary malicious User-Defined Functions (UDFs) on the feature-server, leading to remote code execution (RCE). Furthermore, attackers can disrupt availability by triggering the re-materialization of all tenant features, resulting in a Denial of Service (DoS) condition. This issue is particularly critical for multi-tenant environments where the lack of authentication allows for broad cross-tenant data exposure. Defenders should audit all Feast deployments for the presence of the "no_auth" configuration and implement robust authentication mechanisms immediately.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to gain complete control over feature store operations, leading to critical data exfiltration, remote code execution within the infrastructure, and significant service degradation through denial of service attacks. The vulnerability affects any organization utilizing Feast or feast-operator with default security settings, particularly in cloud-native multi-tenant environments where data isolation is a primary security requirement.

## Recommendation

* Audit existing Feast and feast-operator deployments to identify instances where the "no_auth" configuration is active in production environments.
* Update Feast SDK and feast-operator components to versions that enforce secure authentication defaults.
* Restrict network access to feature-server, registry-server, and offline-server endpoints using firewalls or Service Mesh policies (mTLS/RBAC) to ensure only authorized traffic reaches these services.
* Monitor webserver access logs for anomalous POST requests directed at UDF registration or feature-server management endpoints from unauthorized IP ranges.
