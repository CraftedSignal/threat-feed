---
title: OpenAM Pre-auth User Profile Tampering via Anonymous SOAP Authn in Liberty IDPP/Discovery Endpoints (CVE-2026-45052)
slug: 2026-07-openam-preauth-soap-tampering
description: An improper authorization vulnerability (CVE-2026-45052) in OpenAM Community Edition through version 16.0.6 allows an unauthenticated attacker to write persistent entries into the Liberty Discovery store on any user's LDAP entry and a shared root-realm Discovery branch, due to a flaw in the Liberty Web Services SOAP receiver that permits anonymous writes with elevated internal privileges, potentially influencing service routing or security mechanisms if Liberty discovery data is consumed.
date: "2026-07-03T10:47:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - identity-management
  - web-application
  - openam
vendors:
  - Open Identity Platform
products:
  - OpenAM Community Edition (<= 16.0.6)
  - openam-federation-library (<= 16.0.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An Improper Authorization (CWE-285) issue in OpenAM's Liberty Web Services SOAP receiver allows an unauthenticated remote attacker to write persistent entries
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The endpoint accepts anonymous writes that are performed server-side by the Discovery handlers, bypassing the requester's LDAP and identity ACLs. The global Discovery path explicitly uses the internal admin token.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-p462-xxwx-pqf4
---

A critical improper authorization vulnerability (CVE-2026-45052) has been identified in OpenAM Community Edition, affecting versions through 16.0.6. This flaw resides within the Liberty Web Services SOAP receiver, specifically in its IDPP/Discovery Endpoints. An unauthenticated remote attacker can exploit this vulnerability to perform anonymous writes of persistent entries into the Liberty Discovery store. These malicious writes can target any user's LDAP entry or a shared root-realm Discovery branch. The exploit bypasses standard LDAP and identity Access Control Lists (ACLs) because the server-side Discovery handlers process these requests with elevated internal privileges, explicitly utilizing an internal admin token. This vulnerability, stemming from a legacy protocol (Liberty ID-WSF), allows attackers to manipulate core identity data, with potential downstream impacts on service routing or security mechanism selection in deployments that consume this Discovery data. The issue was patched in OpenAM Community Edition version 16.1.1.

## Attack Chain

1.  **Target Identification**: An unauthenticated remote attacker identifies an internet-facing OpenAM Community Edition instance running a vulnerable version (<= 16.0.6) that exposes the Liberty Web Services SOAP endpoint.
2.  **Endpoint Discovery**: The attacker discovers the vulnerable Liberty IDPP/Discovery SOAP endpoint.
3.  **Malicious Request Crafting**: The attacker crafts a specially designed SOAP request containing data intended to be written persistently into OpenAM's identity store.
4.  **Unauthorized Request Submission**: The attacker submits the crafted SOAP request to the vulnerable Liberty IDPP/Discovery endpoint without requiring any authentication.
5.  **Privilege Escalation (Internal)**: The vulnerable OpenAM server receives the unauthenticated request, and its Liberty Discovery handlers process it using an internal admin token, effectively operating with elevated privileges.
6.  **Data Tampering and Persistence**: The server-side process bypasses normal LDAP and identity ACLs, successfully writing the attacker's specified persistent entries into the Liberty Discovery store, targeting either a user's LDAP entry or a shared root-realm Discovery branch.
7.  **Impact on Service Routing/Security**: If downstream systems actively consume Liberty discovery data, these manipulated records could subsequently influence service routing decisions or compromise security mechanism selections, potentially leading to unauthorized access, bypass of authentication, or denial of service.

## Impact

OpenAM Community Edition deployments up to version 16.0.6 that have the Liberty Web Services component exposed are severely impacted. An unauthenticated attacker can leverage this vulnerability to inject persistent, unauthorized data into critical identity stores. This includes the ability to modify user LDAP entries and global Discovery branches. Because these writes occur with elevated internal privileges and bypass normal access controls, they represent a significant compromise of the identity management system. In environments where Liberty discovery data is actively utilized, such manipulated records could directly influence how services are routed or how security mechanisms operate, potentially leading to widespread unauthorized access, service disruption, or other severe security compromises across the affected enterprise.

## Recommendation

*   Immediately patch OpenAM Community Edition instances to version 16.1.1 or later to remediate CVE-2026-45052.
*   Review and ensure that the Liberty Web Services component is not exposed unnecessarily, especially if not actively used.
*   Consider implementing network segmentation or access control lists to restrict access to OpenAM's administrative and critical endpoints to trusted sources only.
