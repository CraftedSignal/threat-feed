---
title: Grafana OnCall Unauthenticated Access Vulnerability (CVE-2026-63087)
slug: 2026-07-grafana-oncall-unauth-access
description: A critical unauthenticated access vulnerability, CVE-2026-63087, in Grafana OnCall through version 1.16.11 allows remote attackers to obtain a valid PluginAuthToken by sending a POST request to an internal plugin install endpoint using hardcoded default stack_id and org_id values, enabling authentication to all internal API endpoints, creation of arbitrary administrative users, and redirection of API calls to an attacker-controlled host.
date: "2026-07-16T17:18:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - unauthenticated-access
  - grafana
  - oncall
  - vulnerability
  - rce-potential
vendors:
  - Grafana Labs
products:
  - Grafana OnCall
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Grafana OnCall through 1.16.11 contains an unauthenticated access vulnerability that allows remote attackers to obtain a valid PluginAuthToken by sending a POST request to the internal plugin install endpoint using hardcoded default stack_id and org_id values
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Attackers can leverage the acquired token to ... create arbitrary Admin users via the user-context header bootstrap path
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: revoke the legitimate plugin token
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: redirect OnCall-to-Grafana API calls to an attacker-controlled host by overwriting the organization's grafana_url and api_token.
    confidence_band: med
cves:
  - id: CVE-2026-63087
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63087
---

CVE-2026-63087 describes a critical unauthenticated access vulnerability present in Grafana OnCall versions up to 1.16.11. Remote attackers can exploit this flaw by sending a POST request to a specific internal plugin installation endpoint. The vulnerability hinges on the use of hardcoded default `stack_id` and `org_id` values, which are publicly available in the source code. Upon successful exploitation, attackers can acquire a valid `PluginAuthToken`, granting them authentication privileges to all internal API endpoints of the Grafana OnCall instance. This level of access permits a range of malicious activities, including the creation of arbitrary administrative users via the `user-context header bootstrap path`, revocation of legitimate plugin tokens, and the redirection of OnCall-to-Grafana API communications to an attacker-controlled server by manipulating the `grafana_url` and `api_token` settings. This vulnerability presents a severe risk of complete system compromise and data exfiltration.

## Attack Chain

1. An attacker identifies a vulnerable Grafana OnCall instance accessible via the network.
2. The attacker crafts a malicious HTTP POST request targeting the internal plugin install endpoint of the Grafana OnCall application.
3. The POST request includes the hardcoded default `stack_id` and `org_id` values in its body or query parameters, as specified in the public source code.
4. Upon processing the request, the vulnerable Grafana OnCall instance issues a valid `PluginAuthToken` to the attacker due to the unauthenticated access flaw.
5. The attacker uses the newly acquired `PluginAuthToken` to authenticate subsequent requests to internal Grafana OnCall API endpoints.
6. Leveraging this authenticated access, the attacker sends a crafted API request, utilizing the `user-context header bootstrap path`, to create a new administrative user with full privileges.
7. The attacker may optionally revoke the legitimate plugin token to hinder detection or recovery efforts.
8. Finally, the attacker modifies critical configuration settings, such as the `grafana_url` and `api_token`, to redirect all Grafana OnCall-to-Grafana API communications to an attacker-controlled host, potentially leading to data interception or further compromise.

## Impact

Successful exploitation of CVE-2026-63087 grants attackers extensive control over the compromised Grafana OnCall instance. With a CVSS v3.1 Base Score of 9.8, the vulnerability poses a critical risk, enabling full system compromise. Attackers can create arbitrary administrator accounts, gaining complete access to sensitive data and functionality. They can also hijack critical API communication channels by redirecting them to their infrastructure, leading to data exfiltration, service disruption, or further lateral movement into connected Grafana environments. This could result in unauthorized access to monitoring data, altering alert configurations, and disrupting incident response workflows, severely impacting an organization's operational security and reliability.

## Recommendation

* Patch CVE-2026-63087 immediately by updating Grafana OnCall to version 1.16.12 or newer.
* Monitor web server access logs for unusual POST requests directed at internal plugin install endpoints on Grafana OnCall instances.
* Implement monitoring of Grafana OnCall application logs for unexpected creation of administrative users or modification of critical configuration parameters like `grafana_url` and `api_token`.
* Restrict network access to Grafana OnCall internal API endpoints to only trusted sources and necessary services.
