---
title: Unauthenticated Remote Code Execution in Splunk Enterprise Patroni REST API
slug: 2026-10-splunk-rest-api-rce
description: An authentication bypass vulnerability in the Splunk Enterprise Patroni REST API allows unauthenticated remote attackers to execute arbitrary system commands via configuration manipulation.
date: "2026-10-07T22:56:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:splunk:splunk_enterprise:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - splunk
vendors:
  - Splunk
products:
  - Splunk Enterprise (< 10.4.3, < 10.2.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated user with network access to the Patroni Representational State Transfer (REST) Application Programming Interface (API) on a search head cluster member could execute attacker-controlled operating-system commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An unauthenticated user... could execute attacker-controlled operating-system commands.
    confidence_band: high
cves:
  - id: CVE-2026-76268
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76268
  - https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.2/splunk-sidecars/sidecar-configuration-settings
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Splunk Enterprise to version 10.4.3 or 10.2.7.
      owner: IT Operations
      due: 24h
      evidence: Source documentation for CVE-2026-76268 specifies these versions for remediation.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the Patroni REST API via host-based firewalls.
      owner: IT Operations
      addresses: CVE-2026-76268
      evidence: Vulnerability requires network access to the API.
---

CVE-2026-76268 is a critical security vulnerability affecting Splunk Enterprise versions prior to 10.4.3 and 10.2.7. The vulnerability exists within the Patroni REST API component, which is used for cluster management. Due to insufficient authentication checks on this interface, an unauthenticated attacker with network access to a search head cluster member can interact with the API to perform critical configuration operations. By manipulating sidecar configuration settings via the exposed REST endpoint, an attacker can trigger the execution of arbitrary commands on the underlying host operating system with the privileges of the Splunk service account. This issue poses a significant risk to the integrity and confidentiality of the Splunk environment. Organizations running affected versions are strongly advised to upgrade to version 10.4.3, 10.2.7, or later to remediate the vulnerability.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing or internally accessible Splunk search head cluster members.
2. Attacker probes the network to verify reachability of the Patroni REST API endpoint.
3. Attacker sends an unauthenticated HTTP request to the Patroni REST API to list existing sidecar configurations.
4. Attacker constructs a malicious configuration payload containing arbitrary shell commands.
5. Attacker submits the payload via a PUT or POST request to the API, bypassing the missing authentication gate.
6. Splunk Enterprise processes the malicious configuration update.
7. The Patroni sidecar mechanism triggers the configured command, resulting in remote code execution on the search head.

## Impact

Successful exploitation allows unauthenticated remote attackers to achieve full code execution on Splunk search head cluster members. This impact enables attackers to pivot into the internal network, exfiltrate indexed data, or gain persistence within the security monitoring infrastructure. Given the critical nature of Splunk as a centralized logging and analysis platform, compromise of search heads could lead to the complete subversion of security operations and observability capabilities.

## Recommendation

1. Immediately upgrade Splunk Enterprise to version 10.4.3 or 10.2.7 to address CVE-2026-76268.
2. Restrict network access to the Patroni REST API port on search head cluster members to authorized administrative IP ranges using host-based firewalls or network access control lists.
3. Monitor web server and application logs for unauthorized POST or PUT requests to Patroni REST API endpoints originating from non-authorized internal sources.
