---
title: Remote Code Execution in Submariner via CRD Injection
slug: 2026-09-submariner-cve
description: Submariner in cert-auth mode is vulnerable to command injection via improper input validation in the CableName field, allowing unauthenticated remote code execution as root.
date: "2026-09-02T19:15:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:submariner:submariner:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - kubernetes
  - cve
  - cloud
vendors:
  - Submariner
products:
  - Submariner (cert-auth mode)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A malicious cluster can exploit this by publishing a CableName that includes newlines and ipsec.conf directives.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This allows an attacker to inject arbitrary configuration parameters or execute commands through leftupdown hooks.
    confidence_band: high
cves:
  - id: CVE-2026-66786
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66786
action_plan:
  priority: elevated
  owners:
    - Security Operations
    - Infrastructure Security
  immediate_actions:
    - action: Review Kubernetes RBAC for Submariner resource access
      owner: Infrastructure Security
      due: 24h
      evidence: Source identifies CRD manipulation as the primary exploit vector
  mitigation_plan:
    - priority: immediate
      action: Monitor and restrict access to Submariner CRDs
      owner: Infrastructure Security
      addresses: CVE-2026-66786
      evidence: Vulnerability allows execution via CRD input
---

CVE-2026-66786 is a critical vulnerability identified in Submariner when operating in cert-auth mode. The flaw stems from insufficient validation of user-supplied input within Custom Resource Definitions (CRDs). Specifically, the connection configuration is constructed using free-form strings from the CableName parameter. An attacker with the ability to modify or publish a CRD can inject newline characters alongside malicious ipsec.conf directives. 

By manipulating these directives, an attacker can influence the execution of leftupdown hooks within the IPsec configuration. Because these hooks are executed in the context of the gateway node, this vulnerability facilitates remote code execution with root privileges. This poses a significant risk to the integrity and confidentiality of multi-cluster Kubernetes environments utilizing Submariner for cross-cluster connectivity. Defenders should prioritize restricting access to CRD creation and update operations and monitor for anomalous configurations within Submariner resources.

## Attack Chain

1. Attacker gains write access to the Kubernetes API server or manages a cluster federated via Submariner.
2. Attacker initiates the creation or modification of a Submariner CRD object.
3. Attacker injects a payload into the CableName field containing newline characters and crafted ipsec.conf directives.
4. The Submariner controller processes the malicious CRD, appending the injection strings to the local IPsec configuration files.
5. The underlying IPsec service reloads, processing the injected configuration directives.
6. The system invokes the configured leftupdown hooks as defined by the attacker's injected parameters.
7. The gateway node executes the arbitrary commands defined in the hook with root-level privileges.
8. Attacker achieves persistent command execution and potential lateral movement across the connected clusters.

## Impact

Successful exploitation of CVE-2026-66786 results in full system compromise of the gateway node with root privileges. In a multi-cluster deployment, this allows an attacker to bridge the security boundary between clusters, leading to potential data exfiltration, service disruption, and total control over the interconnected network fabric. No victim counts or sector-specific data are currently available, but any organization using Submariner in cert-auth mode is considered at risk.

## Recommendation

* Restrict RBAC permissions for creating or updating Submariner Custom Resource Definitions to trusted administrative service accounts.
* Audit existing Submariner CRDs for non-standard characters or unexpected directives within the CableName field.
* Monitor Kubernetes API audit logs for unusual object modifications related to Submariner resources.
* Upgrade Submariner installations to the latest patched version once released by the vendor to remediate the input validation logic.
