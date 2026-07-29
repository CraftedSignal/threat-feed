---
title: Logging Operator Configuration Injection Leading to RCE
slug: 2026-07-logging-operator-rce
description: The Logging operator is vulnerable to remote code execution due to improper input sanitization in Fluentd configuration rendering, allowing authenticated users to inject arbitrary configuration blocks via CRDs.
date: "2026-07-29T17:02:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - kubernetes
  - configuration-injection
  - cve-2026-54680
vendors:
  - kube-logging
products:
  - logging-operator (< 0.0.0-20260608145523-cf437d7f1e05)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: By specifying Fluentd's core @type exec plugin in that injected block, an attacker can execute arbitrary commands inside the Fluentd aggregator.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mjqf-28ph-426h
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54680
---

The Logging operator for Kubernetes, specifically versions prior to 0.0.0-20260608145523-cf437d7f1e05, contains a critical configuration injection vulnerability tracked as CVE-2026-54680. The operator is responsible for rendering Fluentd configuration files based on custom resource definitions (CRDs) such as 'Flow'. The 'FluentRender' logic fails to escape newline characters and special formatting characters when processing fields like 'record_transformer.records'. 

An attacker who has sufficient Kubernetes RBAC permissions to create or update 'Flow' resources in a namespace can inject arbitrary Fluentd configuration directives. By breaking out of the intended configuration context, an attacker can define a custom '&lt;match **>' block utilizing the Fluentd '@type exec' plugin. This plugin allows for the execution of arbitrary shell commands within the Fluentd aggregator container. Given that the aggregator often manages logs across multiple tenants, this vulnerability facilitates lateral movement, potential access to sensitive node metadata via the Instance Metadata Service (IMDS), and full compromise of the logging infrastructure.

## Attack Chain

1. The attacker identifies a target cluster running a vulnerable version of the Logging operator.
2. The attacker gains or uses existing RBAC permissions to create a 'Flow' custom resource in a permitted namespace.
3. The attacker crafts a malicious 'record_transformer' entry containing newline characters designed to terminate the existing configuration block.
4. The attacker injects a new '&lt;match **>' block containing the '@type exec' plugin definition and a payload command.
5. The Logging operator reconciles the 'Flow' resource and writes the malicious configuration to the generated Fluentd 'fluentd.conf' Secret.
6. The Fluentd aggregator pod refreshes its configuration and initializes the injected 'out_exec' plugin.
7. A log message is triggered or emitted by a pod, forcing the Fluentd buffer to flush.
8. The command specified in the 'command' parameter is executed with the privileges of the Fluentd aggregator process.

## Impact

Successful exploitation results in arbitrary remote code execution within the Fluentd aggregator container. This allows the attacker to steal logs from all namespaces processed by the aggregator, exfiltrate sensitive data, or interact with cloud-native infrastructure services like IMDS (e.g., retrieving instance credentials). This vulnerability affects all environments where the Logging operator is deployed to manage multi-tenant log aggregation.

## Recommendation

* Immediately upgrade the Logging operator to a version equal to or later than 0.0.0-20260608145523-cf437d7f1e05 to remediate CVE-2026-54680.
* Audit Kubernetes RBAC policies to ensure that only authorized service accounts or users have the ability to create or modify 'Flow' and 'Output' custom resources within namespaces.
* Implement Admission Control (e.g., OPA Gatekeeper or Kyverno) to validate 'Flow' resource contents, specifically looking for disallowed characters like newlines or unauthorized Fluentd plugin types within the 'record_transformer' fields.
* Review logs for the creation of 'Flow' or 'Output' resources by unexpected users or ServiceAccounts using Kubernetes audit logs.
