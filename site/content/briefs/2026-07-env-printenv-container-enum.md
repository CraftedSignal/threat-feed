---
title: Container Environment Variable Enumeration via env/printenv Commands
slug: 2026-07-env-printenv-container-enum
description: Adversaries execute 'env' or 'printenv' commands within compromised Linux containers to enumerate environment variables, aiming to discover and harvest sensitive data such as cloud API keys, Kubernetes service account tokens, or database credentials, which facilitates lateral movement and data exfiltration within cloud environments.
date: "2026-07-29T12:40:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - container-security
  - discovery
  - linux
  - cloud
  - kubernetes
vendors:
  - Kubernetes
products:
  - Kubernetes
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: The 'env' or 'printenv' command is used to display all the environment variables for the current shell, and the 'printenv' command is used to print the values of environment variables. These commands are used to enumerate the environment variables of the container, which can be used by an adversary to gain information about the container and the services running inside it.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
    evidence: This rule flags execution of env or printenv inside a Linux container, a common discovery step to expose environment variables that frequently store credentials, tokens, and service configuration.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/discovery_environment_enumeration.toml
iocs:
  - type: ip
    value: 169.254.169.254
ioc_counts:
  ip: 1
rules:
  - title: Detect Container Environment Variable Enumeration
    description: Detects the execution of 'env' or 'printenv' commands within Linux containers, a common technique for adversaries to discover sensitive environment variables.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1082
      - T1613
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This threat brief describes the adversarial technique of enumerating environment variables within Linux containers using commands like `env` or `printenv`. Threat actors, upon gaining initial access to a container, leverage these commands as a discovery step to gather sensitive configuration details. This includes cloud keys, Kubernetes service account tokens, database connection strings, and internal service endpoints. Such information is critical for an attacker to escalate privileges, move laterally within a compromised Kubernetes cluster or cloud environment, make authenticated API calls, or exfiltrate data. Elastic Defend for Containers provides detection capabilities for this activity, which is a common precursor to more damaging attacks. This technique, while seemingly innocuous, can expose critical infrastructure components and lead to significant compromise.

## Attack Chain

1. **Initial Compromise**: An attacker gains shell access to a Linux container through various means, such as exploiting a vulnerable application running inside the container, leveraging a misconfigured Kubernetes API, or compromising a host system.
2. **Container Access**: The attacker establishes an interactive session within the target container, often using tools like `kubectl exec` or directly connecting to a compromised service.
3. **Environment Variable Discovery**: The attacker executes `env` or `printenv` commands directly or via a shell to list all environment variables accessible from within the container's shell.
4. **Sensitive Data Harvesting**: The enumerated environment variables are scanned for high-value secrets, including cloud provider access keys (e.g., AWS_ACCESS_KEY_ID), database credentials (e.g., DB_PASSWORD), API tokens, and Kubernetes service account tokens.
5. **Metadata Service Access**: The attacker may attempt to access the instance metadata service (e.g., `curl 169.254.169.254/metadata`) to retrieve additional cloud credentials or instance-specific information.
6. **Authenticated Access & Lateral Movement**: Harvested credentials and tokens are then used to make authenticated calls to cloud APIs, Kubernetes APIs, or other internal services, enabling lateral movement within the cloud environment or cluster.
7. **Data Exfiltration/Impact**: The attacker leverages the gained access to exfiltrate sensitive data, deploy further malicious tools, or achieve other objectives like resource hijacking or denial of service.

## Impact

Successful exploitation of this discovery technique can lead to severe consequences. Attackers can harvest sensitive cloud credentials, Kubernetes service account tokens, and database passwords, enabling them to gain unauthorized access to critical cloud resources and data. This often results in lateral movement within the Kubernetes cluster, privilege escalation, and direct access to production databases or other sensitive services. The ultimate impact can range from data exfiltration and intellectual property theft to resource hijacking (e.g., cryptomining), service disruption, or even full control over the cloud infrastructure. The enumeration of environment variables significantly lowers the bar for subsequent attack stages by providing attackers with the necessary authentication material.

## Recommendation

* Deploy the provided Sigma rule to your SIEM and tune for your environment to detect `env` and `printenv` execution within containers.
* Correlate alerts from this Sigma rule with Kubernetes audit logs to identify the initiator and context of the suspicious activity.
* Implement robust monitoring for attempts to access the instance metadata service IP `169.254.169.254` from within containers.
* Immediately rotate and invalidate any secrets identified as enumerated, especially if the `169.254.169.254` IP was accessed.
* Enforce preventative controls such as disabling `kubectl exec/attach` for production containers and using secrets managers or projected volumes instead of environment variables for sensitive data.
