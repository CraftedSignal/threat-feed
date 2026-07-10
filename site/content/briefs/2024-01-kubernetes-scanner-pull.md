---
title: Kubernetes Security Scanner Image Pulling Detected
slug: 2024-01-kubernetes-scanner-pull
description: Detection of Kubernetes security scanner images such as kube-hunter, kube-bench, and kube-recon being pulled, indicating potential vulnerability assessment and reconnaissance activity within the Kubernetes environment.
date: "2024-01-03T15:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - container
  - vulnerability-scan
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
references:
  - https://github.com/splunk/splunk-connect-for-kubernetes
rules:
  - title: Kubernetes Scanner Image Pulling
    description: Detects the pulling of known Kubernetes security scanner images
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1526
    data_sources:
      - container
      - kubernetes
  - title: Kubernetes Kube-Hunter Execution Detection
    description: Detects the execution of kube-hunter within a Kubernetes cluster
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1526
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This analytic detects the pulling of known Kubernetes security scanner images, specifically kube-hunter, kube-bench, and kube-recon. These tools are often used to identify vulnerabilities within a Kubernetes cluster. The detection leverages Kubernetes logs, specifically monitoring for messages indicating the pulling of these images. While security teams may use these tools for legitimate security assessments, their presence can also signify malicious reconnaissance by an attacker seeking to exploit weaknesses in the Kubernetes environment. The activity was initially observed on 2026-04-15, and the detection logic was published shortly after on 2026-04-17. Defenders should investigate any unauthorized pulling of these images.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access to the Kubernetes environment through various means, such as exploiting a misconfigured service or compromised credentials.
2.  **Privilege Escalation:** The attacker attempts to escalate privileges within the cluster to gain broader access to resources and information.
3.  **Image Pulling:** The attacker initiates the pulling of security scanner images like kube-hunter, kube-bench, or kube-recon into the Kubernetes environment using `kubectl` or other Kubernetes management tools.
4.  **Reconnaissance:** The attacker executes the security scanner tools within the Kubernetes cluster to identify potential vulnerabilities and misconfigurations. These tools perform automated scans and report findings.
5.  **Lateral Movement:** Based on the identified vulnerabilities, the attacker attempts to move laterally within the cluster, accessing sensitive data or compromising other containers and pods.
6.  **Data Exfiltration/System Compromise:** The attacker exploits discovered vulnerabilities to exfiltrate sensitive data or compromise critical systems within the Kubernetes cluster.
7.  **Persistence:** The attacker establishes persistent access within the cluster to maintain control and potentially re-exploit vulnerabilities in the future.

## Impact

The successful execution of this attack chain can lead to the complete compromise of the Kubernetes cluster. This includes the exfiltration of sensitive data, the disruption of services, and the potential for further attacks on connected systems. The impact can range from data breaches and financial losses to reputational damage and legal liabilities. Even if the attacker fails to fully compromise the environment, the reconnaissance phase can expose vulnerabilities that could be exploited in future attacks.

## Recommendation

*   Deploy the Sigma rule `Kubernetes Scanner Image Pulling` to your SIEM to detect the pulling of known Kubernetes security scanner images.
*   Investigate any instances of security scanner image pulling to determine if the activity is authorized and legitimate.
*   Implement strong access control policies and regularly review Kubernetes configurations to minimize the attack surface and prevent unauthorized access to sensitive resources.
*   Monitor Kubernetes audit logs for suspicious activity and enforce multi-factor authentication to protect against credential compromise.
