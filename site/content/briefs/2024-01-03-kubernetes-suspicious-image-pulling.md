---
title: Kubernetes Suspicious Image Pulling Detection
slug: 2024-01-03-kubernetes-suspicious-image-pulling
description: This analytic detects suspicious image pulling in Kubernetes environments by monitoring Kubernetes audit logs for image pull requests that do not match a predefined list of allowed images, potentially indicating malicious software deployment or system infiltration.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - image-pulling
  - anomaly-detection
  - cloud
vendors:
  - Kubernetes
  - Amazon
products:
  - Kubernetes
  - Amazon Elastic Kubernetes Service
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1526
    technique_name: Native Cloud Management Command Line Interface
references:
  - https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
  - https://github.com/splunk/security_content/blob/main/detections/cloud/kubernetes_suspicious_image_pulling.yml
  - https://github.com/signalfx/splunk-otel-collector-chart/blob/main/docs/migration-from-sck.md
  - https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
  - https://splunk.github.io/splunk-add-on-for-amazon-web-services/CloudWatchLogs/
rules:
  - title: Detect Kubernetes Suspicious Image Pulling
    description: Detects suspicious image pulling activities in Kubernetes by identifying image pull requests that do not match a predefined list of allowed images.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1526
    data_sources:
      - webserver
      - linux
  - title: Detect Kubernetes Image Pulling from Unusual User Agent
    description: Detects Kubernetes image pulling using an unusual or suspicious user agent string.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1526
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This detection focuses on identifying unauthorized or suspicious image pulling activities within a Kubernetes cluster. By monitoring Kubernetes audit logs, the detection triggers when an image pull request is made for an image not present in a predefined list of allowed images. This activity can indicate an attacker attempting to deploy malicious containers, escalate privileges, or infiltrate the system. The scope of targeting is any Kubernetes environment where audit logging is enabled. The detection leverages Kubernetes audit logs and a predefined list of approved images to identify anomalous behavior. Successfully identifying and responding to these events is critical for maintaining the integrity and security of the Kubernetes environment.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access to the Kubernetes cluster, potentially through compromised credentials or a vulnerable application.
2.  **Discovery:** The attacker enumerates available resources within the cluster, identifying potential targets for malicious container deployment.
3.  **Image Selection:** The attacker identifies or crafts a malicious container image to deploy within the Kubernetes environment. This image may contain malware, backdoors, or tools for lateral movement.
4.  **Image Pull Request:** The attacker attempts to pull the malicious image from a registry into the Kubernetes cluster using `kubectl` or similar tools. This action generates an audit log entry.
5.  **Detection Trigger:** The detection analytic compares the requested image against a list of allowed images. Because the malicious image is not on the allow list, the detection triggers.
6.  **Container Deployment:** If the image pull is successful, the attacker deploys the container within the Kubernetes cluster. This may involve creating a new pod, deployment, or other Kubernetes resource.
7.  **Lateral Movement:** Once the malicious container is running, the attacker uses it to move laterally within the cluster, compromising other pods, services, or nodes.
8.  **Impact:** The attacker achieves their objective, such as data exfiltration, denial of service, or complete control of the Kubernetes cluster.

## Impact

A successful attack resulting from suspicious image pulling can have severe consequences. Unauthorized access to sensitive data, deployment of malicious workloads, and lateral movement within the cluster are all potential outcomes. The number of affected systems and the scope of the damage depends on the attacker's objectives and the extent of their access. If the attack succeeds, it can lead to significant financial losses, reputational damage, and disruption of critical services.

## Recommendation

*   Enable and configure Kubernetes audit logging to capture all API server requests. Reference: "Kubernetes Audit" data source.
*   Implement the provided Sigma rule `Detect Kubernetes Suspicious Image Pulling` to identify unauthorized image pulls in your Kubernetes environment.
*   Create and maintain a comprehensive list of allowed images (`kube_allowed_images`) within your SIEM to minimize false positives.
*   Use the Splunk OpenTelemetry Collector for Kubernetes to collect the logs. https://github.com/signalfx/splunk-otel-collector-chart/blob/main/docs/migration-from-sck.md
*   When you want to use this detection with AWS EKS, you need to enable EKS control plane logging https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html. Then you can collect the logs from Cloudwatch using the AWS TA https://splunk.github.io/splunk-add-on-for-amazon-web-services/CloudWatchLogs/.
