---
title: Juju Resource Poisoning Vulnerability Allows Unauthorized Resource Modification
slug: 2026-04-juju-resource-poisoning
description: An authenticated user, machine, or controller within a Juju controller can modify application resources due to a lack of authorization checks, potentially leading to resource poisoning and privilege escalation by uploading malicious resources.
date: "2026-04-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - juju
  - resource-poisoning
  - privilege-escalation
  - cloud
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2025-68153
references:
  - https://github.com/advisories/GHSA-245v-p8fj-vwm2
rules:
  - title: Detect Unauthorized Juju Resource Modification
    description: Detects PUT requests to the Juju resource endpoint without valid authorization, indicating potential resource poisoning attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Malicious Resource Upload to Juju Controller
    description: Detects suspicious file uploads to Juju controller which may indicate resource poisoning
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1105
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A resource poisoning vulnerability exists within Juju, a cloud orchestration tool. Any authenticated user, machine, or controller operating under a Juju controller can exploit this vulnerability to modify the resources of an application within the entire controller. The vulnerability stems from insufficient authorization checks in the resource handler, allowing unauthorized PUT and GET requests. A compromised workload with machine credentials can modify OCI resources for other models in the controller, such as replacing a legitimate Docker image with a trojan horse version. This vulnerability affects Juju versions prior to the fix in commit 26ff93c903d5, specifically in the go/github.com/juju/juju package. This can have significant consequences, including privilege escalation and unauthorized access to sensitive information.

## Attack Chain

1.  Attacker gains initial access to a Juju controller as an authenticated user, machine, or controller. This could be via compromised credentials or a vulnerable workload already within the Juju environment.
2.  The attacker identifies the target model UUID, application name, and resource name they wish to poison. This information can be obtained through enumeration within the Juju environment or by leveraging publicly available charm information from Charmhub.
3.  The attacker crafts a malicious resource, such as a trojan horse Docker image, that has the same file extension as the original resource.
4.  The attacker sends a PUT request to the resource handler endpoint `/:modeluuid/applications/:application/resources/:resources` with the malicious resource.
5.  The Juju controller's resource handler, lacking proper authorization checks, accepts the malicious resource and overwrites the existing resource in its cache.
6.  When the target application attempts to retrieve the resource, it receives the poisoned version from the controller's cache.
7.  The poisoned resource is executed or deployed within the target application's environment, leading to compromise. In the case of a Docker image, this could lead to root access on the underlying system.
8.  The attacker leverages the compromised application (e.g., a Kubernetes vault) to access sensitive information, such as vault secrets, and further expand their access within the environment.

## Impact

This vulnerability allows an attacker to inject security vulnerabilities into other workloads managed by Juju. This can lead to privilege escalation, data breaches, and complete compromise of the Juju-managed environment. The most obvious impact is on deployments using OCI containers, where a malicious Docker image can grant an attacker execution escalation. In a Kubernetes environment managing vault secrets, an attacker could potentially gain root access to all vault secrets, seriously impacting the confidentiality and integrity of the data stored within. The specific impact depends on the type of resource poisoned and its role in the target application, but could be severe.

## Recommendation

*   Upgrade Juju to a version containing the fix for CVE-2025-68153 to address the underlying vulnerability.
*   Implement additional authorization checks and access controls within the Juju environment to restrict resource modification to authorized users and processes.
*   Enable and review Juju API server logs (category: webserver, product: linux) for suspicious PUT requests to resource handler endpoints, looking for unexpected resource modifications.
*   Deploy the Sigma rule "Detect Unauthorized Juju Resource Modification" to your SIEM to detect unauthorized PUT requests to Juju resource endpoints.
