---
title: Juju Resource Poisoning Vulnerability Allows Unauthorized Resource Modification
slug: 2026-04-juju-resource-poisoning
description: An authenticated user, machine, or controller within a Juju controller can modify application resources due to a lack of authorization checks, potentially leading to resource poisoning and privilege escalation by uploading malicious resources.
date: "2026-04-04T12:00:00Z"
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

A resource poisoning vulnerability exists within Juju, a cloud orchestration tool. Any authenticated user, machine, or controller operating under a Juju controller can exploit this vulnerability to modify the resources of an application within the entire controller. The vulnerability stems from insufficient authorization checks in the resource handler, allowing unauthorized PUT and GET requests. A compromised workload with machine credentials can modify OCI resources for other models in the…
