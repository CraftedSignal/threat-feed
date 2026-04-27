---
title: Incus Image Cache Poisoning Vulnerability
slug: 2024-01-incus-image-poisoning
description: A vulnerability exists in Incus where it does not properly verify the combined fingerprint when downloading images from simplestreams servers, allowing an attacker to perform image cache poisoning and potentially expose other tenants to running attacker-controlled images.
date: "2026-03-27T17:08:07Z"
severities:
  - medium
tags:
  - incus
  - image-poisoning
  - simplestreams
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
references:
  - https://github.com/advisories/GHSA-p8mm-23gg-jc9r
ioc_counts:
  domain: 1
  url: 2
rules:
  - title: Detect Suspicious Incus Image Download
    description: Detects network connections from Incus to non-standard image servers, indicating a potential image poisoning attempt.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588
    data_sources:
      - network_connection
      - linux
  - title: Detect Modified SquashFS Files
    description: Detects the presence of squashfs files with unexpected modifications in Incus instances, potentially indicating image tampering.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability in Incus allows for image cache poisoning when downloading images from simplestreams servers. The vulnerability stems from the lack of validation of the combined fingerprint of image files, potentially leading to a compromised image being served to other users. This issue affects Incus servers that have not configured `restricted.image.servers` or equivalent firewall rules, making them susceptible to this attack. An attacker with access to such an Incus environment can…
