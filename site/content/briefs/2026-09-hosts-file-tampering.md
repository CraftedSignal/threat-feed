---
title: Detection of Unauthorized Hosts File Modifications
slug: 2026-09-hosts-file-tampering
description: Adversaries manipulate endpoint hosts files to intercept network traffic, enabling malicious infrastructure redirection or the disruption of security services such as MFA.
date: "2026-09-18T19:18:32Z"
lastmod: "2026-09-19T13:14:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - impact
  - persistence
  - cross-platform
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: Adversaries may modify the hosts file on endpoints to redirect network traffic, potentially routing traffic to malicious infrastructure.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/impact_hosts_file_modified.toml
rules:
  - title: Detect Unauthorized Modification of Hosts File
    description: Detects unauthorized modifications to the hosts file which can be used to redirect network traffic for malicious purposes.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1565.001
    data_sources:
      - file_event
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy hosts file monitoring rules
      owner: Detection Engineering
      due: 48h
  mitigation_plan:
    - priority: medium_term
      action: Implement strict access controls on the hosts file path
      owner: IT Operations
updates:
  - at: "2026-09-19T13:14:35Z"
    level: L1
    summary: OS windows; OS linux; OS macos
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/impact_hosts_file_modified.toml
---

Modifying the hosts file is a persistent technique used by attackers to gain control over local hostname resolution. By acting as the first point of lookup before external DNS, a compromised hosts file allows adversaries to reroute legitimate traffic to malicious IP addresses. This technique has been observed in the wild where actors targeted domain controllers to intercept and redirect multi-factor authentication (MFA) requests. By pointing MFA validation traffic to localhost, attackers can trigger security "fail open" conditions, effectively disabling MFA for active domain accounts. This impact extends across Windows, Linux, and macOS environments, making it a critical area for detection engineering to monitor, particularly where security services rely on clear network paths to reach authentication providers.

## Impact

Successful manipulation of the hosts file can lead to the silent redirection of sensitive organizational traffic, resulting in credential harvesting, man-in-the-middle attacks, or the bypass of critical security controls like MFA. Impact is high in environments where security policies default to "fail open" states when authentication services are unreachable.

## Recommendation

- Implement file integrity monitoring on the hosts file path across all supported operating systems.
- Deploy the Sigma rules below to monitor for unauthorized modifications to the hosts file.
- Review and tune the exclusion list for benign management tools (e.g., configuration management agents, local service scanners) to minimize noise.
- Investigate the parent process tree for any process found modifying the hosts file to determine the initial access vector.
