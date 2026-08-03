---
title: Detection of External IP Discovery via Curl on macOS
slug: 2026-08-macos-curl-discovery
description: Threat actors utilize curl or nscurl on macOS to query public IP geolocation services for reconnaissance, enabling them to assess network context and stage follow-on malicious activity.
date: "2026-08-03T11:53:16Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - macos
  - discovery
  - reconnaissance
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
    evidence: Malware commonly performs this action during reconnaissance to assess potential targets and identify the victim's external IP address.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/discovery_external_ip_address_discovery_via_curl.toml
iocs:
  - type: domain
    value: ipinfo.io
ioc_counts:
  domain: 1
rules:
  - title: Detect External IP Address Discovery via Curl
    description: Detects macOS processes launching curl or nscurl to query common public IP lookup services from potentially untrusted parents or unusual locations.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1016.001
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to detect suspicious curl reconnaissance
      owner: Detection Engineering
      due: 7d
      evidence: Source provided discovery detection logic
  hunt_leads:
    - lead: Search for curl/nscurl execution with short command lines pointing to public IP services
      technique_id: T1016.001
      data_needed:
        - process_creation logs with CommandLine
      priority: low
      confidence: medium
      disposition: convert_to_detection
      evidence: Elastic detection-rules repository
  mitigation_plan:
    - priority: medium_term
      action: Tighten macOS app execution controls and restrict curl context
      owner: IT Operations
      addresses: T1016.001
      evidence: Source investigation guide
---

Adversaries targeting macOS endpoints frequently engage in reconnaissance to identify the victim's external-facing IP address and network environment. This process is commonly automated by scripts or dropped binaries that invoke the built-in curl or nscurl utilities to query various public "what is my IP" and geolocation services. By understanding the host's external network context, attackers can tailor subsequent C2 communications, routing, or staging decisions based on the target's geography or ISP. This behavior is often observed originating from unsigned processes, temporary file locations (e.g., /private/var/folders), or suspicious parent shell processes (bash/zsh) containing network-related command line arguments. Identifying this activity early can help defenders block unauthorized reconnaissance before deeper persistence or data exfiltration occurs.

## Impact

Successful reconnaissance allows attackers to map the network infrastructure of the target, increasing the likelihood of successful C2 establishment and targeted exploitation. While the discovery action itself is low-impact, it is a precursor to more severe activities such as credential theft, lateral movement, and unauthorized exfiltration, potentially affecting any enterprise environment where macOS endpoints are present.

## Recommendation

- Deploy the provided Sigma rule to monitor for suspicious curl executions; tune for administrative diagnostic scripts and known legitimate telemetry tools used in the environment.
- Monitor process-creation events for curl or nscurl spawned by untrusted or unsigned parent applications.
- Block egress access to known public IP lookup domains (e.g., ipify.org, ipinfo.io) from unauthorized or suspicious processes at the network edge or DNS resolver.
- Review endpoints for indicators of persistence (e.g., LaunchAgents, cron jobs) if suspicious IP discovery is confirmed, as this often indicates an active infection stage.
