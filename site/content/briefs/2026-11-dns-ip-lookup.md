---
brief_id: brief-2026-11-10-dns-ip-lookup
event_id: brief-2026-11-10-dns-ip-lookup
revision: 1
activity_at: "2026-11-10T02:45:31Z"
title: Suspicious DNS Queries for Public IP Lookup Services
slug: 2026-11-dns-ip-lookup
description: Adversaries and malware frequently perform network reconnaissance by querying external public IP geolocation and identification services to determine the public-facing identity of an infected host.
date: "2026-11-10T02:45:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Detection rule ready for environment-specific tuning.
tags:
  - reconnaissance
  - dns
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1590
    technique_name: Gather Victim Network Information
    evidence: Adversaries often perform network reconnaissance by querying external public IP identification services.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_susp_external_ip_lookup.yml
  - https://web.archive.org/web/20230129100828/https://www.binarydefense.com/analysis-of-hancitor-when-boring-begets-beacon
  - https://www.trendmicro.com/en_us/research/23/e/managed-xdr-investigation-of-ducktail-in-trend-micro-vision-one.html
rules:
  - title: Detect Suspicious DNS Query for IP Lookup Service APIs
    description: Detects DNS queries for common public IP lookup services (e.g., api.ipify.org, checkip.amazonaws.com) originating from non-browser processes.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1590
    data_sources:
      - dns_query
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection for DNS-based IP lookup discovery.
      owner: Detection Engineering
      due: 7d
      evidence: Source provides a comprehensive list of known IP lookup APIs.
  hunt_leads:
    - lead: Identify non-browser processes communicating with known IP discovery services via DNS logs.
      technique_id: T1590
      data_needed:
        - DNS query logs including process image path
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Observed behavior in malware such as Hancitor and Ducktail.
---

Adversaries and automated malware (such as Hancitor and Ducktail) often perform reconnaissance by querying public IP identification services to obtain the external IP address of a compromised system. While these services are legitimate, their usage by non-browser processes (e.g., background scripts, PowerShell, or command-line tools) is a common indicator of host discovery and beaconing activity during the early stages of an intrusion.

## Recommendation

- Deploy the Sigma rule below to detect unauthorized processes querying common IP lookup services.
- Baseline legitimate administrative scripts or internal agents that require external connectivity to identify public network egress points.
- Utilize DNS query logs to identify non-browser processes communicating with these common external discovery endpoints.
