---
brief_id: brief-2026-11-12-silent-lynx-ai
event_id: brief-2026-11-12-silent-lynx-ai
revision: 1
activity_at: "2026-11-12T14:24:59Z"
title: 'Silent Lynx: Espionage operations using AI agents for automation'
slug: 2026-11-silent-lynx-ai
description: The threat actor Silent Lynx is utilizing an AI agent named Hermes to automate reconnaissance, data exfiltration, and log clearance during cyberespionage operations targeting Central Asian government infrastructure.
date: "2026-11-12T14:24:59Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Silent Lynx
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://therecord.media/kazakhstan-hackers-central-asia
  observed_at: "2026-11-12T14:24:59Z"
  confidence: high
source_assessment:
  reliability: C
  credibility: "2"
  rating: C2
  likelihood: likely
tags:
  - espionage
  - ai-enabled
  - data-exfiltration
  - central-asia
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The operator communicated with the agent in Russian and connected it to a Telegram bot, allowing the hacker to issue instructions remotely from a phone.
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The group developed automated tools to download large quantities of files, including thousands of documents sent to or processed by Tajikistan's Defense Ministry.
references:
  - https://therecord.media/kazakhstan-hackers-central-asia
action_plan:
  hunt_leads:
    - lead: Identify suspicious API traffic or persistent sessions originating from Telegram bot infrastructure communicating with internal systems, potentially indicating command-and-control via automated AI agents.
      technique_id: T1059
      data_needed:
        - Network flow logs
        - Proxy logs
        - EDR process execution logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The operator communicated with the agent in Russian and connected it to a Telegram bot, allowing the hacker to issue instructions remotely from a phone.
    - lead: Monitor for anomalous bulk file read/write activities or high-frequency access patterns on sensitive document repositories by automated scripts, particularly those targeting defense or government ministry directories.
      technique_id: T1005
      data_needed:
        - File access logs
        - Endpoint audit logs
        - DLP alerts
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The group developed automated tools to download large quantities of files, including thousands of documents sent to or processed by Tajikistan's Defense Ministry.
---

Silent Lynx, a hacking group previously associated with espionage campaigns across Central Asia, has been observed leveraging an AI agent named Hermes to facilitate malicious operations. CloudSEK researchers identified an exposed server containing stolen government documents and evidence that the group used the Hermes AI agent, powered by DeepSeek models, to automate tasks such as reconnaissance, data collection, and log erasure. The operator controls the agent via a Telegram bot, allowing for remote command execution. The group maintains access to government networks, with confirmed activity against the Tajikistan national railway and electronic document management systems, and evidence suggesting preparation for further phishing activity against Turkmenistan.

## Attack Chain

1. Initial access to government networks (e.g., Tajikistan national railway).
2. Deployment and interaction with the Hermes AI agent via a Telegram bot interface.
3. Automated reconnaissance, data collection, and log clearing using the AI agent.
4. Large-scale data exfiltration from government document management platforms.

## Impact

Silent Lynx compromised Tajikistan's national railway network and the country's electronic document management platform. Stolen materials include internal correspondence from the Defense Ministry, the National Guard, the State Committee for National Security, and the State Investment Committee, affecting over 100 government organizations. Evidence also indicates the compromise of a server supporting Uzbekistan's Smart Forestry initiative.

## Recommendation

- Monitor for anomalous mass-file transfer activity, specifically targeting large volumes of documents downloaded from internal management platforms.
- Monitor for unauthorized automated tools and script execution on critical infrastructure systems and internal file servers.
