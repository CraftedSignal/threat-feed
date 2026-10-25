---
brief_id: brief-2026-10-25-unitree-go2-rce
event_id: brief-2026-10-25-unitree-go2-rce
revision: 1
activity_at: "2026-10-25T00:27:09Z"
title: 'Unitree Robotics Unitree Go2: OS command injection in chat_go (CVE-2026-115995)'
slug: 2026-10-unitree-go2-rce
description: A security vulnerability in the Unitree Go2 component chat_go allows for remote OS command injection via the set_volume function.
date: "2026-10-25T00:27:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:unitree:go2:*:*:*:*:*:*:*:*
tags:
  - iot
  - vulnerability
  - rce
  - hardware
vendors:
  - Unitree Robotics
products:
  - Unitree Go2 (<= 1.1.11.4)
cves:
  - id: CVE-2026-115995
    cvss: 9.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115995
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Unitree Go2 firmware to 1.1.11.5
      owner: IT Operations
      evidence: Upgrading to version 1.1.11.5 is sufficient to resolve this issue.
---

A security vulnerability has been identified in the Unitree Go2 (versions up to 1.1.11.4). The vulnerability exists in the set_volume function within the gpt_thread.py file of the chat_go component. Manipulating the 'Value' argument leads to OS command injection (CWE-78). The attack can be launched remotely. The vendor has confirmed the issue via internal ticket #474.

## Recommendation
- Upgrade to version 1.1.11.5, which is sufficient to resolve this issue.
