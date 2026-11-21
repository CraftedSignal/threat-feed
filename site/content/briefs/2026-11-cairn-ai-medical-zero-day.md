---
brief_id: brief-2026-11-21-cairn-ai-medical-zero-day
event_id: brief-2026-11-21-cairn-ai-medical-zero-day
revision: 1
activity_at: "2026-11-21T13:04:38Z"
title: MONAI Label Path Traversal Vulnerability Exploited by AI Agents
slug: 2026-11-cairn-ai-medical-zero-day
description: A China-linked threat actor used autonomous Cairn AI agents to discover and exploit a critical path traversal zero-day vulnerability in MONAI Label to achieve root-level code execution.
date: "2026-11-21T13:04:38Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - Unidentified Chinese-nexus threat actor
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.securityweek.com/amazon-china-linked-hackers-ai-agents-exploited-medical-software-zero-day/
  observed_at: "2026-09-01T00:00:00Z"
  confidence: high
source_assessment:
  reliability: C
  credibility: "2"
  rating: C2
  likelihood: likely
products:
  - MONAI Label
references:
  - https://www.securityweek.com/amazon-china-linked-hackers-ai-agents-exploited-medical-software-zero-day/
---

## Overview
Amazon threat intelligence researchers identified a campaign in September 2026 where a China-linked threat actor utilized autonomous AI agents operating via the Cairn open source penetration testing framework to exploit a critical path traversal vulnerability in MONAI Label. The researchers discovered the activity after observing an unauthenticated instance of the Cairn framework.

## Attack Chain
1. Reconnaissance and Access: The threat actor utilized AI agents to target university networks in East Asia. The agents were instructed to obtain shell access.
2. Vulnerability Discovery: The agents mapped the application API of MONAI Label and identified a path traversal bug in a file upload function.
3. Exploitation: The agents used the vulnerability to write arbitrary files to the server. In one instance, the agents planted a Python reverse shell in a file that executes upon Python interpreter startup to achieve a root shell.
4. Lateral Movement: The actor utilized a proxy on a compromised host to tunnel into a second network and target additional devices running the same vulnerable software.

## Impact
Successful exploitation allows for arbitrary file writes and root-level code execution. The vulnerability enables any user who can reach the server over the network to exploit it, as authentication is disabled by default.

## Recommendation
MONAI Label versions 0.8.5 and earlier are affected. A fix has been created and will be included in the next release of the software.
