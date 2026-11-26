---
brief_id: brief-2026-11-26-artex-consoles
event_id: brief-2026-11-26-artex-consoles
revision: 1
activity_at: "2026-11-26T12:36:48Z"
title: 'ARTEX AI Penetration Testing Framework: U.S. Infrastructure Exposure and Trojanized Builds'
slug: 2026-11-artex-consoles
description: Researchers identified 916 live ARTEX autonomous penetration-testing consoles on U.S. infrastructure, including trojanized variants providing unauthenticated root access.
date: "2026-11-26T12:36:48Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Content verified against SOCRadar intelligence
tags:
  - ai-security
  - supply-chain
  - infrastructure-exposure
products:
  - AntiFox
  - ARTEX (all versions)
  - BoomInner
  - SHRIKE
  - Sub2API
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The same framework, exposed the same way, has also turned up in documented intrusions, and a trojanized build circulating on Docker Hub gives anyone who knows a secret marker a pre-authentication root shell on the console host.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A console captured in separate research shows 1.2 million LLM tokens consumed on a task, 28 asset nodes and an activity feed with an automated WebFetch against a malware repository.
    confidence_band: high
references:
  - https://socradar.io/blog/artex-ai-pentest-consoles-us/
  - https://censys.com/blog/artex-agentic-asbestos
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
    - Detection Engineering
  hunt_leads:
    - lead: Identify externally exposed HTTP services on ports 8787 or 8790
      technique_id: T1190
      data_needed:
        - Network scanner data
        - Edge firewall logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 896 of the 916 consoles are served over plain HTTP.
    - lead: Check Docker host environments for 'tomicdd/artex' or 'congdonglinux/artex' images
      technique_id: T1195
      data_needed:
        - Docker image manifest logs
        - Container inventory data
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Trojanized Docker images tomicdd/artex and congdonglinux/artex.
  mitigation_plan:
    - priority: immediate
      action: Ensure all ARTEX console instances are behind authenticated proxies or VPNs
      owner: IT Operations
      addresses: ARTEX console exposure
      evidence: 896 of the 916 consoles are served over plain HTTP.
---

## Overview
ARTEX is an open-source, LLM-driven autonomous penetration-testing framework that has been identified in large-scale deployments on U.S. commercial hosting. As of November 11, 2026, researchers confirmed 916 live ARTEX-family consoles in the United States. While the legitimate software is intended for authorized security testing, the framework is being used in documented intrusions. A critical supply-chain risk exists via trojanized Docker images (specifically 'tomicdd/artex' and 'congdonglinux/artex') which contain a hardcoded backdoored login handler, granting unauthenticated root shell access to the host.

## Impact
The exposure of these consoles represents a significant attack surface, as many are served over plain HTTP and likely feature misconfigurations. Trojanized deployments enable unauthorized actors to gain full administrative control over the underlying host. The high concentration of instances within specific IP blocks suggests coordinated or templated deployments rather than independent adoption.

## Recommendation
- Identify and audit any internal or cloud-hosted ARTEX, AntiFox, BoomInner, or SHRIKE consoles; prioritize removing or securing instances running on default ports 8787 and 8790.
- Verify the integrity of Docker images used for penetration testing platforms; restrict pulls to trusted, internal registries rather than public Docker Hub repositories.
- Implement network egress filtering for servers running penetration testing frameworks to prevent unauthorized automated tool usage or C2 communication.
- Monitor logs for unauthorized access attempts or unusual API activity, particularly for servers also running the 'Sub2API' gateway.
