---
title: AI-Automated Campaign Targeting Online Retailers
slug: 2026-09-ai-powered-retailer-attacks
description: A Chinese-speaking threat actor is leveraging a triad of autonomous AI agents (Strix, Cairn, and Hermes) to conduct vulnerability research, exploitation, and data exfiltration against hundreds of online retail platforms.
date: "2026-09-24T13:13:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ai-threats
  - financial-crime
  - web-application-security
vendors:
  - JBoss
  - Magento
products:
  - Magento (e-commerce platform)
  - JBoss (application server)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The campaign used the open source AI penetration testing tool Strix for vulnerability hunting.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The operator left a cron job in the JBoss log directory that checked the file size every two minutes and appended the skimmer again.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The hackers stole information from over 600,000 unexpired credit cards from two of the compromised companies.
    confidence_band: high
references:
  - https://www.securityweek.com/ai-powered-campaign-targets-hundreds-of-online-retailers/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Application Security
  immediate_actions:
    - action: Review web checkout bundles for unauthorized script injections.
      owner: Application Security
      due: 24h
      evidence: The skimmer was typically appended to a JavaScript file present on the website.
    - action: Audit cron jobs and scheduled tasks for unexpected entries in application directories.
      owner: SOC
      due: 24h
      evidence: Operator left a cron job in the JBoss log directory.
  hunt_leads:
    - lead: Search for automated, burst-like probing patterns originating from unfamiliar IP infrastructure.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The harness chose each attack path in real time through extensive probing.
  mitigation_plan:
    - priority: immediate
      action: Implement Content Security Policy (CSP) to restrict allowed domains for script execution.
      owner: Application Security
      addresses: Skimmer script injection
      evidence: Injection of skimmer scripts into online shops' checkout pages.
---

Since July 2026, a financially motivated, Chinese-speaking threat actor has been utilizing an advanced autonomous AI-driven attack stack to target online retailers. The campaign employs three specific AI harnesses to automate the attack lifecycle: Strix for vulnerability research, Cairn for attack orchestration, and Hermes for persistent management and tactical execution. The threat actor focuses on identifying vulnerabilities in custom web application code, often achieving full access within hours of initial contact.

The operation has achieved significant impact, compromising hundreds of entities and exfiltrating over 600,000 credit card records from at least two retailers. The attackers demonstrate advanced persistence capabilities, utilizing custom AI-generated skills to manipulate database contents, delete backups, and deploy skimmer scripts via diverse injection vectors, including cron jobs within JBoss environments and malicious script tags in web checkout bundles. The use of automated AI tooling allows the actors to operate at a marginal cost, scaling their operations against a wide range of retail targets.

## Attack Chain

1. Target identification using website traffic ranking services to select shops running custom code.
2. Vulnerability hunting performed by the 'Strix' AI harness via automated probing against targeted hosts.
3. Attack orchestration and exploitation path selection handled by the 'Cairn' autonomous penetration testing engine.
4. Initial access gained through identified web application vulnerabilities or the use of pre-existing stolen administrator credentials.
5. Persistence establishment via the 'Hermes' agent, which executes automated tasks like cron job creation in JBoss log directories or modifying Kubernetes initContainers.
6. Data exfiltration of credit card records directly from the target's database, followed by automated cleanup of evidence using agent-specific skills.
7. Injection of skimmer scripts into checkout pages, often using redundant persistence mechanisms to ensure the script persists after application redeployments.

## Impact

The campaign has impacted at least hundreds of online retailers, with concrete evidence of 600,000+ credit card records stolen, 488,000 of which originated from US-based victims. Targeted sectors include fashion retail, hospitality, industrial supply distribution, and airline services. If successful, the attacker gains full control over checkout processes, facilitating long-term financial fraud and the potential for complete data destruction through the agentic deletion of backups and database staging tables.

## Recommendation

1. Monitor web server logs and checkout page bundles for unauthorized script tag injections or changes to JavaScript files.
2. Implement strict monitoring for new, unauthorized cron jobs created within application directories, specifically targeting JBoss or similar middleware environments.
3. Conduct an audit of all administrative credentials for web retail platforms, rotating any passwords that have been exposed or are shared across multiple services.
4. Hunt for anomalous outbound traffic from application servers, as the autonomous agents require external connectivity to orchestrate tasks.
5. Harden database access controls to prevent unauthorized execution of deletion or exfiltration queries via compromised application identities.
