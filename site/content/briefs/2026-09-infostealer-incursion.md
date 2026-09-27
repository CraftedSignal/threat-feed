---
title: Infostealer Incursion Targeting Cloud and AI Credentials
slug: 2026-09-infostealer-incursion
description: Prolific infostealer families like Lumma, RedLine, and Vidar are leveraging industrialized malware-as-a-service to exfiltrate session tokens and API keys, enabling bypass of MFA and unauthorized access to cloud, code, and AI environments.
date: "2026-09-27T08:15:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - infostealer
  - cloud-security
  - credential-theft
  - mfa-bypass
vendors:
  - Amazon
  - Microsoft
  - Google
  - GitHub
  - GitLab
  - OpenAI
products:
  - AWS
  - Azure
  - Google Cloud Platform
  - GitHub
  - GitLab
  - OpenAI
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: Spearphishing Attachment
    evidence: The path to cloud compromise starts on an end-user device... infected by an infostealer.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555.003
    technique_name: Credentials from Web Browsers
    evidence: Session cookies are typically extracted from each browser's on-disk cache. In modern browsers, they can also be retrieved directly from memory.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: Credentials in Files
    evidence: Long-term IAM access keys, which are frequently stored in plain text in configuration files or source code on developer workstations.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - SOC
    - Identity and Access Management
  immediate_actions:
    - action: Review and audit endpoint security configurations on developer workstations.
      owner: SOC
      due: 48h
  hunt_leads:
    - lead: Identify workstation processes attempting to access sensitive credential paths in %USERPROFILE%.
      technique_id: T1552.001
      priority: high
      confidence: high
      disposition: hunt_now
  mitigation_plan:
    - priority: immediate
      action: Transition from hardcoded credential files to short-lived identity federation or hardware-backed tokens.
      owner: Identity and Access Management
---

Wiz Research, in partnership with NordStellar, has identified a commoditized cybercrime ecosystem where infostealer malware families such as Lumma, RedLine, and Vidar facilitate unauthorized access to enterprise environments. These malware families are distributed via Malware-as-a-Service (MaaS) platforms and target developer endpoints through social engineering and trojanized software. By scraping browser caches, memory, and local configuration files, these tools extract high-value assets including AWS/GCP access keys, session cookies, and API tokens. The stolen data is subsequently sold through Initial Access Brokers to ransomware cartels and other adversaries. Attackers utilize these credentials to bypass multi-factor authentication (MFA) and gain privileged access to cloud infrastructure, CI/CD pipelines, and AI platforms like OpenAI, posing significant risks to sensitive corporate data and service integrity. The prevalence of these threats highlights the critical need to secure developer workstations and treat local credential storage as a primary attack surface.

## Attack Chain

1. Initial delivery via phishing, social engineering, or trojanized software (e.g., gaming tools, malicious software dependencies).
2. Execution of infostealer binary (e.g., abuse of legitimate binaries like vbc.exe) on the target's workstation.
3. Malware scans the file system for sensitive CLI configuration files (e.g., ~/.aws/credentials, ~/.git-credentials).
4. Malware performs memory scraping or debugger attachment on browser processes to extract active session tokens and cookies.
5. Exfiltration of harvested credentials, tokens, and API keys to adversary-controlled C2 servers.
6. Adversary imports stolen session cookies into their own browser to hijack authenticated sessions and bypass MFA.
7. Adversary authenticates to target cloud consoles (AWS, Azure, GCP) or development platforms (GitHub, GitLab) as the legitimate user.
8. Execution of post-compromise activity, including resource modification, exfiltration, or unauthorized use of AI services.

## Impact

The impact involves widespread compromise of enterprise cloud estates, CI/CD pipelines, and AI service accounts. With AWS and GCP accounting for nearly 60% of stolen secrets, attackers gain broad administrative or operational control over cloud infrastructure. The extraction of AI credentials allows for illicit LLM usage, while access to development tokens enables code exfiltration and potential supply chain poisoning. Organizations face significant operational risks, including data breaches, unauthorized cloud resource usage, and long-term persistence in CI/CD environments.

## Recommendation

1. Implement automated scanning on developer workstations to detect and alert on the presence of unencrypted credential files (e.g., ~/.aws/credentials, ~/.git-credentials).
2. Enforce the use of hardware-backed security keys or OS-level keychains (e.g., Granted) to prevent plain-text storage of credentials.
3. Monitor cloud identity logs for impossible travel or session hijacking indicators that suggest the use of stolen session tokens.
4. Implement strict egress filtering on developer endpoints to prevent unauthorized communication with known MaaS C2 infrastructure.
5. Audit CI/CD pipelines for hardcoded tokens and rotate all environment variables used for deployment processes.
