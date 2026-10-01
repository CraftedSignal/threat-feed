---
title: TA419 China-Aligned Credential Phishing Against US AI Policy Experts
slug: 2026-10-ta419-phishing
description: China-aligned actor TA419 is conducting targeted, long-tail credential phishing campaigns against US and Japanese AI policy and national security experts using AitM techniques and a custom Frameless BitB toolkit to capture MFA-protected Microsoft 365 sessions.
date: "2026-10-01T10:33:30Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TA419
tags:
  - phishing
  - aitm
  - espionage
  - credential-theft
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: TA419 followed up with a multi-stage URL redirection chain that led to an Adversary-in-the-Middle (AitM) credential phish.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: The group used a customized version of the open-source Browser-in-the-Browser (BitB) phishing tool Frameless BitB.
    confidence_band: high
references:
  - https://www.proofpoint.com/us/blog/threat-insight/hallucinating-credibility-china-aligned-ta419-impersonates-its-way-us-ai-policy
iocs:
  - type: email
    value: leparker@mail.com
  - type: email
    value: hcrediker@mail.com
  - type: email
    value: hcrediker@outlook.com
  - type: domain
    value: driftshare.co
  - type: domain
    value: globalfileshareplatform.com
  - type: ip
    value: 108.61.163.187
ioc_counts:
  domain: 2
  email: 3
  ip: 1
---

TA419 is an espionage-motivated threat actor that has been targeting individuals in the defense, energy, and AI policy sectors since at least April 2025. In July 2026, the group launched targeted campaigns against US think tanks and academic experts, impersonating former government officials and subject matter experts. The threat actor employs a low-and-slow approach, beginning with benign social engineering to build rapport before introducing malicious links. Their infrastructure leverages Cloudflare for traffic obfuscation and NameSilo for domain registration. The actor has been observed using actor-controlled VPS infrastructure, identified by a common self-signed TLS certificate (O=Castro Inc), to send phishing emails. This campaign aligns with broader Chinese intelligence objectives concerning AI regulation, supply chain security, and export controls.

## Attack Chain

1. TA419 sends a benign "conversation starter" email posing as a subject matter expert, inviting the target to join a fictitious advisory committee or contribute to a policy report.
2. Upon receiving a response, the attacker sends a shortened URL link that leads to a first-stage redirect domain (e.g., driftshare[.]co).
3. The first-stage domain performs a Cloudflare Turnstile verification hidden behind a fake OneDrive loading screen to filter automated security scanners.
4. The target is redirected to a second-stage, actor-controlled domain (e.g., globalfileshareplatform[.]com) hosting an Adversary-in-the-Middle (AitM) phishing page.
5. The AitM proxy relays the legitimate Microsoft /common/oauth2/v2.0/authorize request to Microsoft 365 servers in real time.
6. The proxy injects malicious scripts (/secondary/script.js and /secondary/observe.js) into the proxied page to facilitate the Frameless BitB overlay and capture telemetry.
7. The target completes the legitimate authentication process, including MFA, while the Frameless BitB toolkit captures the session token and auto-submits one-time codes.
8. The attacker uses the stolen session cookies for persistent access to the victim's cloud account.

## Impact

The campaign targets sensitive US AI policy development, including reports on supply chains and export controls. Successful compromise allows TA419 to gain persistent, unauthorized access to cloud-based email and documents, potentially leading to the theft of internal strategy documents, communications with policy experts, and pre-publication research.

## Recommendation

1. Enforce phishing-resistant, origin-bound authentication such as FIDO2/WebAuthn-based security keys (passkeys) for all Microsoft 365 and Entra ID accounts to render AitM session harvesting ineffective.
2. Review and audit Entra ID sign-in logs for anomalous user-agent strings or impossible travel patterns associated with successful logins that bypassed standard MFA.
3. Configure email gateways to flag or quarantine emails with links that redirect through known low-reputation domain registrars or temporary file-sharing domains.
4. Train high-value policy experts to verify the identity of unknown subject-matter outreach through independent, out-of-band communication channels.
5. Monitor egress traffic for connections to the identified redirect and phishing infrastructure listed in the IOC table.
