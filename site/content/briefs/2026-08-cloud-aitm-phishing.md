---
title: Adversary-in-the-Middle Phishing via Legitimate Cloud Platforms
slug: 2026-08-cloud-aitm-phishing
description: Threat actors are increasingly abusing reputable PaaS providers to host multi-stage AitM phishing campaigns that use browser service workers and the Ultraviolet library to intercept credentials and MFA tokens.
date: "2026-08-04T13:40:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - aitm
  - cloud
  - credential-harvesting
vendors:
  - Cloudflare
  - Vercel
  - Netlify
  - GitHub
  - Microsoft
products:
  - Cloudflare Workers
  - Vercel
  - Netlify
  - GitHub Pages
  - IPFS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The attack typically begins with a phishing email that uses a plausible pretext — such as a request from a coworker to review documents — to entice the target into clicking a malicious link.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: Once the user successfully completed the challenge, a service worker was registered in their browser.
    confidence_band: high
references:
  - https://securelist.com/cloud-platforms-in-phishing/120832/
iocs:
  - type: domain
    value: workers.dev
ioc_counts:
  domain: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Review proxy logs for traffic to workers.dev and other PaaS subdomains.
      owner: SOC
      due: 48h
      evidence: Source identifies these as primary platforms for hosting phishing pages.
  mitigation_plan:
    - priority: medium_term
      action: Enforce phishing-resistant MFA (WebAuthn/FIDO2) for all users.
      owner: IT Operations
      addresses: AitM credential harvesting
      evidence: AitM attacks effectively bypass legacy MFA, necessitating phishing-resistant alternatives.
---

Threat actors are migrating phishing infrastructure to legitimate cloud platforms such as Cloudflare Workers, Vercel, Netlify, GitHub Pages, and IPFS. This strategy exploits the inherent trust associated with reputable CDN and cloud domains, allowing attackers to evade IP-based blocking and security filtering. By leveraging free-tier developer accounts that do not require identity verification, operators can scale malicious infrastructure rapidly. 

The core of these campaigns is a sophisticated Adversary-in-the-Middle (AitM) approach that uses browser-side service workers to intercept network requests. By utilizing the legitimate Ultraviolet proxy library, the phishing pages dynamically rewrite traffic in real-time, effectively bypassing traditional proxy-based security controls. This approach allows attackers to harvest login credentials and MFA tokens while the victim interacts with what appears to be a legitimate, HTTPS-secured website. The use of URL hash fragments to pass sensitive data between attack stages ensures that malicious parameters remain hidden from standard network-based detection systems.

## Attack Chain

1. Attackers deliver a phishing email containing a link to a compromised legitimate website.
2. The compromised website acts as a disposable relay to capture the victim's email address via a fake CAPTCHA.
3. The victim is redirected to a cloud-hosted subdomain (e.g., workers.dev) with the email address embedded in the URL hash.
4. The phishing page presents a genuine CAPTCHA challenge to confirm the victim is not a bot.
5. Upon success, a malicious service worker is registered in the browser to intercept all outgoing network requests.
6. The service worker injects the Ultraviolet library to create a transparent proxy that rewrites login forms.
7. The user enters credentials and MFA tokens, which are captured and proxied by the attacker's infrastructure.
8. The attacker uses the captured credentials and session tokens to gain unauthorized access to the target's account.

## Impact

Successful attacks result in full credential and MFA token compromise, leading to account takeover. Because these campaigns reside on reputable cloud subdomains, they successfully bypass many traditional reputation-based security filters. The infrastructure allows attackers to bypass MFA mechanisms by capturing session cookies, significantly increasing the risk to enterprise authentication environments.

## Recommendation

- Implement content-based analysis for web traffic to identify malicious JavaScript (e.g., unauthorized service worker registration) rather than relying solely on domain reputation.
- Monitor browser activity for the suspicious registration of service workers on domains that are not part of the organization's sanctioned enterprise application suite.
- Deploy FIDO2/WebAuthn-based phishing-resistant MFA, which inherently mitigates AitM credential harvesting attacks.
- Educate users on the risks of interacting with links that redirect through reputable cloud platforms (like workers.dev) when prompted for sensitive corporate credentials.
- Review proxy logs for traffic patterns associated with known browser-based proxy libraries like Ultraviolet.
