---
title: DKIM Signature Forgery Vulnerability in hMailServer
slug: 2026-10-hmailserver-dkim-spoof
description: Progressive Robot hMailServer 6.0.0 through 6.3.6 contains a vulnerability allowing unauthenticated remote attackers to forge DKIM-signed emails for hosted domains via improper verification of sender identity during the signing process.
date: "2026-10-19T18:09:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:progressiverobot:hmailserver:6.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:progressiverobot:hmailserver:6.3.6:*:*:*:*:*:*:*
vendors:
  - Progressive Robot
products:
  - hMailServer (6.0.0 through 6.3.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: A remote unauthenticated attacker can supply arbitrary inbound mail with a spoofed 'From' header, which the server will then sign using the hosted domain's DKIM key.
    confidence_band: high
cves:
  - id: CVE-2026-107567
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107567
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade hMailServer to a version containing the fix for CVE-2026-107567.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-107567
  mitigation_plan:
    - priority: immediate
      action: Disable DKIM signing for hosted domains that utilize external mail forwarding or aliases.
      owner: IT Operations
      addresses: CVE-2026-107567
      evidence: Vulnerability requires DKIM signing enabled to facilitate the forgery.
---

Progressive Robot hMailServer versions 6.0.0 through 6.3.6 suffer from a critical flaw in their DKIM signing implementation. When DKIM signing is enabled for a hosted domain, the mail server applies a cryptographic signature to all outgoing messages based on the 'From' header, prior to verifying the authenticity of the sender. This logic applies to any inbound message, including those submitted by unauthenticated remote sources. 

An attacker can craft an email with an arbitrary 'From' address belonging to a domain hosted by the vulnerable server. The server, failing to perform sender verification before the signature process, cryptographically signs the malicious message using the domain's private DKIM key. If the mail server is configured with forwarding rules, aliases, distribution lists, or Sieve redirects that result in the message being relayed to external recipients, the forged message will pass DKIM and DMARC alignment checks, significantly increasing the probability of successful phishing and social engineering attacks.

## Attack Chain

1. Attacker identifies a target organization using a vulnerable version of hMailServer (6.0.0 - 6.3.6) with DKIM signing enabled.
2. Attacker confirms the target domain utilizes forwarding, aliases, or distribution lists that relay mail to external addresses.
3. Attacker sends a malicious email via SMTP to the hMailServer, setting the 'From' header to a spoofed address within the target domain.
4. hMailServer receives the inbound message and performs the DKIM signing process based solely on the unverified 'From' header.
5. The server appends a valid cryptographic signature corresponding to the target domain’s DKIM key to the malicious email.
6. The server processes the email through its configured routing (e.g., mail rule or forward) and relays the signed, forged message to an external recipient.
7. The external recipient's mail infrastructure performs SPF/DKIM/DMARC validation, which passes successfully due to the valid (but forged) signature.
8. Recipient consumes the phishing email, resulting in unauthorized access or credential theft.

## Impact

Successful exploitation enables attackers to bypass email authentication mechanisms, allowing them to send highly credible phishing emails that appear to originate from legitimate domains hosted on the affected infrastructure. This facilitates business email compromise (BEC), credential theft, and the distribution of malicious payloads to external users. The vulnerability impacts organizations relying on hMailServer for mail delivery, specifically those utilizing automated forwarding or external aliases.

## Recommendation

1. Patch immediately: Upgrade hMailServer to a version beyond 6.3.6 that implements sender authentication prior to the DKIM signing process.
2. Configuration mitigation: If an immediate upgrade is not possible, disable DKIM signing for domains that utilize forwarding, aliases, or distribution lists that relay mail externally, until the patch is applied.
3. Security policy: Enable 'SmtpAuthenticatedSenderCheck' in the hMailServer configuration to force authentication checks on envelope addresses, though this does not fully mitigate the risk of signing forgeries based on the 'From' header.
4. Monitoring: Monitor email logs for unusual spikes in forwarded messages or relay activity originating from unauthenticated sources that utilize domain-specific DKIM keys.
