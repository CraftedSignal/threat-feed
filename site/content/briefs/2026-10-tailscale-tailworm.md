---
brief_id: brief-2026-10-27-tailscale-tailworm
event_id: brief-2026-10-27-tailscale-tailworm
revision: 4
activity_at: "2026-10-28T16:58:30Z"
revision_history:
  - revision: 2
    at: "2026-10-27T16:40:44Z"
    checksum: sha256:e7c7b1bf34227b1df2dc0219a11cd770b031a52f7dc5ff4edb05a8535c96e354
    summary: OS linux
    changed_fields:
      - affected_os
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/tailscale-tailworm-ssh-forwarding-privesc
  - revision: 3
    at: "2026-10-28T07:33:18Z"
    checksum: sha256:c4c9e6efd05ac2612ab01b180ff7cb110138e197aa8c7677673c9be9d23daf00
    summary: added coverage for Tailscale (< 1.104.4) +1 products
    changed_fields:
      - action_plan
      - affected_os
      - affected_products
      - claim_state
      - content
      - lastmod
      - references
      - summary
      - tags
      - title
      - updates
    source_urls:
      - https://thehackernews.com/2026/10/tailscale-patches-ssh-flaws-that-could.html
  - revision: 4
    at: "2026-10-28T16:58:30Z"
    checksum: sha256:69a78b2701712c4c68218c19bf6750b17805da9c1deef5597f2f8a8dea7df134
    summary: new product
    changed_fields:
      - affected_products
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/tailscale-tailworm-ssh-forwarding-privesc
title: 'Tailscale: Privilege escalation and security flaws in SSH server'
slug: 2026-10-tailscale-tailworm
description: Tailscale versions prior to 1.104.4 contain multiple vulnerabilities in SSH socket forwarding and service handling that could allow authenticated users to escalate privileges to root on targeted nodes.
date: "2026-10-27T16:06:16Z"
lastmod: "2026-10-28T16:57:52Z"
type: advisory
claim_state: verified
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
  validation_status: Needs vendor patch verification and environment testing upon release.
tags:
  - privilege-escalation
  - lateral-movement
  - network-security
  - tailscale
vendors:
  - Tailscale
products:
  - Tailscale client (<= 1.104.2)
  - headscale (<= 0.29.5)
  - Tailscale (< 1.104.4)
  - headscale
  - Tailscale (<= 1.104.2)
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: In lab tests, this resulted in root access on target servers and the theft of keys that can be used to add rogue devices to the network.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.004
    technique_name: SSH
    evidence: Since no user credentials are involved, an automated attack chaining these bugs moved from machine to machine across every server the policy granted SSH access to.
    confidence_band: high
references:
  - https://www.securityweek.com/tailscale-rushes-patches-after-uncoordinated-disclosure-of-tailworm-flaws/
  - https://pwn.watch/i/tailscale-tailworm-ssh-forwarding-privesc
  - https://tailworm.com/
  - https://tailscale.com/ssh-investigation-update
  - https://tailscale.com/security-bulletins
  - https://github.com/tailscale/tailscale/releases/tag/v1.104.4
  - https://thehackernews.com/2026/10/tailscale-patches-ssh-flaws-that-could.html
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
    - IT Operations
  immediate_actions:
    - action: Disable SSH forwarding in Tailscale access policies
      owner: SOC
      due: 24h
      evidence: Tailscale advises organizations to review their SSH access policies and disable SSH forwarding where it isnt needed
    - action: Upgrade all Tailscale clients to 1.104.4.
      owner: IT Operations
      due: 48h
      evidence: Tailscale has released version 1.104.4 to fix flaws in its built-in SSH server.
    - action: Apply TS_SSH_DISABLE_FORWARDING=1 to tailscaled service environment for servers unable to patch.
      owner: IT Operations
      due: 24h
      evidence: If you cannot update a server yet, you can turn off SSH forwarding on it by setting TS_SSH_DISABLE_FORWARDING=1.
  hunt_leads:
    - lead: Identify unusual SSH sessions originating from unexpected nodes within the Tailscale mesh
      technique_id: T1021.004
      data_needed:
        - Tailscale/Headscale audit logs
        - SSH connection telemetry
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: automated attack chaining these bugs moved from machine to machine across every server
    - lead: Monitor Tailscale audit logs for unusual SSH session attempts or forwarded socket connections from low-privilege accounts.
      technique_id: T1021.004
      data_needed:
        - Tailscale audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The flaws are in how Tailscale SSH forwards network connections.
  mitigation_plan:
    - priority: immediate
      action: Apply Tailscale client and headscale security patches once released
      owner: IT Operations
      addresses: Tailworm vulnerabilities
      evidence: Tailscale is getting ready to ship a client update that addresses privilege escalation weaknesses
    - priority: immediate
      action: Enforce principle of least privilege in Tailscale ACLs/policy files to restrict device-to-device access.
      owner: IT Operations
      addresses: Lateral movement risk
      evidence: Tailscale also recommends reviewing SSH access rules so that only the users and devices that need access have it.
updates:
  - at: "2026-10-27T16:40:11Z"
    level: L1
    summary: OS linux
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/tailscale-tailworm-ssh-forwarding-privesc
  - at: "2026-10-28T07:32:38Z"
    level: L1
    summary: added coverage for Tailscale (< 1.104.4) +1 products
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/10/tailscale-patches-ssh-flaws-that-could.html
  - at: "2026-10-28T16:57:52Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/tailscale-tailworm-ssh-forwarding-privesc
---

Tailscale has released version 1.104.4 to address four security bulletins (TS-2026-014, TS-2026-015, TS-2026-016, and TS-2026-017) affecting its built-in SSH server. The primary vulnerability involves a timing-based socket-forwarding flaw where an attacker with existing network access can perform a socket-swap, allowing them to interact with root-privileged Unix sockets such as the Docker control socket or the tailscaled local API. Additional vulnerabilities include a denial-of-service vector via memory exhaustion, unauthorized local API access in tailscale serve, and potential permission header leakage. These flaws do not allow for unauthenticated access, requiring an attacker to already possess a foothold on a device authorized by the network access policy. No CVE identifiers have been assigned at this time.

## Impact

Successful exploitation could allow an attacker to gain root-level access to sensitive local services on a target node. The flaws are limited by existing network access policies; attackers can only target machines that their current policy already permits them to reach.

## Recommendation

- Update all Tailscale client installations to version 1.104.4 or later immediately.
- If immediate patching is not possible, disable SSH forwarding by setting the environment variable 'TS_SSH_DISABLE_FORWARDING=1' in the tailscaled service configuration.
- Review network access rules to ensure minimal privilege, as compromised devices can move laterally to any node permitted by the policy.
- For headscale users, acknowledge that SSH forwarding should be treated as root-level access until a fix is available, as the current version does not support disabling this functionality.
