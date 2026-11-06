---
brief_id: brief-2026-11-05-openssh-auth-bypass-97dae15e
event_id: brief-2026-11-05-openssh-auth-bypass-97dae15e
revision: 2
activity_at: "2026-11-06T00:51:17Z"
revision_history:
  - revision: 2
    at: "2026-11-06T00:51:17Z"
    checksum: sha256:6ec90a6ee784f511be8e186e07ed69fd23171e2833ec1665d978eeb76efa0911
    summary: OS alpine linux
    changed_fields:
      - affected_os
      - affected_products
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/alpine-openssh-musl-crypt-password-auth-bypass-nov-2026
title: 'OpenSSH: Password authentication bypass (CVE-2026-123158)'
slug: 2026-11-openssh-auth-bypass-97dae15e
description: CVE-2026-123158 is an authentication bypass vulnerability in OpenSSH running on Linux systems using musl libc without PAM, potentially allowing unauthorized access via long password submissions.
date: "2026-11-05T23:53:32Z"
lastmod: "2026-11-06T00:50:37Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - high
actors:
  - 0xBlackash
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*
vendors:
  - OpenBSD
products:
  - OpenSSH (< 10.6p2)
  - openssh-server
  - openssh-server-pam
affected_os:
  - Alpine Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authentication bypass in OpenSSH sshd on Linux without PAM using musl libc.
    confidence_band: high
cves:
  - id: CVE-2026-123158
    cvss: 8.1
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=BD6BCE9C-628A-5692-B6ED-917BA9E7D4E8
  - https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/
  - https://github.com/openssh/openssh-portable/commit/4353fdc43ef646c43a8dda7025cc1a898caf1482
  - https://sploitus.com/exploit?id=BD6BCE9C-628A-5692-B6ED-917BA9E7D4E8&utm_source=rss&utm_medium=rss
  - https://pwn.watch/i/alpine-openssh-musl-crypt-password-auth-bypass-nov-2026
  - https://www.openssh.org/releasenotes.html
  - https://www.openssh.org/txt/release-10.6p2
  - https://www.cve.org/CVERecord?id=CVE-2026-123158
  - https://sshhole.com
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123158
  - https://status.linode.com/incidents/fc9c3k1n3ph1
  - https://orca.security/resources/research/sshole-openssh-authentication-bypass-gives-attackers-root-on-alpine-linux/
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch OpenSSH to version 10.6p2 or higher on all identified Linux hosts using musl libc.
      owner: IT Operations
      due: 24h
      evidence: Official remediation guidance from OpenSSH and Alpine Linux.
  hunt_leads:
    - lead: Identify successful password authentication events for user accounts configured for key-based access.
      technique_id: T1190
      data_needed:
        - /var/log/messages or auth.log
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Review SSH authentication logs for Accepted password events.
  mitigation_plan:
    - priority: immediate
      action: Set PasswordAuthentication no in /etc/ssh/sshd_config.
      owner: IT Operations
      addresses: CVE-2026-123158
      evidence: Temporary mitigation provided by security advisory.
updates:
  - at: "2026-11-06T00:50:37Z"
    level: L1
    summary: OS alpine linux
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/alpine-openssh-musl-crypt-password-auth-bypass-nov-2026
---

CVE-2026-123158, dubbed "SSHhole," is an authentication bypass vulnerability in OpenSSH. The vulnerability stems from an interaction between the musl libc `crypt()` function and OpenSSH password verification logic. When an attacker provides a password between 256 and 1024 characters, `crypt()` may return an asterisk `*` as an error indicator. If an account is configured with `*` as its stored password hash (commonly used for disabled or key-only accounts), the OpenSSH authentication routine may interpret the match as successful, granting unauthorized access.

## Attack Chain

1. Attacker identifies an OpenSSH target running on a musl libc-based Linux distribution without PAM.
2. Attacker enumerates accounts configured for key-only authentication (often identified by `*` in the shadow file).
3. Attacker initiates an SSH password authentication attempt.
4. Attacker provides a crafted password string between 256 and 1024 characters.
5. The target's `crypt()` function returns `*` due to length overflow.
6. OpenSSH logic compares the returned `*` with the account's stored `*` hash.
7. OpenSSH erroneously confirms the password match.
8. Attacker gains unauthorized access to the target account.

## Impact

Successful exploitation allows for unauthorized SSH access to affected accounts. The level of access gained depends on the privileges of the targeted account.

## Recommendation

- Upgrade to OpenSSH 10.6p2 or later immediately to resolve the authentication logic flaw.
- Disable password authentication on systems where it is not strictly required by setting `PasswordAuthentication no` in `sshd_config`.
- Inventory systems using musl libc to identify high-risk assets, particularly Alpine Linux and embedded device environments.
- Audit SSH logs for unexpected successful password authentication events, specifically for accounts normally restricted to SSH keys.
