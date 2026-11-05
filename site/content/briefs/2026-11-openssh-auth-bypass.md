---
brief_id: brief-2026-11-05-openssh-auth-bypass
event_id: brief-2026-11-05-openssh-auth-bypass
revision: 2
activity_at: "2026-11-05T21:32:29Z"
revision_history:
  - revision: 2
    at: "2026-11-05T21:32:29Z"
    checksum: sha256:10cccd9c0608e077a6afed61549175980eea1cb11fe0dc328d43fd698e83fba0
    summary: OS alpine linux
    changed_fields:
      - affected_os
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/alpine-openssh-musl-crypt-password-auth-bypass-nov-2026
title: 'OpenSSH: Password authentication bypass (sshole)'
slug: 2026-11-openssh-auth-bypass
description: OpenSSH 10.6p2 addresses a password authentication bypass vulnerability affecting systems that utilize musl libc with PAM support disabled, such as Alpine Linux.
date: "2026-11-05T20:26:24Z"
lastmod: "2026-11-05T21:31:43Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source information confirmed; remediation steps verified against vendor release notes.
vendors:
  - OpenSSH
products:
  - OpenSSH (< 10.6p2)
  - openssh-server
  - openssh-server-pam
affected_os:
  - Linux (musl libc based)
  - Alpine Linux 3.16
  - Alpine Linux 3.17
  - Alpine Linux 3.18
  - Alpine Linux 3.19
  - Alpine Linux 3.20
  - Alpine Linux 3.21
  - Alpine Linux 3.22
  - Alpine Linux 3.23
  - Alpine Linux 3.24
  - Alpine Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OpenSSH just published OpenSSH 10.6p2 with a critical fix for a password authentication bypass on systems that use musl libc and have PAM disabled.
    confidence_band: high
cves:
  - id: CVE-2026-123158
    cvss: 8.1
    kev_status: "false"
references:
  - https://www.openssh.org/releasenotes.html#10.6p2
  - https://seclists.org/oss-sec/2026/q4/528
  - https://sshhole.com/
  - https://seclists.org/oss-sec/2026/q4/522
  - https://pwn.watch/i/alpine-openssh-musl-crypt-password-auth-bypass-nov-2026
  - https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/
  - https://www.openssh.org/releasenotes.html
  - https://www.openssh.org/txt/release-10.6p2
  - https://www.cve.org/CVERecord?id=CVE-2026-123158
  - https://github.com/openssh/openssh-portable/commit/4353fdc43ef646c43a8dda7025cc1a898caf1482
  - https://sshhole.com
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123158
  - https://status.linode.com/incidents/fc9c3k1n3ph1
  - https://orca.security/resources/research/sshole-openssh-authentication-bypass-gives-attackers-root-on-alpine-linux/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade OpenSSH to version 10.6p2 or later.
      owner: IT Operations
      due: 24h
      evidence: Official OpenSSH 10.6p2 release notes confirm the fix for the reported vulnerability.
  hunt_leads:
    - lead: Identify systems in the environment running OpenSSH on musl libc distributions (e.g., Alpine Linux) where PAM is disabled.
      technique_id: T1190
      data_needed:
        - System configuration inventory
        - sshd_config files
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The issue is specific to configurations using musl libc and PAM disabled.
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenSSH to 10.6p2 or implement PAM authentication to mitigate the vulnerability.
      owner: IT Operations
      addresses: OpenSSH musl libc bypass
      evidence: Maintainer statement indicates the fix in 10.6p2 is a workaround for the underlying libc issue.
updates:
  - at: "2026-11-05T20:26:45Z"
    level: L2
    summary: added CVE-2026-123158;
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/alpine-openssh-musl-crypt-password-auth-bypass-nov-2026
  - at: "2026-11-05T21:31:43Z"
    level: L1
    summary: OS alpine linux
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/alpine-openssh-musl-crypt-password-auth-bypass-nov-2026
---

OpenSSH 10.6p2 introduces a fix for a password authentication bypass vulnerability that affects systems built and running with PAM support disabled. While the OpenSSH maintainers state the root cause lies within the underlying musl libc, the flaw is exploitable via sshd. Alpine Linux is specifically identified as a system configuration where this issue is present. This vulnerability has been referred to as "sshole" in public disclosures.

## Impact

The vulnerability allows an unauthenticated attacker to bypass password-based authentication mechanisms in sshd when the system is configured to use musl libc without PAM support, potentially leading to unauthorized remote access.

## Recommendation

- Upgrade OpenSSH to version 10.6p2 or later on all systems using musl libc where PAM is not enabled.
- Audit existing server configurations to determine if PAM support is disabled in current OpenSSH installations.
- Prioritize patching for Alpine Linux environments or similar distributions relying on musl libc.
