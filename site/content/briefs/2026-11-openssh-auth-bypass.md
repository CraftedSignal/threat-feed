---
brief_id: brief-2026-11-05-openssh-auth-bypass
event_id: brief-2026-11-05-openssh-auth-bypass
revision: 5
activity_at: "2026-11-05T23:54:16Z"
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
  - revision: 3
    at: "2026-11-05T21:43:48Z"
    checksum: sha256:9c911e02a35eecc8f9afed721621a6c75d942e67ead9105ed7d01dfbb66866c2
    summary: severity → critical
    changed_fields:
      - action_plan
      - affected_products
      - affected_vendors
      - content
      - lastmod
      - priority_score
      - priority_signals
      - references
      - rules
      - severity
      - summary
      - tags
      - title
      - ttps
      - updates
    source_urls:
      - https://thehackernews.com/2026/11/openssh-issues-emergency-fix-for-flaw.html
  - revision: 4
    at: "2026-11-05T22:31:38Z"
    checksum: sha256:ca65b349ee520ba7b20eaa230fc4dc30bb222c7aafd992abcf7f90ec711f7f28
    summary: musl version < 10.6p2
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1468/
  - revision: 5
    at: "2026-11-05T23:54:16Z"
    checksum: sha256:fd52ee4e3af369ba246bafd2d1edd97ca0126a71eb363ed4acc1ee5022a08fdb
    summary: OS openwrt
    changed_fields:
      - affected_os
      - lastmod
      - references
      - updates
    source_urls:
      - https://arstechnica.com/security/2026/11/vulnerability-allows-attackers-to-log-into-some-linux-devices-sans-password/
title: 'OpenSSH: Authentication bypass on Alpine Linux'
slug: 2026-11-openssh-auth-bypass
description: An authentication bypass vulnerability in OpenSSH on Alpine Linux allows remote attackers to log in to passwordless accounts by providing a 257-1,024 byte password when password authentication is enabled.
date: "2026-11-05T20:26:24Z"
lastmod: "2026-11-05T23:53:37Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
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
tags:
  - vulnerability
  - authentication
  - linux
vendors:
  - OpenSSH
  - Alpine Linux
products:
  - OpenSSH (< 10.6p2)
  - openssh-server
  - openssh-server-pam
  - tiny-cloud
  - musl (< 10.6p2)
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
  - OpenWrt
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OpenSSH just published OpenSSH 10.6p2 with a critical fix for a password authentication bypass on systems that use musl libc and have PAM disabled.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    subtechnique_id: T1078.004
    subtechnique_name: Cloud Accounts
    evidence: Attackers can log in to accounts that have no password, such as SSH key-only accounts, on some Alpine Linux servers running the standard openssh-server package.
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
  - https://thehackernews.com/2026/11/openssh-issues-emergency-fix-for-flaw.html
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1468/
  - https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-015/
  - https://arstechnica.com/security/2026/11/vulnerability-allows-attackers-to-log-into-some-linux-devices-sans-password/
rules:
  - title: Detect Suspicious SSH Login to Passwordless Accounts
    description: Detects successful password-based SSH logins for accounts that typically do not utilize passwords, such as root or service accounts, which may indicate exploitation of the Alpine Linux authentication bypass.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Upgrade OpenSSH to version 10.6p2 or later.
      owner: IT Operations
      due: 24h
      evidence: Official OpenSSH 10.6p2 release notes confirm the fix for the reported vulnerability.
    - action: Patch OpenSSH to 10.6p2 or later
      owner: IT Operations
      due: 24h
      evidence: Alpine has published fixed packages for every release back to 3.16.
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
    - lead: Identify accounts with * as password field and review associated log activity
      technique_id: T1078
      data_needed:
        - etc/shadow file contents
        - /var/log/messages
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The advisory suggests looking in /var/log/messages for sshd lines reading Accepted password for an account that has no password.
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenSSH to 10.6p2 or implement PAM authentication to mitigate the vulnerability.
      owner: IT Operations
      addresses: OpenSSH musl libc bypass
      evidence: Maintainer statement indicates the fix in 10.6p2 is a workaround for the underlying libc issue.
    - priority: immediate
      action: Set PasswordAuthentication no in /etc/ssh/sshd_config
      owner: IT Operations
      addresses: Authentication bypass
      evidence: Turning off password logins also stops the attack.
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
  - at: "2026-11-05T21:43:10Z"
    level: L3
    summary: severity → critical
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/11/openssh-issues-emergency-fix-for-flaw.html
  - at: "2026-11-05T22:30:10Z"
    level: L2
    summary: musl version < 10.6p2
    sources:
      - anssi
    source_urls:
      - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1468/
  - at: "2026-11-05T23:53:37Z"
    level: L1
    summary: OS openwrt
    sources:
      - ars-security
    source_urls:
      - https://arstechnica.com/security/2026/11/vulnerability-allows-attackers-to-log-into-some-linux-devices-sans-password/
---

A critical vulnerability exists in the `openssh-server` package on Alpine Linux (and other musl-based systems) when configured without PAM and with `PasswordAuthentication` enabled. Attackers can bypass authentication for accounts without a set password (marked as `*` in `/etc/shadow`) by providing a password string between 257 and 1,024 bytes long. The flaw occurs because the musl `crypt()` function returns an "unmatchable" value for inputs exceeding 256 bytes, which the OpenSSH authentication logic improperly equates to a successful match when borrowing a salt from another local account. 

## Impact
Successful exploitation grants unauthorized access to any account without a set password, including key-only users, system accounts like `root` (if not otherwise restricted), and the default `alpine` user in certain cloud images. Unauthorized access may lead to privilege escalation if the compromised account has `doas` or `sudo` rights. No attacks have been reported in the wild.

## Recommendation
- Update `openssh-server` to the latest version (e.g., 3.21.10, 3.22.8, 3.23.8, or 3.24.4) via `apk upgrade -U -a` and restart the SSH service.
- If patching is not immediate, disable password authentication by setting `PasswordAuthentication no` in `sshd_config` or associated drop-in files, then verify with `sshd -t` and restart the service.
- Audit `/var/log/messages` for unexpected "Accepted password" logs for service or key-only accounts.
- Review `doas` usage, recently created files, and `authorized_keys` for signs of post-exploitation activity.
