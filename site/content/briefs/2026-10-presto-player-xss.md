---
title: Stored XSS in Presto Player WordPress Plugin
slug: 2026-10-presto-player-xss
description: The Presto Player WordPress plugin is vulnerable to Stored Cross-Site Scripting via the presto-player tag, allowing unauthenticated attackers to execute arbitrary web scripts.
date: "2026-10-10T07:51:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:presto_player:presto_player:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - wordpress
  - cve-2026-96682
vendors:
  - Presto Player
products:
  - Presto Player (<= 4.5.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Presto Player plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Comment Content via <presto-player> Tag in all versions up to, and including, 4.5.1.
    confidence_band: high
cves:
  - id: CVE-2026-96682
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96682
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Presto Player plugin to version 4.5.2 or later.
      owner: IT Operations
      due: 24h
      evidence: Source identifies vulnerability in versions <= 4.5.1.
  mitigation_plan:
    - priority: immediate
      action: Enable manual comment moderation for all users in WordPress settings.
      owner: IT Operations
      addresses: CVE-2026-96682
      evidence: Source notes reliance on auto-approval settings for persistent exploitation.
---

The Presto Player plugin for WordPress (versions up to and including 4.5.1) contains a Stored Cross-Site Scripting (XSS) vulnerability. The flaw stems from insufficient input sanitization and output escaping when processing content within the &lt;presto-player> tag. An unauthenticated attacker can inject arbitrary malicious scripts into comment fields. While the initial injection may require comment approval, WordPress default settings often auto-approve subsequent comments from the same author, providing an attacker with a mechanism to persist and execute payloads without further administrative intervention. Impact includes unauthorized script execution within the context of a victim's session, potentially leading to session hijacking, defacement, or redirection to malicious sites.

## Attack Chain

1. Attacker identifies a WordPress site with Presto Player plugin version 4.5.1 or earlier installed.
2. Attacker crafts a malicious comment containing a crafted &lt;presto-player> tag with embedded JavaScript.
3. Attacker submits the comment via the public comment form.
4. Attacker leverages the site's default auto-approval configuration or waits for manual administrator approval of the comment.
5. The malicious script is stored in the WordPress database linked to the comment content.
6. Victim visits the page where the comment is rendered.
7. The browser renders the &lt;presto-player> tag, triggering the execution of the injected script in the context of the victim's session.
8. Attacker achieves malicious script execution (e.g., session token theft).

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary scripts in the browsers of site visitors, including administrators. This can lead to account takeover, unauthorized actions performed on behalf of authenticated users, and theft of sensitive session information. The vulnerability affects all users running vulnerable versions of the Presto Player plugin.

## Recommendation

Update the Presto Player plugin to the latest available version beyond 4.5.1 to remediate CVE-2026-96682. Implement a Web Application Firewall (WAF) to detect and block malicious script injection attempts targeting the &lt;presto-player> tag in comment inputs. Review WordPress comment moderation settings to require manual approval for all new user comments to mitigate auto-approval exploitation vectors.
