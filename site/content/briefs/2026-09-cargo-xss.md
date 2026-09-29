---
title: Reflected Cross-Site Scripting in MediaWiki Cargo Extension
slug: 2026-09-cargo-xss
description: The Cargo extension for MediaWiki is vulnerable to reflected XSS via unescaped field-alias text in export error messages, allowing unauthenticated attackers to execute arbitrary scripts in the wiki's origin.
date: "2026-09-29T15:35:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:mediawiki:cargo:*:*:*:*:*:mediawiki:*:*
vendors:
  - Wikimedia
products:
  - Cargo (<= 3.9.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The original report established anonymous access to the vulnerable error path without a saved page or existing Cargo data.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: A victim opening a crafted request could run script in the wiki origin with their available permissions.
    confidence_band: high
cves:
  - id: CVE-2026-96876
    epss: 0.00258
references:
  - https://vulners.com/cve/CVE-2026-96876
  - https://gerrit.wikimedia.org/r/c/mediawiki/extensions/Cargo/+/1328630
  - https://bombobombone.github.io/posts/cve-2026-96876/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade MediaWiki Cargo extension to a patched version.
      owner: IT Operations
      due: 48h
      evidence: Upstream fix identified in CVE-2026-96876 record.
  mitigation_plan:
    - priority: immediate
      action: Deploy patch from Gerrit (https://gerrit.wikimedia.org/r/c/mediawiki/extensions/Cargo/+/1328630).
      owner: IT Operations
      addresses: CVE-2026-96876
      evidence: Vendor provided fix.
---

The MediaWiki Cargo extension, versions up to 3.9.4, contains a security vulnerability (CVE-2026-96876) resulting from improper sanitization of exception messages. Specifically, error messages generated during export operations fail to HTML-escape untrusted input derived from field-alias text. An unauthenticated attacker can craft a malicious HTTP request that forces the application to return an error page containing executable markup. If a victim visits the crafted URL, the injected script executes within the context of the wiki origin, potentially allowing unauthorized actions or data access using the victim's session privileges. The vulnerability was reported by Marco Paciaroni and fixed by the upstream maintainers via a patch that mandates HTML-escaping for all exception messages before rendering them in export responses.

## Impact

Successful exploitation allows for reflected cross-site scripting (XSS) in the context of the affected wiki. An attacker can use this to execute arbitrary JavaScript in the victim's browser session, which could lead to session hijacking, defacement of the wiki content, or unauthorized interactions with the wiki platform. As this is an unauthenticated vector, any public-facing MediaWiki instance utilizing the Cargo extension (version 3.9.4 or earlier) is potentially at risk of exploitation by external actors.

## Recommendation

- Upgrade the MediaWiki Cargo extension to a version that includes the fix for CVE-2026-96876.
- Apply the vendor-provided patch available at the Gerrit tracking task: https://gerrit.wikimedia.org/r/c/mediawiki/extensions/Cargo/+/1328630.
- Audit existing MediaWiki configurations to identify if the Cargo extension is enabled and confirm the current version in use.
