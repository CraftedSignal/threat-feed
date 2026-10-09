---
title: TinaCMS Admin Iframe Origin Validation Bypass
slug: 2026-10-tinacms-iframe-origin-bypass
description: TinaCMS improperly validates admin preview URLs, allowing attackers to frame external origins and hijack the postMessage trust channel to perform unauthorized GraphQL operations.
date: "2026-10-09T21:23:09Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - TinaCMS
products:
  - tinacms
  - '@tinacms/app'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: By luring an authenticated TinaCMS editor to a malicious link, the attacker initiates the exploit chain.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The admin executes GraphQL operations on behalf of the editor, effectively performing unauthorized actions.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-x34j-47hf-4xg7
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all instances of TinaCMS and apply the latest available patches.
      owner: IT Operations
      due: 48h
      evidence: Source documentation identifies the bug in current and prior versions.
  mitigation_plan:
    - priority: immediate
      action: Implement a strict Content Security Policy (CSP) restricting frame-src to same-origin.
      owner: Security Operations
      addresses: Cross-origin framing vulnerability
      evidence: The lack of CSP allows the external origin to be framed.
---

TinaCMS contains a critical vulnerability where the admin preview feature constructs an `<iframe src>` attribute from a URL fragment splat without verifying that the destination remains same-origin. By crafting a URL fragment with a doubled slash (e.g., `#/~//attacker.example/p`), an attacker can force the admin dashboard to embed an external site. Because the application derives its `expectedOrigin` trust anchor from the same unvalidated input, the attacker-controlled iframe is treated as a trusted peer for the `postMessage` communication channel.

Once an authenticated editor is lured to a malicious link, the attacker-controlled iframe can intercept the administrative session. The attacker can then inject arbitrary GraphQL queries, which the TinaCMS admin executes using the editor's active session token. The resulting data is then posted back to the attacker's origin, resulting in unauthorized read and write access to the site's content API. This issue affects the `tinacms` and `@tinacms/app` packages.

## Attack Chain

1. Attacker crafts a malicious URL containing a double slash in the hash fragment (`#/~//evil.com/page`).
2. Attacker induces an authenticated TinaCMS editor to click the malicious link.
3. The TinaCMS admin `HashRouter` interprets the fragment as a protocol-relative URL and loads `//evil.com/page` into an iframe.
4. The application logic derives `expectedOrigin` from the same malicious input, incorrectly marking the external origin as trusted.
5. The attacker-controlled frame sends an `open` message to the admin via the `postMessage` channel.
6. The TinaCMS admin validates the message origin against the poisoned `expectedOrigin`, confirming it as trusted.
7. The admin executes the attacker's supplied GraphQL query using the editor's authentication token.
8. The admin sends the query result back to the attacker-controlled frame, completing data exfiltration.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain full read and write access to the content managed by the TinaCMS instance. As the operations are performed using the authenticated editor's credentials, the attacker can modify site content, delete documents, or retrieve sensitive data exposed through the GraphQL API, effectively bypassing all authentication controls for the CMS content.

## Recommendation

Prioritize upgrading TinaCMS and associated packages to a version where this vulnerability is mitigated. Since the source notes that `tinacms@3.9.3` hardening was incomplete, audit all instances for any version that does not explicitly enforce a strict same-origin check for the preview iframe. Ensure that `getExpectedPreviewOrigin` is refactored to refuse any origin other than `window.location.origin`. Deploy a Content Security Policy (CSP) that restricts `frame-src` to trusted local origins to mitigate the risk of cross-origin framing.
