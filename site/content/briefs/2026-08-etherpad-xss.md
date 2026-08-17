---
title: Stored Cross-Site Scripting in Etherpad Lite HTML Export
slug: 2026-08-etherpad-xss
description: Etherpad Lite version 1.8.14 and earlier is vulnerable to stored XSS via the HTML export feature, allowing attackers to inject malicious payloads into attribute pool values that execute upon viewing exported documents.
date: "2026-08-17T18:46:31Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Etherpad
products:
  - Etherpad Lite (1.8.14)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The value comes verbatim from the pad attribute pool, which a pad editor controls via a crafted changeset... yielding stored XSS for any collaborator who opens the export.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2jp7-wwpg-3p9w
  - https://github.com/ether/etherpad-lite/pull/7905
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Etherpad Lite to a version containing the patch for CVE-2026-55090.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-55090 vulnerability remediation
---

Etherpad Lite contains a stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-55090, within its HTML export functionality. The vulnerability resides in `src/node/utils/ExportHtml.ts`, where the `getHTMLFromAtext` function fails to sanitize values interpolated from the `exportHtmlAdditionalTagsWithData` plugin hook. Because attribute pool values are stored verbatim when users create or edit pads, an attacker can manipulate attribute values to contain HTML injection payloads, such as `" onload="alert(1)`. When the document is exported to HTML and opened by a victim in a browser, the malicious script executes within the context of the origin. This affects installations using plugins that register the hook, such as ep_font_color or ep_font_size. Defenders should prioritize updating to the patched version identified in the pull request #7905.

## Impact

Successful exploitation results in arbitrary JavaScript execution in the context of the user viewing the exported HTML document. This could lead to session hijacking, unauthorized actions performed on behalf of the victim, or data exfiltration. The vulnerability impacts all Etherpad Lite environments using versions up to 1.8.14 that leverage specific plugins.

## Recommendation

- Upgrade Etherpad Lite to the latest version to include the fix for CVE-2026-55090.
- Audit custom Etherpad plugins that utilize the `exportHtmlAdditionalTagsWithData` hook to ensure they utilize the `Security.escapeHTMLAttribute` method.
- Restrict access to pad creation and editing to trusted users to mitigate the risk of malicious changeset injection.
