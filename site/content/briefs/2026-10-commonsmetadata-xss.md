---
title: Stored XSS in CommonsMetadata via LicenseUrl
slug: 2026-10-commonsmetadata-xss
description: A stored cross-site scripting (XSS) vulnerability in the CommonsMetadata component, tracked as CVE-2026-103584, allows attackers to inject 'javascript:' URIs into image metadata, leading to unauthorized script execution in the wiki origin.
date: "2026-10-01T03:37:54Z"
type: threat
types:
  - threat
severities:
  - low
exploited: true
cpes:
  - cpe:2.3:a:wikimedia:commonsmetadata:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - wikimedia
vendors:
  - Wikimedia
products:
  - CommonsMetadata
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'An editor could store a javascript: URL. When an interface rendered that metadata as a link, a visitor who followed it could run script in the wiki origin.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: When an interface rendered that metadata as a link, a visitor who followed it could run script in the wiki origin.
    confidence_band: high
cves:
  - id: CVE-2026-103584
  - id: CVE-2026-103585
references:
  - https://gerrit.wikimedia.org/r/1346780
  - https://bombobombone.github.io/posts/cve-2026-103584/
  - https://phabricator.wikimedia.org/T435999
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  mitigation_plan:
    - priority: medium_term
      action: Upgrade CommonsMetadata component to the patched version referenced in Gerrit 1346780
      owner: IT Operations
      addresses: CVE-2026-103584
      evidence: CommonsMetadata fix on Gerrit
---

CVE-2026-103584 is a stored XSS vulnerability identified in the CommonsMetadata component used within the Wikimedia ecosystem. The vulnerability exists because the component copies the 'licensetpl_link' value from file descriptions into the 'LicenseUrl' field of image metadata without performing necessary URL scheme validation. An attacker with low-level privileges can store a 'javascript:' URI within the metadata, which is subsequently rendered by the web interface. When a victim user interacts with this link, the embedded JavaScript executes in the context of the wiki origin. A secondary, related vulnerability, CVE-2026-103585, impacts the MediaSearch QuickView consumer path, demonstrating a broader issue with how metadata is consumed across the platform. This issue was reported by Marco Paciaroni (BomboBombone) and addressed via a patch in Gerrit.

## Impact

Successful exploitation results in arbitrary JavaScript execution within the context of the affected wiki origin. This could allow an attacker to hijack user sessions, perform unauthorized actions on behalf of the victim, or exfiltrate sensitive data accessible within the browser session. The vulnerability carries a low CVSS score (2.1), reflecting its reliance on user interaction and the requirement for specific metadata configuration, but it remains a security concern for platforms processing user-supplied image metadata.

## Recommendation

Prioritized actions for security teams:
- Verify that the CommonsMetadata component is updated to the version containing the fix documented in Gerrit change 1346780.
- Audit existing image metadata entries for suspicious URI schemes (e.g., 'javascript:') in the 'LicenseUrl' field if an automated check can be scripted against the API.
- Implement strict Content Security Policy (CSP) headers to mitigate the impact of potential XSS vulnerabilities by restricting the sources from which scripts can be executed.
