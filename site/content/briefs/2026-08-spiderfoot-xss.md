---
title: Stored Cross-Site Scripting in SpiderFoot via Correlation Titles
slug: 2026-08-spiderfoot-xss
description: SpiderFoot versions 4.0 and earlier are vulnerable to stored cross-site scripting (XSS) due to improper HTML sanitization in correlation titles, allowing attackers to execute arbitrary JavaScript in an operator's browser.
date: "2026-08-18T12:51:10Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - smicallef
products:
  - spiderfoot
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can inject malicious HTML elements with event handlers into correlation results that execute scripts in the operator's browser
    confidence_band: high
cves:
  - id: CVE-2026-75626
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75626
  - https://www.vulncheck.com/advisories/spiderfoot-stored-cross-site-scripting-via-correlation-titles
  - https://github.com/smicallef/spiderfoot/issues/2012
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade SpiderFoot instances to versions containing the fix for CVE-2026-75626
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-75626
  mitigation_plan:
    - priority: immediate
      action: Restrict SpiderFoot scan targets to trusted or internal infrastructure to prevent interaction with malicious banners
      owner: SOC
      addresses: CVE-2026-75626
      evidence: NVD advisory description
---

SpiderFoot (versions 4.0 and earlier) contains a stored cross-site scripting (XSS) vulnerability (CVE-2026-75626) stemming from a failure to properly HTML-escape correlation titles. These titles are dynamically generated using data gathered from external scan sources, such as server banners and metadata. An attacker who can influence these external data sources - for example, by hosting a service that returns a malicious banner - can cause SpiderFoot to generate a correlation result containing injected HTML elements and JavaScript event handlers. When an operator accesses the correlations view in the SpiderFoot web interface, the malicious script executes in the context of the operator's session. This vulnerability poses a significant risk, as successful execution could allow for the exfiltration of sensitive information, including API keys stored within the application.

## Attack Chain

1. Attacker identifies a target organization using SpiderFoot for reconnaissance.
2. Attacker deploys a server or infrastructure controlled by them to be scanned by the target's SpiderFoot instance.
3. Attacker crafts a malicious server banner or metadata field containing an HTML payload (e.g., &lt;img src=x onerror=alert(1)>).
4. The target's SpiderFoot instance scans the attacker's infrastructure and ingests the malicious banner into its database.
5. SpiderFoot processes this data and creates a correlation entry, incorporating the unescaped malicious payload into the correlation title.
6. The target's operator accesses the "Correlations" view in the SpiderFoot dashboard.
7. The browser renders the malicious title, triggering the stored XSS payload in the operator's session context.
8. Attacker achieves execution of arbitrary JavaScript to steal session tokens or API keys.

## Impact

Successful exploitation of this vulnerability allows an attacker to compromise the operator's session. Potential impacts include the theft of application-specific API keys, unauthorized access to the SpiderFoot instance, and the potential for pivoting into the operator's local environment through further browser-based attacks.

## Recommendation

Prioritized actions for security teams:
- Update SpiderFoot to the latest available version that includes a patch for CVE-2026-75626.
- Implement strict egress filtering to limit the external infrastructure the SpiderFoot instance can reach, reducing exposure to malicious scan targets.
- Monitor web application logs for unexpected requests to the correlations view or unusual JavaScript execution patterns.
- Review documentation for CVE-2026-75626 to identify specific mitigation steps provided by the maintainers.
