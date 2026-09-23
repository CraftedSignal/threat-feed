---
title: Stored XSS in Home Assistant Statistics Graph Card
slug: 2026-09-home-assistant-xss
description: Home Assistant contains a stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-91130) in the Statistics Graph card, allowing arbitrary JavaScript execution when viewing entities with malicious names.
date: "2026-09-23T01:54:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:home-assistant:home_assistant:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - supply-chain
vendors:
  - Home Assistant
products:
  - Home Assistant (< 2026.7.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: Supply Chain Compromise
    evidence: An alternative, and more impactful scenario, is that the entity gets a malicious name from the provider of the integration.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability can be exploited... allowing for Cross-Site Scripting attacks against anyone who views a Statistics Graph card.
    confidence_band: high
cves:
  - id: CVE-2026-91130
  - id: CVE-2025-62172
    epss: 0.00422
references:
  - https://github.com/advisories/GHSA-wx4m-69m9-gx3m
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91130
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Home Assistant to version 2026.7.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source states Home Assistant < 2026.7.0 is vulnerable
  mitigation_plan:
    - priority: immediate
      action: Upgrade Home Assistant to 2026.7.0 or later
      owner: IT Operations
      addresses: CVE-2026-91130
      evidence: Fixed in 2026.7.0
---

Home Assistant versions prior to 2026.7.0 are vulnerable to a stored Cross-Site Scripting (XSS) attack via the Statistics Graph card component. The vulnerability exists because the application fails to sanitize entity names before rendering them within ECharts tooltips. Specifically, in `src/components/chart/statistics-chart.ts`, the `param.seriesName` variable is interpolated into an HTML string without being passed through the `filterXSS()` function. This oversight mirrors a similar vulnerability found in the Energy dashboard (CVE-2025-62172), which was previously patched. An attacker can exploit this by setting a malicious name for an entity, either as an authenticated user or through a supply-chain vector via a third-party integration that automatically populates entity names. When an unsuspecting user views a Statistics Graph card containing the compromised entity and hovers over a data point, the malicious JavaScript executes in their browser session.

## Attack Chain

1. An attacker identifies a target Home Assistant instance or a third-party integration utilized by target users.
2. The attacker crafts a payload containing malicious HTML/JavaScript within an entity name string (e.g., `<img src=x onerror=alert(document.domain) />`).
3. If via supply chain, the attacker compromises a third-party integration or uses a malicious integration to inject the payload into the Home Assistant entity database.
4. If via direct access, an authenticated attacker creates a "Template sensor" helper with the malicious name.
5. The target user adds a Statistics Graph card to their dashboard, configured to display the malicious entity.
6. The victim navigates to the dashboard and interacts with the chart by hovering over a data point.
7. The `statistics-chart` component renders the unsanitized entity name into the ECharts tooltip, triggering the malicious script execution.
8. The script executes within the context of the victim's authenticated browser session, leading to potential account compromise or further actions.

## Impact

The vulnerability allows for remote code execution within the victim's browser context. If exploited via the supply-chain vector, an attacker does not require direct access to the target's Home Assistant instance to deliver the payload. Successful exploitation grants the attacker the ability to perform actions on behalf of the authenticated user, potentially leading to unauthorized control over smart home devices, exfiltration of configuration data, or further internal network reconnaissance.

## Recommendation

Prioritized actions for administrators:
- Upgrade Home Assistant to version 2026.7.0 or later immediately to patch CVE-2026-91130.
- Review all third-party integrations and custom sensors for unexpected or anomalous entity names.
- Audit existing dashboard Statistics Graph cards for any entities displaying irregular naming conventions.
