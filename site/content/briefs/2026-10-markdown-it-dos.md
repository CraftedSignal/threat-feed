---
title: Denial of Service Vulnerability in markdown-it Parser
slug: 2026-10-markdown-it-dos
description: A resource exhaustion vulnerability in the markdown-it Markdown parser allows for denial of service (DoS) when processing untrusted input with the typographer option enabled.
date: "2026-10-19T20:12:06Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:markdown-it_project:markdown-it:*:*:*:*:*:node.js:*:*
products:
  - markdown-it (< 14.3.2, < 15.0.2)
cves:
  - id: CVE-2026-111759
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111759
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade markdown-it dependency to version 14.3.2 or 15.0.2
      owner: Development
      due: 48h
      evidence: CVE-2026-111759 resolution note
  mitigation_plan:
    - priority: immediate
      action: Set typographer configuration to false in application logic
      owner: Development
      addresses: CVE-2026-111759
      evidence: 'Source notes that typographer: false is not affected'
---

The markdown-it library is vulnerable to a regular expression-style denial of service (ReDoS) attack when configured with 'typographer: true'. The vulnerability, identified as CVE-2026-111759, resides in the smartquotes rule implementation. Specifically, the parser performs quadratic processing time when encountering specially crafted sequences of opening and closing single or double quotes. Because this pattern triggers repeated scanning of the entire opener stack, a malicious actor providing malformed Markdown input can cause significant CPU consumption, potentially leading to service degradation or complete denial of service for applications using the parser to render untrusted content. This impact is highest in web applications that process user-submitted Markdown in real-time. The issue is resolved in markdown-it versions 14.3.2 and 15.0.2.

## Impact

Successful exploitation results in high CPU utilization on systems parsing malicious Markdown strings. This can lead to service latency, timeouts, or availability loss for applications handling large volumes of user-generated content, such as comment sections, documentation platforms, or messaging services.

## Recommendation

- Update the markdown-it library to version 14.3.2 or 15.0.2 immediately.
- If immediate patching is not possible, disable the 'typographer' setting in the markdown-it configuration (typographer: false), as the default configuration is not affected.
- Implement input validation and length constraints on Markdown strings prior to parsing to mitigate potential resource exhaustion attempts.
