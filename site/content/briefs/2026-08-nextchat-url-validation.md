---
title: Improper URL Validation in NextChat Proxy Endpoint
slug: 2026-08-nextchat-url-validation
description: NextChat versions 2.15.8 through 2.16.1 are vulnerable to credential theft due to weak URL validation in the proxy endpoint, allowing attackers to exfiltrate the server's OpenAI API key.
date: "2026-08-30T17:11:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nextchat:nextchat:*:*:*:*:*:*:*:*
vendors:
  - NextChat
products:
  - NextChat (2.15.8-2.16.1)
cves:
  - id: CVE-2026-82639
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82639
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade NextChat to version 2.16.2 or later to address CVE-2026-82639
      owner: IT Operations
      due: 48h
      evidence: Source document identifies version range 2.15.8 through 2.16.1 as vulnerable.
    - action: Rotate OpenAI API keys currently stored in NextChat instances
      owner: SOC
      due: 24h
      evidence: Vulnerability allows exfiltration of the Authorization header containing the API key.
  mitigation_plan:
    - priority: immediate
      action: Upgrade NextChat
      owner: IT Operations
      addresses: CVE-2026-82639
      evidence: NVD vulnerability entry
---

NextChat versions 2.15.8 through 2.16.1 contain an improper URL validation vulnerability located within the application's proxy endpoint. The flaw stems from the application utilizing weak substring matching rather than proper hostname parsing when validating the 'x-base-url' HTTP header. 

An attacker can leverage this logic error by providing a crafted URL that contains the string 'api.openai.com' as a substring. This bypasses the intended security controls, causing the NextChat server to route requests to an attacker-controlled destination while including the server's sensitive OpenAI API key within the Authorization header. This vulnerability enables unauthorized access to and potential exfiltration of the organization's OpenAI API credentials.
