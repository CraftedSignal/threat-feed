---
brief_id: brief-2026-10-29-litellm-file-read
event_id: brief-2026-10-29-litellm-file-read
revision: 2
activity_at: "2026-10-29T19:55:25Z"
revision_history:
  - revision: 2
    at: "2026-10-29T19:55:25Z"
    checksum: sha256:68e531e08c156bfb96d30b03b2e17b433ff8c375682d1fb63015df67e79efb9c
    summary: added coverage for LiteLLM (>= 1.91.0, < 1.100.4) +4 products
    changed_fields:
      - action_plan
      - affected_products
      - cpes
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - ttps
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-7hp6-4w63-5g45
title: 'LiteLLM: Local file read vulnerability in vertex_ai_credentials'
slug: 2026-10-litellm-file-read
description: An authenticated user with the internal_user_viewer role can read arbitrary local files from the LiteLLM proxy runtime by exploiting an incomplete blocklist in the vertex_ai_credentials parameter.
date: "2026-10-29T19:49:34Z"
lastmod: "2026-10-29T19:52:02Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:litellm:litellm:*:*:*:*:*:*:*:*
vendors:
  - LiteLLM
products:
  - LiteLLM (< 1.95.0)
  - LiteLLM (>= 1.91.0, < 1.100.4)
  - LiteLLM (>= 1.101.0, < 1.101.3)
  - LiteLLM (>= 1.102.0, < 1.102.2)
  - LiteLLM (>= 1.103.0, < 1.103.1)
  - LiteLLM (>= 1.104.0rc1, < 1.104.0rc2)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: An authenticated LiteLLM proxy user could read arbitrary local files from the proxy runtime by sending a crafted vertex_ai_credentials value to /utils/transform_request.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated user with internal_user privileges can escalate to proxy_admin and achieve remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: including the ability to execute arbitrary commands via the MCP stdio endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-114612
    cvss: 9.9
    epss: 0.00319
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-g5ff-637f-6q2m
  - https://github.com/advisories/GHSA-7hp6-4w63-5g45
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114612
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade LiteLLM to 1.95.0 or later
      owner: IT Operations
      due: 48h
      evidence: Remediation section specifies upgrading to 1.95.0.
    - action: Patch LiteLLM to 1.100.4, 1.101.3, 1.102.2, 1.103.1, or 1.104.0rc2
      owner: IT Operations
      due: 24h
      evidence: GHSA-7hp6-4w63-5g45 patch release
    - action: Set EXPERIMENTAL_UI_LOGIN=false if immediate upgrade is not possible
      owner: IT Operations
      due: 24h
      evidence: Mitigation advice from GHSA-7hp6-4w63-5g45
  hunt_leads:
    - lead: Identify requests to /utils/transform_request containing vertex_ai_credentials in the request body
      technique_id: T1083
      data_needed:
        - Web server access logs or application-level request logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability is triggered by supplying a crafted vertex_ai_credentials value to /utils/transform_request.
    - lead: Identify unusual API key creation requests containing metadata fields associated with administrative credential patterns
      technique_id: T1068
      data_needed:
        - LiteLLM application logs (API request payloads)
        - Authentication service logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An attacker exploits this by requesting a new API key with a crafted metadata field containing a forged admin credential.
  mitigation_plan:
    - priority: immediate
      action: Upgrade LiteLLM to 1.95.0
      owner: IT Operations
      addresses: LiteLLM Local File Read
      evidence: Upgrade to 1.95.0 or later.
    - priority: immediate
      action: Upgrade to non-vulnerable versions or disable EXPERIMENTAL_UI_LOGIN
      owner: IT Operations
      addresses: CVE-2026-114612
      evidence: GHSA-7hp6-4w63-5g45
updates:
  - at: "2026-10-29T19:52:02Z"
    level: L2
    summary: added coverage for LiteLLM (>= 1.91.0, < 1.100.4) +4 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-7hp6-4w63-5g45
---

LiteLLM contains a vulnerability where the `/utils/transform_request` endpoint fails to properly sanitize the `vertex_ai_credentials` parameter. While `vertex_credentials` was explicitly blocked in the request-body safety checks, the alias `vertex_ai_credentials` was omitted. An authenticated user with the `internal_user_viewer` role can supply a local file path to this parameter, causing the application to read the file and potentially transmit its contents to an attacker-controlled destination.

## Impact

An attacker can read any file accessible by the system user running the LiteLLM process. Sensitive files such as `/proc/self/environ` may contain environment variables, including `LITELLM_MASTER_KEY` and various provider API keys, leading to full administrative compromise of the proxy instance.

## Recommendation

Upgrade the LiteLLM package to version 1.95.0 or later immediately. The updated version includes `vertex_ai_credentials` in the request-body blocklist, mitigating the vulnerability. No configuration workarounds are available for versions prior to 1.95.0.
