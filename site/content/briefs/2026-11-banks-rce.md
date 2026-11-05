---
brief_id: brief-2026-11-05-banks-rce
event_id: brief-2026-11-05-banks-rce
revision: 1
activity_at: "2026-11-05T22:30:30Z"
title: 'Banks: Arbitrary import path resolution remote code execution (CVE-2026-61536)'
slug: 2026-11-banks-rce
description: The banks library fails to validate tool import paths parsed from template content, allowing an attacker to achieve arbitrary code execution by defining malicious Tool objects that resolve to system-level Python callables.
date: "2026-11-05T22:30:30Z"
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
  validation_status: test_defined
cpes:
  - cpe:2.3:a:banks:banks:*:*:*:*:*:*:*:*
tags:
  - rce
  - python
  - vulnerability
vendors:
  - banks
products:
  - banks (<= 2.4.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: any importable Python attribute (e.g. os.system, subprocess.getoutput) can be selected
    confidence_band: high
cves:
  - id: CVE-2026-61536
    cvss: 7.5
    epss: 0.00377
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-64vx-6h2c-rjh7
  - https://github.com/banks/banks/issues/CVE-2026-61536
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Identify all applications using the banks library and assess if they utilize external or shared prompt registries
      owner: SOC
      due: 24h
      evidence: Vulnerability affects banks applications that load prompts from attacker-influenced sources
  hunt_leads:
    - lead: Monitor application logs for unexpected Tool object definitions or calls to unusual system modules within template-rendered outputs
      technique_id: T1059.003
      data_needed:
        - Application logs (process execution context)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Malicious Tool JSON is plain text in the rendered template body
  mitigation_plan:
    - priority: immediate
      action: Implement a strict allowlist for callable tools at the application level and avoid dynamic resolution
      owner: IT Operations
      addresses: CVE-2026-61536
      evidence: Root cause is untrusted resolution in _get_tool_callable
---

The banks library contains a vulnerability in its completion extension where tool definitions are parsed directly from template bodies without validation. An attacker can inject a JSON-serialized `Tool` object into a template, specifying an arbitrary `import_path`. When the application processes the template, `importlib.import_module` is invoked on the attacker-controlled path, allowing the instantiation of any available Python callable. This enables remote code execution (RCE) with the privileges of the host process. This vulnerability persists in version 2.4.2 despite previous fixes for Jinja sandboxing, as the tool resolution logic operates outside the sandboxed environment.

## Attack Chain
1. Attacker gains write access to a prompt registry (e.g., RedisPromptRegistry or shared filesystem).
2. Attacker injects a malicious `{% completion %}` block containing a JSON-serialized `Tool` object.
3. The malicious `Tool` object specifies a high-risk `import_path` (e.g., `os.system`).
4. The application renders the template and calls `Tool.model_validate_json()` to parse the injected JSON.
5. The library calls `_get_tool_callable`, passing the untrusted `import_path` to `importlib.import_module`.
6. The LLM is invoked or prompted to call the function name defined in the malicious tool.
7. The application resolves the callable via `getattr()` and executes it with attacker-supplied arguments.
8. Arbitrary command execution occurs under the application process context.

## Impact
Successful exploitation allows for arbitrary code execution on the server hosting the banks-based application. This impact is significant for environments where prompts are fetched from external or shared sources, potentially leading to full system compromise depending on the process permissions.

## Recommendation
- Upgrade or migrate away from vulnerable implementations using the affected `CompletionExtension` until a vendor-supplied security patch is released.
- Implement a hardcoded allowlist for tool callables at the application level to replace the dynamic `importlib` resolution.
- Audit all prompt storage mechanisms (Redis, file-based registries) to ensure only authorized users can modify template content.
- Restrict process-level permissions for inference services to limit the impact of potential RCE.
