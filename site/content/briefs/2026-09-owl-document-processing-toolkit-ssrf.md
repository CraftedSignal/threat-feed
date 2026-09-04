---
title: SSRF Vulnerability in OWL DocumentProcessingToolkit
slug: 2026-09-owl-document-processing-toolkit-ssrf
description: The OWL DocumentProcessingToolkit is vulnerable to server-side request forgery in the extract_document_content tool, allowing attackers to perform prompt injection to exfiltrate internal resources.
date: "2026-09-04T15:31:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:owl:documentprocessingtoolkit:*:*:*:*:*:*:*:*
vendors:
  - OWL
products:
  - DocumentProcessingToolkit
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can inject malicious URLs through prompt injection to make the server fetch internal resources, with responses returned to the agent context.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: Attackers can inject malicious URLs through prompt injection to make the server fetch internal resources, with responses returned to the agent context.
    confidence_band: high
cves:
  - id: CVE-2026-85675
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85675
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Restrict network egress from systems running DocumentProcessingToolkit to prevent internal access
      owner: Security Engineering
      due: 24h
      evidence: Source describes SSRF vulnerability requiring internal resource access
  mitigation_plan:
    - priority: immediate
      action: Monitor vendor channels for security patches addressing CVE-2026-85675
      owner: IT Operations
      addresses: CVE-2026-85675
      evidence: Source identifies vulnerability requiring patch
---

The OWL DocumentProcessingToolkit contains a critical server-side request forgery (SSRF) vulnerability within its extract_document_content tool. This flaw originates from a failure to perform adequate validation on caller-supplied URLs, specifically lacking necessary filtering for schemes, hosts, or IP addresses. Attackers can leverage prompt injection techniques to manipulate the input provided to the tool, compelling the server to perform requests against arbitrary internal network resources. Because the tool is designed to return the results of these fetches directly into the agent context, an attacker can effectively bridge the gap between public-facing inputs and protected internal network segments, potentially exfiltrating sensitive data that would otherwise be unreachable. This vulnerability poses a significant risk to any organization deploying the toolkit in an environment where the agent has access to internal endpoints.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to internal resources by leveraging the server as a proxy. This can lead to the exfiltration of sensitive internal data, metadata, or configuration details, depending on the network services exposed internally. The impact is elevated by the automated nature of agent-based systems, which may grant the attacker seamless access to internal APIs or internal-only documentation services.

## Recommendation

Prioritize the immediate application of patches or vendor-provided updates for the DocumentProcessingToolkit as soon as they become available. Implement strict egress filtering on any server running the toolkit, restricting its ability to communicate with internal IP ranges or reserved network segments unless explicitly required for legitimate business processes. Ensure that any input provided to agentic tools is subjected to strict schema validation and allowlisting of URL schemes before being passed to the processing logic. Monitor webserver and application logs for unusual outbound request patterns originating from the DocumentProcessingToolkit process, specifically looking for requests directed at private network identifiers or internal hostnames.
