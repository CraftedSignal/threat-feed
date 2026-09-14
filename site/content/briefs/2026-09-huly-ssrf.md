---
title: SSRF Vulnerability in Huly Platform Print Service
slug: 2026-09-huly-ssrf
description: Huly Platform versions up to 0.7.426 contain a server-side request forgery vulnerability that allows authenticated users to access internal metadata services via the print service.
date: "2026-09-14T19:35:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - ssrf
  - vulnerability
vendors:
  - Huly
products:
  - Huly Platform (<= 0.7.426)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505.001
    technique_name: Server Software Component
    evidence: Authenticated workspace members can supply arbitrary URLs to the print endpoint.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91079
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Team
  immediate_actions:
    - action: Upgrade Huly Platform to version > 0.7.426
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-91079 patch status
  mitigation_plan:
    - priority: immediate
      action: Configure network egress rules to block traffic from application servers to 169.254.169.254
      owner: Network Security
      addresses: CVE-2026-91079
      evidence: SSRF vulnerability allows access to internal metadata services
---

Huly Platform versions up to and including 0.7.426 contain a critical server-side request forgery (SSRF) vulnerability within its print service. The flaw stems from insufficient validation of hostnames provided to the print endpoint. Authenticated workspace members can manipulate this endpoint to submit arbitrary URLs. The platform utilizes Puppeteer to render these URLs into downloadable PDF or image files. By exploiting this mechanism, an attacker can coerce the print service into sending requests to sensitive internal network locations, such as cloud metadata services or other locally hosted applications that are not intended to be publicly accessible. This vulnerability poses a significant risk to internal infrastructure by facilitating unauthorized reconnaissance and potential exfiltration of sensitive configuration or data from the local network environment.

## Attack Chain

1. Attacker authenticates as a workspace member within the Huly Platform.
2. Attacker navigates to the print service interface or API endpoint responsible for generating document previews or downloads.
3. Attacker crafts a request containing an internal-only URL (e.g., http://169.254.169.254/latest/meta-data/) as the target for the print rendering function.
4. The Huly print service receives the request and, lacking a hostname allowlist, passes the URL to the underlying Puppeteer rendering engine.
5. The Puppeteer instance initiates an outbound HTTP request to the target URL from the context of the internal Huly application server.
6. The target internal resource returns the requested metadata or sensitive information to the print service.
7. Puppeteer renders the response into a PDF or image file and makes the file available for download by the attacker.
8. Attacker downloads the resulting file to view the contents of the internal resource.

## Impact

Successful exploitation allows authenticated users to bypass perimeter security controls and access internal-only network resources. This can lead to the exposure of cloud instance metadata, internal API credentials, or sensitive network host data. The impact is significant for organizations relying on the Huly Platform in cloud environments where metadata services contain high-value security tokens.

## Recommendation

1. Upgrade Huly Platform instances to a version subsequent to 0.7.426 as soon as a patch is available.
2. Implement strict network egress filtering on the application server hosting the Huly print service to block requests to RFC1918 addresses and cloud provider metadata IPs (e.g., 169.254.169.254).
3. Monitor web server logs for suspicious requests to the print service endpoint that contain internal-only IP addresses or private domain names in the URL parameters.
