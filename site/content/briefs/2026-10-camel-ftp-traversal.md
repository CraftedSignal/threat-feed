---
title: Apache Camel FTP Component Path Traversal Vulnerability
slug: 2026-10-camel-ftp-traversal
description: Apache Camel's camel-ftp component contains a path traversal vulnerability (CVE-2026-79983) allowing unauthorized file operations outside the intended directory via malicious server-supplied file listings.
date: "2026-10-16T13:33:53Z"
lastmod: "2026-10-16T16:27:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:apache:camel:*:*:*:*:*:*:*:*
tags:
  - camel-ftp
  - path-traversal
  - cve-2026-79983
  - apache-camel
vendors:
  - Apache
products:
  - Camel (4.0.0-4.18.4, 4.19.0-4.22.0)
  - Camel
references:
  - https://camel.apache.org/security/CVE-2026-79983.html
  - https://issues.apache.org/jira/browse/CAMEL-24487
  - https://sploitus.com/exploit?id=CC0B874D-1142-508F-B706-2B350284E5A8
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4006
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Apache Camel components to 4.18.5, 4.22.1, or 4.23.0.
      owner: IT Operations
      due: 48h
      evidence: Apache security advisory for CVE-2026-79983.
  mitigation_plan:
    - priority: immediate
      action: Switch FTP connections to SFTP/FTPS to prevent man-in-the-middle listing manipulation.
      owner: Security Engineering
      addresses: CVE-2026-79983
      evidence: Source mitigation guidance.
updates:
  - at: "2026-10-16T16:27:02Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4006
---

Apache Camel, specifically the `camel-ftp` component, is vulnerable to a path traversal issue (CVE-2026-79983) that allows an attacker to read, rename, or delete files outside of the defined polled directory. The vulnerability arises because remote-file consumers construct absolute paths by concatenating the configured polling directory with the file name reported in the server directory listing without sufficient validation or lexical normalization. 

Because the FTP control channel lacks inherent integrity protection, an attacker performing a man-in-the-middle attack or an attacker controlling a malicious or multi-tenant FTP server can inject crafted file names containing directory traversal sequences such as 'd/../../'. If the service is configured with options like 'delete=true', 'move', 'preMove', or 'readLock=rename', the vulnerable consumer may perform these actions on unauthorized files using the credentials of the Camel service itself. The vulnerability affects Camel versions 4.0.0 through 4.18.4 and 4.19.0 through 4.22.0.

## Impact

Successful exploitation allows for unauthorized file access, including reading sensitive system files or deleting/renaming files on the filesystem accessible to the Camel service. In environments where the service account has elevated privileges, this could result in significant data exfiltration or service disruption. The risk is particularly high for implementations using cleartext FTP or those connecting to untrusted or multi-tenant remote FTP servers.

## Recommendation

- Upgrade Apache Camel to version 4.18.5, 4.22.1, 4.23.0, or later to incorporate the fix for CVE-2026-79983.
- If immediate patching is not feasible, migrate from insecure FTP to SFTP or FTPS to ensure transport integrity and verify host certificates to prevent MITM-based listing manipulation.
- Implement strict filters on file consumers using 'antInclude' or 'include' options to restrict processing to expected file name patterns.
- Restrict the permissions of the FTP service account to only the specific directory intended for polling to minimize the scope of potential traversal.
- Monitor application logs for files being processed that appear to resolve outside of the intended root directory, which may indicate exploitation attempts.
