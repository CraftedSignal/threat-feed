---
title: AsyncHttpClient Credential Exposure via Authentication Downgrade
slug: 2026-10-asynchttpclient-downgrade
description: A vulnerability in AsyncHttpClient causes a fallback to Basic authentication when receiving a malformed Digest challenge, leading to cleartext credential exposure via base64-encoded headers.
date: "2026-10-08T19:29:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cves:
  - id: CVE-2026-107231
---

AsyncHttpClient (v2.x through 2.16.0 and v3.x through 3.0.12) contains a vulnerability (CVE-2026-107231) in its handling of Digest authentication challenges. The implementation of `parseWWWAuthenticateHeader` and `parseProxyAuthenticateHeader` incorrectly defaults to Basic authentication if a Digest challenge fails to provide a usable nonce. 

An attacker who can influence the authentication challenge (such as a compromised origin server, malicious proxy, or an adversary performing a man-in-the-middle attack) can provide a malformed `WWW-Authenticate` header. By omitting the nonce or providing a quoted parameter containing an unescaped backslash, the attacker forces the client to downgrade the request to Basic authentication. The client then sends the username and password in an `Authorization: Basic` header, which is base64-encoded and trivially reversible. This flaw permits credential harvesting against services that the user intends to authenticate with via secure Digest mechanisms, particularly when the exchange occurs over plaintext HTTP.

## Impact

The vulnerability results in the exposure of user credentials to unauthorized parties, including malicious proxies or attackers on the network path. Credentials harvested via this downgrade can be reused by attackers to authenticate against the target service or other services where the user
