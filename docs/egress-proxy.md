# Outbound proxy

Optional. Routes every call AVRON makes — the detection model, all providers,
and both connection tests — through an HTTP proxy, so provider traffic leaves
from one address you control.

Reasons to bother: a fixed egress IP for a provider's allow-list, reaching a
provider from a permitted region, or separating model traffic from the rest of
your outbound.

AVRON does not ship a proxy. Point it at whatever you already run — Squid,
HAProxy, a cloud NAT gateway, a corporate egress proxy.

## Configuring it

**Egress** in the console:

| Field | Notes |
|---|---|
| Enable | Off by default |
| Proxy address | `http://user:pass@host:3128`. Stored encrypted. |
| Bypass list | Hosts that must never go through the proxy |

Percent-encode any `@` in the password as `%40`. Otherwise
`http://user:p@ss@host:3128` parses the host as `ss@host` and fails in a way
that looks like an authentication error.

**The bypass list is not optional.** It must contain your container names —
`avron`, and any local provider. Sending container-to-container traffic out
through an external proxy fails in a way that looks like broken DNS rather than
a proxy misconfiguration.

## Verifying

**Check where traffic exits** shows the exit IP with and without the proxy side
by side. Two different addresses means it is working. The same address twice
means the proxy is on this host and nothing has changed.

From the shell, against the proxy directly:

```bash
U="http://user:pass@10.0.0.5:3128"
curl -x "$U" -s https://api.ipify.org; echo          # should be the proxy's IP
curl -x "$U" https://api.openai.com/v1/models -s -o /dev/null -w '%{http_code}\n'
```

Note that `curl` reports `000` whenever a CONNECT tunnel fails to open, even
when the proxy correctly answered 407 or 403. Read the verbose output with
`-sv`, not the status code.

## If you are building the proxy

Two settings matter more than the rest:

- **Require authentication.** An open proxy on a public IP is found by scanners
  within hours.
- **Restrict CONNECT to 443.** Without it, anything that reaches the proxy can
  tunnel to SMTP or SSH with your egress host as the source. That is the
  difference between a proxy and an open relay.

Also worth knowing: a CONNECT proxy tunnels TLS without decrypting, so it never
sees request bodies. It knows which host was contacted and when — good for
confidentiality, and it means the access log is a metadata trail of which
provider handled what.

## A gotcha that costs an afternoon

**Node's built-in `fetch` ignores `HTTPS_PROXY`.** Setting the environment
variable does nothing for an application using `fetch` without an explicit
`ProxyAgent`. If a Node-based upstream seems to ignore your proxy, use that
application's own proxy setting instead. AVRON passes the proxy explicitly to
httpx, so its Egress setting always applies.
