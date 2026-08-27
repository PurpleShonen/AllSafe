# Client Portal — isolated auth component

Everything the portal needs is in this folder. The rest of the site links to
`portal/index.html` and shares the stylesheet; that is the whole coupling.

```
portal/
├── index.html       Sign-in page (split layout, shared stylesheet)
├── auth-config.js   THE SEAM — endpoint URL + request/response contract
├── portal.js        Transport only: POST creds, render verdict
├── login.cgi        Current backend: hardcoded-credential STUB
└── README.md        this file
```

## The contract

`portal.js` knows exactly one thing about authentication:

```
POST <AllsafePortalAuth.endpoint>
Content-Type: application/json

  { "username": "...", "password": "..." }

→ { "status": "granted" | "denied", "message": "...", "redirect": "<optional>" }
```

If the response body is not JSON, `portal.js` falls back to the HTTP status:
`2xx` → granted, `401`/`403` → denied, anything else → error. That fallback is
deliberate — it is what lets a plain `mod_authnz_ldap`-protected path work with
no JavaScript changes at all.

The front end never sees a directory name, a bind DN, a realm, a group, or a
token format. Keep it that way.

## Current backend: the stub

`login.cgi` compares against a dict of hardcoded credentials and returns the
verdict JSON. It issues no session, enforces no lockout, and applies no rate
limiting. It exists to make the page demonstrable.

| Username | Password |
|---|---|
| `demo.client` | `AllsafeDemo!1` |
| `j.ellis` | `Northgate!2026` |
| `p.mistry` | `Meridian!2026` |

Wired up by `ScriptAlias /portal/login /var/www/allsafe/portal/login.cgi` in
`deploy/allsafe.conf`, which needs `a2enmod cgid`.

Test it directly:

```bash
curl -s -X POST http://allsafe.local/portal/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"demo.client","password":"AllsafeDemo!1"}'
```

## Swapping in real LDAP auth against allsafe.local

Two routes. Both leave `index.html` and `portal.js` untouched.

### Option A — small backend service doing the bind (recommended)

Gives you sessions, lockout, logging, and group checks. Write a ~60-line Flask
or Express service that binds to the DC and returns the same JSON contract.

```python
# sketch only — not part of this build
from ldap3 import Server, Connection, ALL
srv = Server("ldaps://dc01.allsafe.local", get_info=ALL)
try:
    Connection(srv, user=f"{username}@allsafe.local",
               password=password, auto_bind=True).unbind()
    verdict = {"status": "granted", "message": "Signed in."}
except Exception:
    verdict = {"status": "denied", "message": "Username or password not recognised."}
```

Then in Apache (`a2enmod proxy proxy_http`), replacing the `ScriptAlias`:

```apache
ProxyPass        /portal/login http://127.0.0.1:8081/login
ProxyPassReverse /portal/login http://127.0.0.1:8081/login
```

`auth-config.js` needs no change — the endpoint path is the same.

### Option B — Apache-native mod_authnz_ldap

No extra process, but no session and no custom messaging.

```bash
sudo a2enmod authnz_ldap ldap
```

```apache
<Location /portal/session>
    AuthType Basic
    AuthName "Allsafe Client Portal"
    AuthBasicProvider ldap
    AuthLDAPURL "ldaps://dc01.allsafe.local/DC=allsafe,DC=local?sAMAccountName?sub?(objectClass=user)"
    AuthLDAPBindDN "CN=svc_portal,OU=Service Accounts,DC=allsafe,DC=local"
    AuthLDAPBindPassword "exec:/usr/local/bin/portal-bind-pw"
    Require ldap-group CN=Portal Users,OU=Groups,DC=allsafe,DC=local
</Location>
```

Then one line in `auth-config.js`:

```js
endpoint: '/portal/session',
```

Basic auth expects an `Authorization` header rather than a JSON body, so with
this option you would send the credentials that way instead — the one place
`portal.js` would need a small change. Option A avoids that entirely, which is
why it is the recommended route.

## When you do wire up real auth

The stub skips all of this on purpose. A real deployment needs:

- **TLS.** Do not send directory credentials over plain HTTP. Enable the HTTPS
  vhost before this goes anywhere near a real DC.
- **A dedicated service account** for the bind, with no privileges beyond
  reading the attributes it needs, and a password sourced from outside the
  config file (`exec:` above, or a systemd credential).
- **Lockout and rate limiting**, at the backend rather than in the browser.
- **Logging of failed binds** to somewhere Wazuh reads — the marketing site's
  Apache access log will show the `401`s, but the reason lives in the backend.
- **Generic failure messages.** `login.cgi` already returns the same text for an
  unknown username and a wrong password; keep that property.
