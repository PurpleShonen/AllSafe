/* ==========================================================================
   Allsafe Client Portal — authentication seam
   --------------------------------------------------------------------------
   THIS IS THE ONLY FILE THAT KNOWS WHERE AUTH LIVES.

   The front end (portal.js) knows one thing: it POSTs a credential pair to
   `endpoint` and receives a verdict. It does not know or care whether the
   endpoint is a hardcoded stub, an LDAP bind against allsafe.local, a Kerberos
   broker, or an OIDC exchange.

   Swapping the backend later = editing this file, and nothing else in the site.

   ---- Request contract -----------------------------------------------------
     POST <endpoint>
     Content-Type: application/json
     { "username": "<string>", "password": "<string>" }

   ---- Response contract ----------------------------------------------------
     Any HTTP status. Body is JSON:
     {
       "status":   "granted" | "denied",   // required
       "message":  "<string shown to the user>",   // required
       "redirect": "<url>"                 // optional; followed when granted
     }

     If the response is not JSON, portal.js falls back to the HTTP status:
     2xx => granted, 401/403 => denied, anything else => error.
     That fallback is what makes a drop-in mod_authnz_ldap protected path work
     without touching the JavaScript.
   ========================================================================== */
window.AllsafePortalAuth = {

  /* Where credentials are submitted.
     - Current stub:      "/portal/login"   (ScriptAlias -> login.cgi)
     - Flask/Node bind:   "/portal/login"   (reverse-proxied to 127.0.0.1:PORT)
     - mod_authnz_ldap:   "/portal/session" (a Location protected by AuthLDAPURL) */
  endpoint: '/portal/login',

  /* Where to land after a successful sign-in when the endpoint does not send
     its own `redirect`. Left as the login page for now — there is no
     authenticated area in this build. */
  successRedirect: null,

  /* Send cookies/credentials with the request. Needed once a real backend
     issues a session cookie; harmless for the stub. */
  withCredentials: true,

  /* Abort the request after this many milliseconds. An LDAP bind against an
     unreachable DC should surface as an error, not a hang. */
  timeoutMs: 8000,

  /* Copy shown under the form when the endpoint is unreachable. */
  errorMessage: 'The sign-in service is not responding. Try again shortly, or call your lead analyst.'
};
