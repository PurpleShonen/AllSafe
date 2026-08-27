# Allsafe Cybersecurity — marketing site

Static HTML5 / CSS3 / vanilla JS. No framework, no build step, no package
manager. The contents of this folder drop straight into `/var/www/allsafe`.

Fictional company, original copy. Nothing here is lifted from *Mr. Robot* or
from any real security vendor.

---

## File structure

```
site/
├── index.html              Home — hero, service cards, client strip, CTA
├── services.html           Services — MDR, pentest, IR, GRC, training
├── about.html              About — history, mission, leadership grid
├── careers.html            Careers — four placeholder listings
├── contact.html            Contact — non-functional form + office details
├── README.md               this file
│
├── assets/
│   ├── css/style.css       Single stylesheet for the whole site (incl. portal)
│   ├── js/main.js          Mobile nav toggle, active-link marking, year stamp
│   └── img/favicon.svg     Server-rack circle mark
│
├── portal/                 ISOLATED COMPONENT — see "Portal seam" below
│   ├── index.html          Sign-in page
│   ├── auth-config.js      The seam: endpoint + request/response contract
│   ├── portal.js           Transport only; knows nothing about auth method
│   ├── login.cgi           Hardcoded-credential STUB backend
│   └── README.md           How to swap the stub for real LDAP auth
│
└── deploy/
    └── allsafe.conf        Reference VirtualHost for sites-available/
```

The logo is inline SVG in every page (header, footer, portal) plus a standalone
copy at `assets/img/favicon.svg` for the favicon. There is no raster image
asset anywhere in the site.

Header and footer markup is duplicated per page — that is the cost of having no
build step, and it is deliberate. If you edit the nav, edit it in all five root
pages plus `portal/index.html`.

---

## Deployment on Ubuntu

### 1. Install Apache and enable modules

```bash
sudo apt update
sudo apt install -y apache2
sudo a2enmod rewrite headers expires cgid
# sudo a2enmod ssl        # only if serving HTTPS
```

`cgid` is required only by the portal auth stub. See the portal README if you
replace it.

### 2. Copy the site into place

```bash
sudo mkdir -p /var/www/allsafe
sudo rsync -a --delete --exclude 'README.md' --exclude 'deploy/' \
    ./site/ /var/www/allsafe/
```

`README.md` and `deploy/` are excluded from the web root; the VirtualHost also
denies `.md` and `.conf` requests as a second line of defence.

### 3. Ownership and permissions

Apache runs as `www-data` on Ubuntu. It only needs to *read* the site — nothing
here is written at runtime, so do not give the web root group write access.

```bash
sudo chown -R root:www-data /var/www/allsafe
sudo find /var/www/allsafe -type d -exec chmod 750 {} \;
sudo find /var/www/allsafe -type f -exec chmod 640 {} \;
sudo chmod 750 /var/www/allsafe/portal/login.cgi     # must be executable
```

If you would rather have a deploy user own the tree, `chown -R deploy:www-data`
works the same way — the requirement is that `www-data` can read (and traverse)
everything, and can execute `login.cgi`.

### 4. Install the VirtualHost

```bash
sudo cp site/deploy/allsafe.conf /etc/apache2/sites-available/allsafe.conf
sudo a2ensite allsafe
sudo a2dissite 000-default          # optional: drop the Ubuntu default page
sudo apache2ctl configtest
sudo systemctl reload apache2
```

### 5. Name resolution

`allsafe.local` needs to resolve. In the home lab this is normally an A record
on the domain controller. For a quick local test, add to `/etc/hosts` on the
client machine:

```
192.0.2.10   allsafe.local www.allsafe.local
```

### 6. Verify

```bash
curl -I http://allsafe.local/
curl -s -X POST http://allsafe.local/portal/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"demo.client","password":"AllsafeDemo!1"}'
```

The second command should return `{"status": "granted", ...}`.

---

## Portal seam (short version)

The client portal lives entirely in `portal/`. Its front end posts JSON
credentials to one configurable endpoint and renders whatever verdict comes
back. It makes no assumption about how the credentials are checked.

Today that endpoint is a CGI stub with hardcoded credentials. To move to a real
LDAP bind against `allsafe.local`, change the `ScriptAlias` in
`deploy/allsafe.conf` and the `endpoint` value in `portal/auth-config.js`.
Nothing else in the site changes. Full detail in `portal/README.md`.

**Demo credentials:** `demo.client` / `AllsafeDemo!1` (also `j.ellis` /
`Northgate!2026`, `p.mistry` / `Meridian!2026`).

---

## Logs

Both files should be picked up by the Splunk Universal Forwarder on WEB01 and
sent to SPLUNK01:

| File | Contents |
|---|---|
| `/var/log/apache2/allsafe_access.log` | Combined-format request log for the vhost |
| `/var/log/apache2/allsafe_error.log` | Apache errors, including CGI stderr from `login.cgi` |

Failed portal sign-ins appear as `POST /portal/login` with status `401` in the
access log. That is the marketing site's only interesting authentication signal.

---

## Local preview without Apache

Every path in the site is relative, so `file:///.../site/index.html` renders
correctly for layout work. The portal form will report *"Sign-in unavailable"*
because there is no CGI handler — that is expected. For a closer preview:

```bash
python3 -m http.server 8000 --directory site
```

Still no CGI, so the portal form still cannot succeed; use Apache to exercise it.

---

## Browser support

Modern evergreen browsers. `fetch`, `AbortController`, CSS custom properties,
`aspect-ratio`, and CSS grid are all used without polyfills.
