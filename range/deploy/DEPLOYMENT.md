# Allsafe Range — deployment guide

> ⚠️ Intentionally vulnerable. Deploy only inside the lab, on a VM you can roll
> back. Never port-forward it to the internet. See
> [`../README-WARNING.md`](../README-WARNING.md).

Two supported shapes:

- **A.** systemd + gunicorn behind Apache on WEB01 (recommended).
- **B.** Docker Compose (fastest to stand up and tear down).

---

## Deployment model — the recommended one

Allsafe Range runs on **WEB01** (Ubuntu 26.04) alongside the marketing site, as
a second Apache VirtualHost. WEB01 sits on the SOC-LAB vSwitch with the rest of
the lab, so log shipping to SPLUNK01 is a plain internal connection — no tunnel,
no public exposure.

```
   SOC-LAB vSwitch
        │
        ├─▶ [ WEB01 : Apache :80/:443 ] ──▶ 127.0.0.1:8080 (gunicorn)
        │            │                              │
        │            └── range_access/error.log     └── /var/log/allsafe-range/*.log
        │                         │                              │
        │                         └────── Splunk UF ─────────────┘
        │                                     │
        └─────────────────────────▶ [ SPLUNK01 : 9997 ]
```

Attacks come from WIN11-01 or ANALYST01 on the same switch — you drive them
yourself rather than waiting for internet scan traffic. You trade real
external noise for a network you fully control and can replay deliberately.

> ⚠️ **Blast radius.** Range is intentionally vulnerable, and on this layout it
> shares a host with the marketing site. A successful exploit gets code
> execution as `allsafe-range` on WEB01. That is acceptable for a lab you can
> rebuild — snapshot WEB01 before a session and roll back after — but it is a
> real trade against the isolation the app's own
> [`README-WARNING.md`](../README-WARNING.md) asks for. If you would rather keep
> the separation, give Range its own VM on the vSwitch; everything below applies
> unchanged except the vhost lives alone.

---

## A. systemd + gunicorn behind Apache

### 1. System user and directories

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin allsafe-range
sudo mkdir -p /opt/allsafe-range /var/lib/allsafe-range/uploads /var/log/allsafe-range
```

### 2. Deploy the code

```bash
sudo rsync -a --exclude '.venv' --exclude 'data' --exclude 'logs*' \
    ./range/ /opt/allsafe-range/
sudo python3 -m venv /opt/allsafe-range/.venv
sudo /opt/allsafe-range/.venv/bin/pip install -r /opt/allsafe-range/requirements.txt
# For the A03 finding, ALSO: pip install -r requirements-outdated.txt

sudo chown -R allsafe-range:allsafe-range /opt/allsafe-range \
    /var/lib/allsafe-range /var/log/allsafe-range
```

### 3. Service

```bash
sudo cp /opt/allsafe-range/deploy/allsafe-range.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now allsafe-range
systemctl status allsafe-range
curl -s http://127.0.0.1:8080/healthz
```

The unit runs `flask --app run init-db` on every start, so each restart is a
clean seed. It binds loopback only.

### 4. Apache reverse proxy

```bash
sudo a2enmod proxy proxy_http headers remoteip
sudo cp /opt/allsafe-range/deploy/range.allsafe.local.conf \
        /etc/apache2/sites-available/
sudo a2ensite range.allsafe.local
sudo apache2ctl configtest
sudo systemctl reload apache2
```

To take the vulnerable app offline instantly without touching the marketing
site: `sudo a2dissite range.allsafe.local && sudo systemctl reload apache2`.

> The range vhost is a **separate file** from the marketing site's
> `allsafe.conf` on purpose, so the two enable/disable independently.

---

## B. Docker Compose

```bash
docker compose up --build -d        # http://127.0.0.1:8080 by default
docker compose logs -f range
docker compose down -v              # tear down INCLUDING data volumes
```

To reach it from elsewhere on the vSwitch, change the port mapping to
`80:8080` (and ideally still front it with Apache/TLS). Otherwise it stays bound
to loopback.

---

## Firewalling WEB01

Lock WEB01 down to what the lab actually needs. Example with `ufw`:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp                 # SSH from ANALYST01 (key-only)
sudo ufw allow 80/tcp                 # the range + marketing site
sudo ufw allow 443/tcp                # if serving TLS
sudo ufw enable
```

The Splunk UF connects **outbound** to SPLUNK01:9997, so no inbound rule is
needed for log shipping. Nothing here should be port-forwarded from your Fedora
host to the internet — the range is meant to be reachable from inside the
vSwitch only.

The app process never listens on a public interface — Apache is the only
ingress, and gunicorn is on `127.0.0.1:8080`.

---

## Log shipping to SPLUNK01

Ship **both** the app's JSON logs and Apache's own logs.

### Option 1 — Splunk Universal Forwarder (the lab's SIEM path)

Install the UF on WEB01 and drop in the three configs from this directory:

```bash
# Create the index on SPLUNK01 first: Settings > Indexes > New Index > allsafe_range

sudo cp /opt/allsafe-range/deploy/splunk-inputs.conf \
        /opt/splunkforwarder/etc/system/local/inputs.conf
sudo cp /opt/allsafe-range/deploy/splunk-outputs.conf \
        /opt/splunkforwarder/etc/system/local/outputs.conf
sudo /opt/splunkforwarder/bin/splunk restart
```

`splunk-props.conf` goes on **SPLUNK01**, not on WEB01 — see the header comment
in that file for why (it changes if you switch to index-time extraction).

The UF runs as root or as a dedicated `splunk` user; either way it needs read
access to `/var/log/allsafe-range/` and `/var/log/apache2/`. If the UF runs
unprivileged, add it to the `adm` group:

```bash
sudo usermod -aG adm splunk
```

Confirm the data is arriving, on SPLUNK01:

```
index=allsafe_range | stats count by sourcetype
```

You should see all four sourcetypes: `allsafe:range:app`,
`allsafe:range:access`, `access_combined`, `apache_error`.

### Option 2 — Filebeat or rsyslog (alternative shippers)

Kept for anyone pointing this at Elastic/OpenSearch or a Wazuh manager instead
of Splunk. Use [`filebeat-allsafe-range.yml`](filebeat-allsafe-range.yml) (JSON
parsing already configured) or
[`rsyslog-allsafe-range.conf`](rsyslog-allsafe-range.conf), and point the output
at your collector's address on the vSwitch. These are **not** used by the
default lab build — pick one shipper, not two, or you will double-index.

| Source | Path on WEB01 | View it gives |
|---|---|---|
| App requests | `/var/log/allsafe-range/access.log` | Parsed params, `suspected` tags |
| App events | `/var/log/allsafe-range/app.log` | Security events (the interesting ones) |
| Apache access | `/var/log/apache2/range_access.log` | Edge view: raw bytes, TLS, malformed reqs |
| Apache errors | `/var/log/apache2/range_error.log` | Proxy/500 errors |

---

## Rebuild / teardown

- **systemd:** `sudo systemctl restart allsafe-range` reseeds the DB.
- **Docker:** `docker compose down -v && docker compose up --build -d`.
- **VM:** roll back WEB01 to the pre-session snapshot. Snapshot before every
  session — with the range sharing a host with the marketing site, the snapshot
  is what keeps the blast radius at zero.
