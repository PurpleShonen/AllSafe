# Allsafe Range — deployment guide

> ⚠️ Intentionally vulnerable. Deploy only on an isolated, disposable VM. See
> [`../README-WARNING.md`](../README-WARNING.md).

Two supported shapes:

- **A.** systemd + gunicorn behind Apache on a dedicated VM (recommended for the
  "real external scan traffic" goal).
- **B.** Docker Compose (fastest to stand up and tear down).

---

## Deployment model — the recommended one

Run Allsafe Range on a **small, isolated cloud VM** (a cheap DigitalOcean /
Linode / Hetzner droplet), **not** on the home network. This gets you genuine
external-IP scan and attack traffic — real log data — with zero blast radius
into the home lab. Snapshot the VM, run a session, roll back.

Logs are shipped **back to the home-lab Wazuh instance over a WireGuard tunnel**,
so the SIEM is never exposed to the internet. The droplet reaches in over the
tunnel to deliver logs; nothing reaches the other way.

```
   Internet ──▶ [ droplet: Apache :80/:443 ] ──▶ 127.0.0.1:8080 (gunicorn)
                        │                                │
                        └── range_access/error.log       └── /var/log/allsafe-range/*.log
                                     │                                │
                                     └──────── WireGuard tunnel ──────┘
                                                    │
                                     [ home lab: Wazuh manager 10.66.0.1 ]
```

If you would rather run it on an isolated home-lab VLAN instead, that's fine —
you just trade real external traffic for a network you fully control. Everything
below still applies; skip the cloud-firewall section.

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

To expose it for external scan traffic on the droplet, change the port mapping
to `80:8080` (and ideally still front it with Apache/TLS). Otherwise it stays
bound to loopback.

---

## Firewalling the isolated cloud VM

Lock the droplet down to only what it needs. Example with `ufw`:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp                 # SSH (ideally key-only, or via the tunnel)
sudo ufw allow 80/tcp                 # the range (the traffic you want)
sudo ufw allow 443/tcp               # if serving TLS
sudo ufw allow in on wg0             # WireGuard tunnel interface (log shipping)
sudo ufw enable
```

Better: move SSH itself onto the WireGuard tunnel and drop `22/tcp` from the
public interface entirely, so only `80`/`443` face the internet.

The app process never listens on a public interface — Apache is the only
ingress, and gunicorn is on `127.0.0.1:8080`.

---

## Log shipping to the home-lab Wazuh instance

Ship **both** the app's JSON logs and Apache's own logs. Two options.

### Option 1 — Wazuh agent (simplest if you already run Wazuh)

Install the Wazuh agent on the droplet, point it at the manager's **WireGuard**
address, and add these `localfile` blocks to
`/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/allsafe-range/app.log</location>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/var/log/allsafe-range/access.log</location>
</localfile>
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/range_access.log</location>
</localfile>
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/range_error.log</location>
</localfile>
```

The agent connects **outbound** to the manager over the tunnel (1514/udp or
1514/tcp), so the SIEM never needs an inbound rule from the internet.

### Option 2 — Filebeat or rsyslog

If you ship to OpenSearch/Logstash rather than the Wazuh agent, use
[`filebeat-allsafe-range.yml`](filebeat-allsafe-range.yml) (JSON parsing already
configured) or [`rsyslog-allsafe-range.conf`](rsyslog-allsafe-range.conf). Point
the output at the collector's **tunnel** address (e.g. `10.66.0.1`), never a
public IP.

### WireGuard, in brief

On both the droplet and the home-lab collector:

```ini
# /etc/wireguard/wg0.conf  (droplet side)
[Interface]
Address = 10.66.0.2/24
PrivateKey = <droplet-private-key>

[Peer]                        # home-lab endpoint
PublicKey = <homelab-public-key>
Endpoint = <home-public-ip-or-ddns>:51820
AllowedIPs = 10.66.0.0/24
PersistentKeepalive = 25
```

```bash
sudo apt install -y wireguard
sudo systemctl enable --now wg-quick@wg0
ping 10.66.0.1                # the home-lab collector over the tunnel
```

Now every log path in the table below reaches Wazuh over an encrypted tunnel,
and the only internet-facing ports on the droplet are the ones serving the range
itself.

| Source | Path on droplet | View it gives |
|---|---|---|
| App requests | `/var/log/allsafe-range/access.log` | Parsed params, `suspected` tags |
| App events | `/var/log/allsafe-range/app.log` | Security events (the interesting ones) |
| Apache access | `/var/log/apache2/range_access.log` | Edge view: raw bytes, TLS, malformed reqs |
| Apache errors | `/var/log/apache2/range_error.log` | Proxy/500 errors |

---

## Rebuild / teardown

- **systemd:** `sudo systemctl restart allsafe-range` reseeds the DB.
- **Docker:** `docker compose down -v && docker compose up --build -d`.
- **VM:** roll back to the pre-session snapshot. Treat the instance as
  disposable — that is the operating model, not a fallback.
