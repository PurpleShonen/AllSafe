"""Gunicorn config for Allsafe Range. Bind loopback; Apache proxies to it."""
bind = "127.0.0.1:8080"
workers = 2
threads = 2
timeout = 30
# Access logging is handled inside the app (structured JSON). Gunicorn's own
# access log is left off to avoid a second, differently-shaped log.
accesslog = None
errorlog = "-"          # to journald via systemd
loglevel = "info"
proc_name = "allsafe-range"
