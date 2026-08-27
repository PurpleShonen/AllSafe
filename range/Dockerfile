# Allsafe Range — container image
# INTENTIONALLY VULNERABLE. Run only on an isolated network. See README-WARNING.md.
FROM python:3.12-slim

# Default install = current, patched deps (no known-vulnerable pins).
# To reproduce the A03 finding, add: RUN pip install -r requirements-outdated.txt
WORKDIR /opt/allsafe-range
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV RANGE_DB_PATH=/var/lib/allsafe-range/range.db \
    RANGE_UPLOAD_DIR=/var/lib/allsafe-range/uploads \
    RANGE_LOG_DIR=/var/log/allsafe-range \
    RANGE_TRUST_PROXY=1

RUN mkdir -p /var/lib/allsafe-range /var/log/allsafe-range \
 && useradd --system --no-create-home range \
 && chown -R range:range /var/lib/allsafe-range /var/log/allsafe-range
USER range

EXPOSE 8080
# Rebuild the DB fresh on every start — treat the instance as disposable.
CMD ["sh", "-c", "flask --app run init-db && exec gunicorn -c deploy/gunicorn.conf.py run:app"]
