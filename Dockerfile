ARG PYTHON_IMAGE=python:3.12.15-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 portal && useradd -u 10001 -g portal -M portal \
    && mkdir -p /data && chown portal:portal /data
RUN /usr/sbin/setcap -r /usr/bin/ping
WORKDIR /srv
COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
ARG APP_DIR=app
COPY --chown=portal:portal ${APP_DIR}/ /srv/portal/
USER 10001:10001
EXPOSE 5000
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=12 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=2)"
CMD ["waitress-serve", "--host=0.0.0.0", "--port=5000", "--threads=4", "--call", "portal.main:create_app"]
