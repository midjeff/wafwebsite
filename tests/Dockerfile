FROM python:3.12.15-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
WORKDIR /checks
COPY tests/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY tests/ ./
ENTRYPOINT ["python", "http_checks.py"]
