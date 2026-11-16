# Hosted demo: the dashboard plus everything it starts (SuperLink, three SuperNodes, the attacks),
# all inside one container. Build: docker build -t pqc-flower .
# Run:   docker run -p 8765:8765 -e DASHBOARD_PASSWORD=... pqc-flower   then open http://localhost:8765
FROM python:3.12-slim

# lsof/procps: run_local.sh checks ports and stops leftover processes; openssl/ssh-keygen: test credentials
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash curl lsof procps openssl openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir uv==0.12.23

WORKDIR /app
ENV UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

COPY . .
# Dataset, CA + TLS certificate, ECDSA and ML-DSA-65 farm keys: demo credentials made inside the image
RUN uv sync --frozen --no-dev \
 && mkdir -p data && scripts/get_data.sh \
 && scripts/gen_credentials.sh 3 \
 && .venv/bin/python -m pqcflower.signing 3 \
 && .venv/bin/python -m pqcflower.pqc_login 3

ENV DASHBOARD_HOST=0.0.0.0 DASHBOARD_PORT=8765 PYTHONUNBUFFERED=1
EXPOSE 8765
CMD [".venv/bin/python", "dashboard/server.py"]
