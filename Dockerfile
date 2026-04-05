FROM node:20-bookworm-slim

ARG GITLEAKS_VERSION=8.24.2
ARG OSV_SCANNER_VERSION=2.2.3

ENV DEBIAN_FRONTEND=noninteractive
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  git \
  python3 \
  python3-pip \
  unzip \
  && rm -rf /var/lib/apt/lists/*

# Semgrep (SAST)
RUN pip3 install --no-cache-dir semgrep

# Gitleaks (secrets scanner)
RUN set -eux; \
  arch="$(dpkg --print-architecture)"; \
  case "$arch" in \
    amd64) gitleaks_arch="x64" ;; \
    arm64) gitleaks_arch="arm64" ;; \
    *) echo "Unsupported architecture: $arch"; exit 1 ;; \
  esac; \
  curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gitleaks_arch}.tar.gz" -o /tmp/gitleaks.tgz; \
  tar -xzf /tmp/gitleaks.tgz -C /tmp; \
  install -m 0755 /tmp/gitleaks /usr/local/bin/gitleaks; \
  rm -f /tmp/gitleaks /tmp/gitleaks.tgz

# OSV-Scanner (dependency vulnerability scanner)
RUN set -eux; \
  arch="$(dpkg --print-architecture)"; \
  case "$arch" in \
    amd64) osv_arch="amd64" ;; \
    arm64) osv_arch="arm64" ;; \
    *) echo "Unsupported architecture: $arch"; exit 1 ;; \
  esac; \
  curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${osv_arch}.zip" -o /tmp/osv.zip; \
  unzip /tmp/osv.zip -d /tmp/osv; \
  install -m 0755 /tmp/osv/osv-scanner /usr/local/bin/osv-scanner; \
  rm -rf /tmp/osv /tmp/osv.zip

RUN corepack enable

WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .

ENV NODE_ENV=production
ENV PORT=10000

EXPOSE 10000

CMD ["pnpm", "run", "start:api"]
