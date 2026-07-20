# ── Builder stage ─────────────────────────────────────────────────────────────
# Carries the compile toolchain (build-essential + dev headers) only long enough
# to build wheels for the source-shipped deps (yara-python, pytsk3, the git-based
# ccl_chromium_reader, …). Wheels are installed --no-index into the runtime stage
# so gcc/build-essential/dev headers never land in the shipped image.
FROM ubuntu:26.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev python3-venv \
    build-essential \
    libmagic-dev libtsk-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Isolated venv so pip is not externally-managed (PEP 668) and wheel building
# stays reproducible.
RUN python3 -m venv /opt/buildenv
ENV PATH="/opt/buildenv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Also wheel the build backend itself: some packages declare setuptools as an
# install requirement, and the runtime stage installs with --no-index, so
# setuptools/wheel/pip must be present in /wheels or that resolve fails
# ("No matching distribution found for setuptools>=61.0").
RUN pip wheel --no-cache-dir pip setuptools wheel -w /wheels

# Build wheels for the pinned requirements (yara-python, pytsk3 compile here).
COPY tools/sluice/worker/requirements.txt requirements.txt
RUN pip wheel --no-cache-dir -r requirements.txt -w /wheels

# ccl_chromium_reader is required by pyhindsight but is not on PyPI. Build it (and
# its ccl_simplesnappy dep) into a wheel from GitHub so the runtime install is
# fully offline.
RUN pip wheel --no-cache-dir -w /wheels \
    "git+https://github.com/cclgroupltd/ccl_chromium_reader.git"

# ── Runtime stage ───────────────────────────────────────────────────────────────
FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# ── System deps (runtime only — no compiler/toolchain) ──────────────────────────
# binutils               → 'strings' command for Strings module
# perl                   → RegRipper (Perl-based)
# unzip                  → Hayabusa + RegRipper zip extraction
# libimage-exiftool-perl → ExifTool metadata extractor
# libmagic1              → runtime lib for python-magic (dev headers live in builder)
# libtsk-dev             → provides the libtsk shared lib the pytsk3 wheel links to
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    libmagic1 \
    wget curl git \
    binutils \
    perl \
    unzip \
    libimage-exiftool-perl \
    libtsk-dev \
    testdisk \
    mono-runtime \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Add GIFT PPA for plaso (Ubuntu 24.04 = noble)
RUN add-apt-repository -y ppa:gift/stable

# ── Hayabusa DFIR binary + rules (Sigma-based EVTX threat hunting) ───────────
# Extract to a temp location, then normalize: copy the *contents* of the
# directory that contains the binary (which also contains rules/ and config/)
# into /opt/hayabusa/ — regardless of whether the zip has a top-level folder.
ARG HAYABUSA_VERSION=3.2.0
RUN wget -q -O /tmp/hayabusa.zip \
         "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-musl.zip" \
    && unzip -q /tmp/hayabusa.zip -d /tmp/hayabusa_extracted \
    && BIN=$(find /tmp/hayabusa_extracted -name "hayabusa-*-lin-x64-musl" -not -name "*.zip" -type f | head -1) \
    && cp -r "$(dirname "$BIN")/." /opt/hayabusa/ \
    && chmod +x "/opt/hayabusa/$(basename "$BIN")" \
    && ln -sf "/opt/hayabusa/$(basename "$BIN")" /usr/local/bin/hayabusa \
    && rm -rf /tmp/hayabusa.zip /tmp/hayabusa_extracted

# ── RegRipper (deep Windows registry analysis, Perl) ─────────────────────────
RUN wget -q -O /tmp/regripper.zip \
         "https://github.com/keydet89/RegRipper3.0/archive/refs/heads/master.zip" \
    && unzip -q /tmp/regripper.zip -d /opt/ \
    && mv /opt/RegRipper3.0-master /opt/regripper \
    && chmod +x /opt/regripper/rip.pl \
    && rm /tmp/regripper.zip

# ── de4dot (.NET assembly deobfuscator, runs under Mono) ─────────────────────
# Uses kant2002/de4dot v3.2.0 net48 build (Mono-compatible Linux binary).
RUN wget -q -O /tmp/de4dot.zip \
         "https://github.com/kant2002/de4dot/releases/download/v3.2.0/de4dot-net48.zip" \
    && unzip -q /tmp/de4dot.zip -d /tmp/de4dot_extracted \
    && mkdir -p /usr/local/lib/de4dot \
    && EXE=$(find /tmp/de4dot_extracted -name "de4dot.exe" -type f | head -1) \
    && cp "$EXE" /usr/local/lib/de4dot/de4dot.exe \
    && printf '#!/bin/sh\nexec mono /usr/local/lib/de4dot/de4dot.exe "$@"\n' \
         > /usr/local/bin/de4dot \
    && chmod +x /usr/local/bin/de4dot \
    && rm -rf /tmp/de4dot.zip /tmp/de4dot_extracted

# ── Plaso (log2timeline/psort) — required for .plaso file parsing ────────────
RUN apt-get update && apt-get install -y --no-install-recommends plaso-tools

# ── Python venv for additional packages (with system site-packages) ──────────
RUN python3 -m venv --system-site-packages /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
# Make the shared contract package importable without runtime sys.path hacks
# (citadel_contracts is COPYed to /app/citadel_contracts).
ENV PYTHONPATH=/app

# ── Python deps (includes pyhindsight for the Hindsight module) ───────────────
# Install the pre-built wheels from the builder stage with no network access —
# fast + reproducible, and no compiler in the runtime image. ccl_chromium_reader
# (required by pyhindsight, not on PyPI) is among the wheels built upstream.
COPY tools/sluice/worker/requirements.txt .
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
    && pip install --no-cache-dir --no-index --find-links=/wheels ccl_chromium_reader \
    && python3 -c "import ccl_chromium_reader; print('ccl_chromium_reader installed OK')" \
    && rm -rf /wheels

# Patch pyhindsight for Python < 3.11 compatibility.
# datetime.UTC was introduced in Python 3.11; replace with datetime.timezone.utc.
RUN python3 -c "import datetime; datetime.UTC" 2>/dev/null || \
    find /opt/venv/lib -name "*.py" -path "*/pyhindsight/*" -exec \
    sed -i 's/datetime\.UTC/datetime.timezone.utc/g' {} \;

# ── Shared contract package ───────────────────────────────────────────────────
# Sluice (this image) loads Babel parser packs that subclass
# citadel_contracts.BasePlugin; it depends on the CONTRACT, not on Babel.
# At /app/citadel_contracts so both the loader and base_plugin's shim resolve it.
COPY tools/citadel_contracts/ /app/citadel_contracts/
RUN pip install --no-cache-dir /app/citadel_contracts

# ── Processor source code ─────────────────────────────────────────────────────
COPY tools/sluice/worker/ .
RUN touch tasks/__init__.py utils/__init__.py

# Built-in plugins baked into the image at a separate path.
# The seed-plugins init container copies these into the shared PVC (/app/babel)
# at pod startup, so they are available at runtime without being overwritten by
# the volume mount.
COPY tools/babel/ /app/babel_builtin/

# Built-in analysis modules — seeded into modules-pvc by the seed-modules init container.
COPY tools/anvil/ /app/anvil_builtin/

# Mount points for shared volumes (populated at runtime by init containers, or
# by named Docker volumes in docker-compose.prod.yml — /app/uploads must exist
# here so a *fresh* named volume inherits uid 1000 on first population instead
# of defaulting to root, which would break writes once the container drops to
# a non-root user below).
RUN mkdir -p /app/babel /app/anvil /app/uploads

# ── Run as non-root ───────────────────────────────────────────────────────────
# This image parses hostile third-party input (forensic artifacts, custom
# analysis modules); it must not run as root. Fixed uid/gid 1000 matches the
# runAsUser/fsGroup already forced at the pod level in k8s/processor/deployment.yaml
# and charts/citadel/values.yaml (podSecurityContext), so ownership lines up
# whether the container is started directly (docker compose) or under k8s.
# chown happens *before* the USER switch so Docker-managed named volumes
# (docker-compose.prod.yml plugins_data/uploads_data) inherit uid 1000 on
# first population instead of root.
# ubuntu:24.04 already ships an "ubuntu" user/group at uid/gid 1000 — reuse it
# instead of colliding with it (useradd -u 1000 fails: "UID 1000 is not unique").
RUN chown -R 1000:1000 /app /opt/venv
USER 1000:1000

# CELERY_CONCURRENCY — number of parallel worker processes per pod replica.
# Default 4 is a good baseline for mixed I/O + CPU workloads.
# For CPU-heavy modules (Hayabusa, Volatility3) set to number of vCPUs assigned.
# For I/O-heavy ingest-only workers set to 8–16.
# Queue order matters: the *_high queues are listed first so Redis always
# hands back a high-priority task ahead of its base-queue twin whenever both
# have pending work (see celery_app.py's task_queues comment).
CMD ["sh", "-c", "celery -A celery_app worker --loglevel=info --concurrency=${CELERY_CONCURRENCY:-4} -Q ingest_high,modules_high,ingest,modules,default"]
