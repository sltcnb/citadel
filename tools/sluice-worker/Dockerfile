FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# ── System deps ───────────────────────────────────────────────────────────────
# binutils               → 'strings' command for Strings module
# perl                   → RegRipper (Perl-based)
# unzip                  → Hayabusa + RegRipper zip extraction
# libimage-exiftool-perl → ExifTool metadata extractor
# libjpeg-dev / zlib1g-dev → optional image libraries for ExifTool
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev python3-venv \
    build-essential \
    libmagic1 libmagic-dev \
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
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
COPY tools/sluice-worker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ccl_chromium_reader is required by pyhindsight but is not on PyPI.
# Install from GitHub (has pyproject.toml so pip handles it, including its ccl_simplesnappy dep).
RUN pip install --no-cache-dir \
    "git+https://github.com/cclgroupltd/ccl_chromium_reader.git" \
    && python3 -c "import ccl_chromium_reader; print('ccl_chromium_reader installed OK')"

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
COPY tools/sluice-worker/ .
RUN touch tasks/__init__.py utils/__init__.py

# Built-in plugins baked into the image at a separate path.
# The seed-plugins init container copies these into the shared PVC (/app/babel)
# at pod startup, so they are available at runtime without being overwritten by
# the volume mount.
COPY tools/babel/ /app/babel_builtin/

# Built-in analysis modules — seeded into modules-pvc by the seed-modules init container.
COPY tools/anvil/ /app/anvil_builtin/

# Mount points for shared volumes (populated at runtime by init containers)
RUN mkdir -p /app/babel /app/anvil

# CELERY_CONCURRENCY — number of parallel worker processes per pod replica.
# Default 4 is a good baseline for mixed I/O + CPU workloads.
# For CPU-heavy modules (Hayabusa, Volatility3) set to number of vCPUs assigned.
# For I/O-heavy ingest-only workers set to 8–16.
CMD ["sh", "-c", "celery -A celery_app worker --loglevel=info --concurrency=${CELERY_CONCURRENCY:-4} -Q ingest,modules,default"]
