# ── Builder stage ─────────────────────────────────────────────────────────────
# Carries the compile toolchain (gcc/g++) + libtsk-dev headers only long enough
# to build wheels for the deps that ship as source (yara-python, pytsk3, …).
# The resulting wheels are installed into the slim runtime stage with --no-index,
# so gcc/g++/dev headers never land in the shipped image.
FROM python:3.14-slim AS builder

# Toolchain + native headers so the source-built wheels compile here (not at
# runtime): gcc/g++, libtsk-dev for pytsk3 (whose ./configure also needs `file`,
# make + autotools) and libssl-dev/pkg-config for yara-python 4.3.1's bundled
# libyara authenticode module (needs openssl/asn1.h).
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ make file autoconf automake libtool pkg-config \
    libssl-dev libtsk-dev \
    && rm -rf /var/lib/apt/lists/*

# Build context is the repo root — copy api/ requirements first.
COPY api/requirements.txt requirements.txt
# Pin-preserving: pip wheel resolves the exact pinned versions from requirements
# and writes them (plus their transitive deps) to /wheels for offline install.
RUN pip wheel --no-cache-dir -r requirements.txt -w /wheels

# ── Runtime stage ───────────────────────────────────────────────────────────────
FROM python:3.14-slim

WORKDIR /app

# Make the shared contract package importable without runtime sys.path hacks
# (citadel_contracts is COPYed to /app/citadel_contracts below).
ENV PYTHONPATH=/app

# Runtime libs only — no compiler/toolchain. libtsk-dev provides the libtsk
# shared library that the pytsk3 wheel links against at import time; libmagic1
# for python-magic; the WeasyPrint (report.pdf) Pango/Cairo/GDK-Pixbuf + font
# stack; libssl is provided by the base image.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 libtsk-dev \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libcairo2 \
    libffi8 shared-mime-info fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Install the pre-built wheels with no network access — fast + reproducible.
COPY api/requirements.txt requirements.txt
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

COPY api/ .

# Shared contract package — API + parser packs depend on it (BasePlugin /
# ForensicEvent helpers). At /app/citadel_contracts so base_plugin's re-export
# shim (parents[1]) resolves it.
COPY tools/citadel_contracts/ /app/citadel_contracts/
RUN pip install --no-cache-dir /app/citadel_contracts

# Scribe — report rendering engine (Markdown / graphical HTML). Tool code lives
# in tools/scribe; the API only gathers data and calls it.
COPY tools/scribe/ /app/scribe_pkg/
RUN pip install --no-cache-dir /app/scribe_pkg

# Pilot — autonomous DFIR agent engine (LLM loop + tools). Tool code lives in
# tools/pilot; api/routers/llm_config.py is a thin re-export shim. The engine
# reaches ES/Redis/modules via the api app already on PYTHONPATH=/app.
COPY tools/pilot/ /app/pilot_pkg/
RUN pip install --no-cache-dir /app/pilot_pkg

# Sigil detection-rule content (its own repo/submodule at tools/sigil).
COPY tools/sigil/ /app/sigil/
ENV CITADEL_RULES_DIR=/app/sigil

# Bake the artifact collector script into the image so the download
# endpoint always works — regardless of whether the volume mount is present.
RUN mkdir -p /app/collector
COPY tools/talon/collect.py /app/collector/collect.py
COPY tools/talon/fo_uploader.py /app/collector/fo_uploader.py


# Tool capability manifests — each tool repo ships capabilities.yaml; collect
# them into /app/capabilities/<tool>.yaml so GET /tools/capabilities can render
# the UI from each tool's own declaration (true tool/orchestrator separation).
COPY tools/ /tmp/tools/
RUN mkdir -p /app/capabilities \
    && for d in /tmp/tools/*/; do \
         f="${d}capabilities.yaml"; \
         [ -f "$f" ] && cp "$f" "/app/capabilities/$(basename "$d").yaml" || true; \
       done \
    && rm -rf /tmp/tools \
    && ls -1 /app/capabilities/ || true
ENV CAPABILITIES_DIR=/app/capabilities

# Built-in analysis modules — seeded into modules-pvc by the seed-modules init container.
COPY tools/anvil/ /app/anvil_builtin/
RUN mkdir -p /app/anvil /app/static

# Ensure all internal packages have __init__.py stubs
RUN touch routers/__init__.py services/__init__.py auth/__init__.py

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
