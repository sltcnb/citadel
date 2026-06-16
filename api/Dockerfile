FROM python:3.11-slim

WORKDIR /app

# Make the shared contract package importable without runtime sys.path hacks
# (citadel_contracts is COPYed to /app/citadel_contracts below).
ENV PYTHONPATH=/app

# gcc + libtsk-dev so pytsk3 (The Sleuth Kit bindings) compiles — the disk-image
# parser is discovered here for the UI, so its import must succeed too.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libmagic1 libtsk-dev \
    && rm -rf /var/lib/apt/lists/*

# Build context is the repo root — copy api/ sources first
COPY api/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

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
