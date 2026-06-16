"""
Pilot — Citadel's autonomous DFIR investigation agent.

The engine (LLM client, agent loop, tools, prompts, run lifecycle) lives in
``pilot.service``. It is pip-installed into the API image; the FastAPI router is
re-exported through the thin ``api/routers/llm_config.py`` shim so existing
routes/imports keep working. The agent reaches Elasticsearch/Redis/modules via
the API app on ``PYTHONPATH=/app`` (same model as the other in-image tools).
"""
