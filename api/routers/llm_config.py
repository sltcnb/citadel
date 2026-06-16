"""
Compatibility shim — the LLM / Pilot engine now lives in the ``pilot`` package
(tools/pilot/pilot/service.py), pip-installed into the API image.

Every name (router, endpoints, helpers, private functions) is re-exported here
so existing imports keep working unchanged:

    from routers.llm_config import _get_config, _call_llm, generate_sigma_yaml, ...
    app.include_router(llm_config.router, ...)

Nothing else should be added to this file — edit pilot/service.py instead.
"""

from pilot import service as _service

# Mirror the engine module's namespace (public + private) into this shim so any
# `from routers.llm_config import X` resolves to the real implementation.
globals().update(
    {
        k: v
        for k, v in vars(_service).items()
        if not (k.startswith("__") and k.endswith("__"))
    }
)

# The FastAPI router main.py registers.
router = _service.router
