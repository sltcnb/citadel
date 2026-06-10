.PHONY: help dev build push deploy undeploy logs

REGISTRY   ?= localhost:5000
TAG        ?= latest
NAMESPACE  := citadel

help:
	@echo "Citadel — Kubernetes forensics analysis platform"
	@echo ""
	@echo "  make dev          Start local dev stack with docker-compose (no K8s needed)"
	@echo "  make deploy       Full K8s deploy — reads config.json, sets up cluster"
	@echo "  make status       Show all pods and services"
	@echo "  make destroy      Delete cluster and all data"
	@echo "  make logs-api     Stream API logs"
	@echo "  make logs-proc    Stream processor logs"
	@echo "  make reload-plugins  Hot-reload plugins without pod restart"
	@echo "  make shell-api    Shell into API pod"
	@echo "  make shell-proc   Shell into processor pod"

# ── Local development (no Kubernetes) ─────────────────────────────────────────
dev:
	docker compose up --build

dev-down:
	docker compose down -v

# ── Kubernetes — all-in-one via deploy.py ─────────────────────────────────────
deploy:
	python3 deploy.py

deploy-no-build:
	python3 deploy.py --no-build

status:
	python3 deploy.py --status

destroy:
	python3 deploy.py --destroy

undeploy: destroy

# ── Logs ───────────────────────────────────────────────────────────────────────
logs-api:
	kubectl logs -n $(NAMESPACE) -l app=api -f --tail=100

logs-proc:
	kubectl logs -n $(NAMESPACE) -l app=processor -f --tail=100

logs-frontend:
	kubectl logs -n $(NAMESPACE) -l app=frontend -f --tail=100

# ── Debugging ──────────────────────────────────────────────────────────────────
shell-api:
	kubectl exec -it -n $(NAMESPACE) deploy/api -- bash

shell-proc:
	kubectl exec -it -n $(NAMESPACE) deploy/processor -- bash

reload-plugins:
	curl -X POST http://localhost:8000/api/v1/plugins/reload
	@echo ""
	@echo "Plugins reloaded."

# ── Plugin management ──────────────────────────────────────────────────────────
# Example: make copy-plugin PLUGIN=./my_plugin/my_plugin_plugin.py
copy-plugin:
	@PROC_POD=$$(kubectl get pod -n $(NAMESPACE) -l app=processor -o jsonpath='{.items[0].metadata.name}'); \
	kubectl cp $(PLUGIN) $(NAMESPACE)/$$PROC_POD:/app/babel/
	$(MAKE) reload-plugins
