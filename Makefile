.PHONY: test dev-up dev-down build

test:
	.venv/bin/python -m pytest tests/ -v

dev-up:
	kind create cluster --name rbac-subtract 2>/dev/null || true
	kubectl wait --for=condition=Ready node --all --timeout=60s
	kubectl apply -f manifests/crd.yaml
	kubectl wait --for=condition=Established crd/modifyclusterroles.kim.karolinska.se --timeout=30s
	@echo "Controller running. Ctrl+C to stop."
	@echo "In another terminal: kubectl apply -f examples/modifyclusterrole-sample.yaml"
	kopf run main.py --verbose

dev-down:
	kind delete cluster --name rbac-subtract

build:
	docker build -t modifyclusterrole-controller:latest .
