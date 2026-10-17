.DEFAULT_GOAL := all

# Optional local deployment settings; tests and dependency checks need no secrets.
-include private/etc/envfile
-include private/ghcr_username
VERSION=2.6
COMPOSE = docker compose -f tests/docker-compose.test.yaml
UV_EXPORT = uv export --locked --no-hashes --no-annotate --no-emit-project

.PHONY: all clean venv full release push push-local test-local test-remote \
	test-release test-unit test-integration test-integration-down test \
	export-deps check-deps

check-env-%:
	@ # This code checks if an environment variable is empty
	@ # set ahead of running makefile. i.e. target=blah make check-env-target
	@ if [ "${${*}}" = "" ]; then \
			echo "Environment variable $* not set"; \
			exit 1; \
	fi

clean:
	rm -rf .venv/ venv/ .pytest_cache/ .coverage coverage.xml
	find cgi-bin lib tests scripts -type d -name __pycache__ -prune -exec rm -rf {} +

venv:
	uv sync --locked

export-deps:
	$(UV_EXPORT) --no-dev > etc/webserver_requirements.txt
	$(UV_EXPORT) --only-dev > etc/test_requirements.txt

check-deps:
	@set -eu; tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	$(UV_EXPORT) --no-dev > "$$tmp/runtime.txt"; \
	diff -u etc/webserver_requirements.txt "$$tmp/runtime.txt"; \
	$(UV_EXPORT) --only-dev > "$$tmp/test.txt"; \
	diff -u etc/test_requirements.txt "$$tmp/test.txt"

etc/config.ini:
	@if [ -f private/etc/config.ini ]; then \
		cp private/etc/config.ini $@; \
	else cp etc/config.ini.sample $@; fi

full: etc/config.ini
	@if [ -f private/etc/envfile ]; then cp private/etc/envfile etc/envfile; fi
	podman build -f Containerfile . -t overlord-dns-admin

release: check-env-RELEASE_USERNAME
	podman tag localhost/overlord-dns-admin:latest ghcr.io/${RELEASE_USERNAME}/overlord-network-kill-switch:${VERSION}
	podman push ghcr.io/${RELEASE_USERNAME}/overlord-network-kill-switch:${VERSION}

push: check-env-GHCR_USERNAME
	podman tag localhost/overlord-dns-admin:latest ghcr.io/${GHCR_USERNAME}/overlord-network-kill-switch:${VERSION}-test
	podman push ghcr.io/${GHCR_USERNAME}/overlord-network-kill-switch:${VERSION}-test

push-local: check-env-target
	rsync --progress -rv cgi-bin/*.py ${target}:dns_admin/cgi-bin/
	rsync --progress -rv etc/ ${target}:dns_admin/etc/
	ssh ${target} cd dns_admin \&\&

#-v ./cgi-bin/:/opt/webserver/cgi-bin/ -v ./lib/:/opt/webserver/lib/
#  -v ./etc/config.ini:/opt/webserver/etc/config.ini
# --dns=${DNS_SERVERS} # deprecated? podman bug?
TEST_CMD = podman run -d --replace --name=overlord-dns -p 19000:19000 --restart=on-failure:5 --env-file=./etc/envfile

test-local:
	$(TEST_CMD) localhost/overlord-dns-admin

test-remote: check-env-GHCR_USERNAME
	podman pull ghcr.io/${GHCR_USERNAME}/overlord-network-kill-switch:${VERSION}-test
	$(TEST_CMD) ghcr.io/${GHCR_USERNAME}/overlord-network-kill-switch:${VERSION}-test

test-release: check-env-GHCR_USERNAME
	podman pull ghcr.io/${GHCR_USERNAME}/overlord-network-kill-switch:${VERSION}
	$(TEST_CMD) ghcr.io/${GHCR_USERNAME}/overlord-network-kill-switch:${VERSION}

test-unit:
	uv run --locked pytest tests/unit -v -m unit --tb=short

test-integration: etc/config.ini
	@set -eu; trap '$(COMPOSE) down -v' EXIT; \
	$(COMPOSE) up -d --build --wait --wait-timeout 300; \
	uv run --locked pytest tests/integration -v -m integration --tb=short

test-integration-down:
	$(COMPOSE) down -v

test: test-unit

all:
	@echo "No op."
