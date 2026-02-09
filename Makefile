IMAGE ?= ghcr.io/whilesmart/formsink
TAG   ?= latest
SOURCE ?= https://github.com/whilesmart/formsink
VENDOR ?= WhileSmart
DESCRIPTION ?= FormSink

.PHONY: install serve dev start lint test build up down logs restart clean prod-build prod-push

install:
	npm install

serve: dev

dev:
	npm run dev

start:
	npm run start

lint:
	npm run lint

test:
	npm run test

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

restart: down up

clean: down
	docker compose down -v
	rm -rf data/

prod-build:
	docker build \
		--label org.opencontainers.image.source=$(SOURCE) \
		--label org.opencontainers.image.description="$(DESCRIPTION)" \
		--label org.opencontainers.image.vendor=$(VENDOR) \
		--label org.opencontainers.image.version=$(TAG) \
		-t $(IMAGE):latest .
	@if [ "$(TAG)" != "latest" ]; then \
		docker tag $(IMAGE):latest $(IMAGE):$(TAG); \
	fi

prod-push:
	docker push $(IMAGE):latest
	@if [ "$(TAG)" != "latest" ]; then \
		docker push $(IMAGE):$(TAG); \
	fi
