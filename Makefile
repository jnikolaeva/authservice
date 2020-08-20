APP_EXECUTABLE?=./bin/auth
RELEASE?=1.0
MIGRATIONS_RELEASE?=0.1
MIGRATIONS_IMAGENAME?=arahna/auth-service-migrations:v$(MIGRATIONS_RELEASE)
IMAGENAME?=arahna/auth-service:v$(RELEASE)

.PHONY: clean
clean:
	rm -f ${APP_EXECUTABLE}

.PHONY: build
build: clean
	docker build -t $(MIGRATIONS_IMAGENAME) -f DockerfileMigrations .
	docker build -t $(IMAGENAME) .

.PHONY: release
release:
	git tag v$(RELEASE)
	git push origin v$(RELEASE)