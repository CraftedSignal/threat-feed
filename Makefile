.PHONY: notifier-build notifier-image notifier-push notifier-deploy notifier-test

NOTIFIER_IMAGE := europe-west1-docker.pkg.dev/craftedsignal-shared/craftedsignal/feed-notifier:latest

# Build static linux/amd64 binary for the Cloud Run service.
notifier-build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		go build -trimpath -ldflags="-w -s" -o feed-notifier ./cmd/notifier/

# Build the container image (requires podman or docker).
notifier-image: notifier-build
	podman build --platform linux/amd64 -f Dockerfile.notifier -t $(NOTIFIER_IMAGE) .
	rm -f feed-notifier

# Push to Artifact Registry.
notifier-push: notifier-image
	podman push $(NOTIFIER_IMAGE)

# Build, push, and roll the Cloud Run service. Requires terraform-applied
# service to exist; gcloud auth + kubectl context not needed (Cloud Run
# pulls the new :latest image on next revision).
notifier-deploy: notifier-push
	gcloud run deploy feed-notifier-prod \
		--region europe-west1 \
		--image $(NOTIFIER_IMAGE) \
		--project craftedsignal-prod

notifier-test:
	go test ./cmd/notifier/...
