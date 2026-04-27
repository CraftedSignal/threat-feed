.PHONY: dev build clean install serve help fonts setup search-index

help:
	@echo "CraftedSignal Threat Feed - Hugo + Tailwind CSS"
	@echo ""
	@echo "Usage:"
	@echo "  make install       Install npm dependencies"
	@echo "  make setup         Full setup (install + fonts)"
	@echo "  make dev           Start development server with live reload"
	@echo "  make build         Build production site to ./public (incl. Pagefind index)"
	@echo "  make serve         Build and serve production site locally"
	@echo "  make search-index  Run Pagefind on the existing public/ directory"
	@echo "  make clean         Remove build artifacts"
	@echo ""

install:
	npm ci || npm install

# Dev: build + Pagefind + static server, so search works locally.
# Re-run `make dev` after content changes (no hot reload — search wins).
dev: clean
	hugo --buildDrafts --buildFuture --gc
	npx pagefind --site public
	@echo ""
	@echo "→ http://localhost:1313/"
	@echo ""
	cd public && python3 -m http.server 1313

# Hot-reload dev (no search index — fallback message will show).
dev-fast:
	hugo server --buildDrafts --buildFuture --disableFastRender

build:
	hugo --gc --minify
	npx pagefind --site public

search-index:
	npx pagefind --site public

serve: build
	cd public && python3 -m http.server 8080

clean:
	rm -rf public resources .hugo_build.lock

fonts:
	@mkdir -p static/fonts
	cp node_modules/@fontsource/inter/files/inter-latin-400-normal.woff2 static/fonts/
	cp node_modules/@fontsource/inter/files/inter-latin-500-normal.woff2 static/fonts/
	cp node_modules/@fontsource/inter/files/inter-latin-600-normal.woff2 static/fonts/
	cp node_modules/@fontsource/inter/files/inter-latin-700-normal.woff2 static/fonts/
	cp node_modules/@fontsource/space-grotesk/files/space-grotesk-latin-400-normal.woff2 static/fonts/
	cp node_modules/@fontsource/space-grotesk/files/space-grotesk-latin-500-normal.woff2 static/fonts/
	cp node_modules/@fontsource/space-grotesk/files/space-grotesk-latin-600-normal.woff2 static/fonts/
	cp node_modules/@fontsource/space-grotesk/files/space-grotesk-latin-700-normal.woff2 static/fonts/
	@echo "Fonts copied to static/fonts/"

setup: install fonts
	@echo "Setup complete! Run 'make dev' to start developing."
