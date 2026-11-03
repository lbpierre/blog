# Org -> Markdown (ox-hugo) -> Hugo
# Run `make export` before committing: CI only builds the committed Markdown.
EMACS ?= emacs

.PHONY: export serve build clean

## Export every subtree of content-org/*.org with ox-hugo
export:
	$(EMACS) --batch -l tools/ox-hugo-export.el 2>&1 | grep -E '^\[export\]|Exported|FAILED|Error'

## Local preview, drafts (TODO) and future posts included
serve:
	hugo server -D -F --disableFastRender

## Production build (what CI publishes)
build:
	hugo --gc --minify

clean:
	rm -rf public resources/_gen
