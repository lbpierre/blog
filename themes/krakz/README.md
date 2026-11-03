# Krakz — Hugo theme

Light, calm, reading-first theme for technical blogs written in Org mode and
exported with ox-hugo. No external requests: fonts and icons are self-hosted,
JS is vanilla with no dependencies.

## Features
- Home: filterable cards (keyword, year, tags, sort) showing each post's first image
  (front matter `image = "..."` overrides it). Filters are kept in the URL (`/?tags=loader&year=2024`).
- Articles page: compact archive grouped by year. Tag and category pages.
- Header: Articles / About, expandable full-text search (`/` or `Ctrl+K`), RSS + Atom links.
- Posts: sticky table of contents, reading progress, margin side notes (`%sidenote`),
  zoomable figures, styled `<details>` and ox-hugo captions.
- Code: Chroma with a warm "paper" palette (assets/css/chroma.css), line numbers on by
  default (sticky, never copied), hl_lines, language label, copy button. `text`/`example`
  blocks have no numbers unless `-n` is set in org.
- Downloads: `{{< download "path/in/scripts" … >}}` renders file cards (type, size) for
  files kept in the project's `scripts/` folder, published at `/files/` by a module mount.
  From Org: `#+begin_export hugo` … `#+end_export`.
- Feeds: /index.xml (RSS, full content) and /atom.xml (Atom), also per section and tag.

## Site config
The site `hugo.toml` needs `outputs.home = ["HTML","RSS","Atom","SearchIndex"]`,
`markup.highlight.noClasses = false` and `markup.goldmark.renderer.unsafe = true`.
Optional: mount `static/ox-hugo` on `assets/ox-hugo` to get WebP card thumbnails.
Social links: `[[params.social]]` with `name`, `icon` (x | github | mastodon), `url`, `rel`.

## Customising
Colours are CSS variables at the top of assets/css/main.css. Put overrides in your
site's assets/css/custom.css; the theme loads it automatically.
