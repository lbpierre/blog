/* Krakz theme — progressive enhancements, no dependencies. */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const fold = (s) => (s || "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");
  const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  /* ------------------------------------------------------------------
     Header search
     ------------------------------------------------------------------ */
  const search = $("[data-search]");
  if (search) {
    const toggle = $("[data-search-toggle]", search);
    const panel = $(".search__panel", search);
    const input = $("[data-search-input]", search);
    const results = $("[data-search-results]", search);
    const indexURL = document.currentScript?.dataset.searchIndex || $("script[data-search-index]")?.dataset.searchIndex || "/index.json";
    let index = null, loading = null, selected = -1;

    const load = () => loading || (loading = fetch(indexURL)
      .then((r) => r.json())
      .then((data) => (index = data.map((d) => ({
        ...d,
        _t: fold(d.title), _g: fold((d.tags || []).join(" ")), _d: fold(d.description), _c: fold(d.content),
      }))))
      .catch(() => (index = [])));

    const open = () => {
      panel.hidden = false;
      toggle.setAttribute("aria-expanded", "true");
      input.focus();
      load();
      if (!input.value) results.innerHTML = '<p class="search__hint">Type to search titles, tags and full text.</p>';
    };
    const close = () => {
      panel.hidden = true;
      toggle.setAttribute("aria-expanded", "false");
    };

    toggle.addEventListener("click", () => (panel.hidden ? open() : close()));
    document.addEventListener("click", (e) => { if (!panel.hidden && !search.contains(e.target)) close(); });
    document.addEventListener("keydown", (e) => {
      const typing = /input|textarea|select/i.test(document.activeElement?.tagName || "") || document.activeElement?.isContentEditable;
      if ((e.key === "/" || (e.key === "k" && (e.metaKey || e.ctrlKey))) && !typing) { e.preventDefault(); open(); }
      else if (e.key === "Escape" && !panel.hidden) { close(); toggle.focus(); }
    });

    const snippet = (text, terms) => {
      const lower = fold(text);
      let pos = -1;
      for (const t of terms) { pos = lower.indexOf(t); if (pos > -1) break; }
      if (pos < 0) return "";
      const start = Math.max(0, pos - 70);
      let s = (start ? "…" : "") + text.slice(start, start + 200) + "…";
      return highlight(s, terms);
    };
    const highlight = (s, terms) => {
      let out = esc(s);
      if (!terms.length) return out;
      const re = new RegExp("(" + terms.map(reEsc).sort((a, b) => b.length - a.length).join("|") + ")", "gi");
      // fold-insensitive highlight is approximated on the raw text
      return out.replace(re, "<mark>$1</mark>");
    };

    const render = () => {
      const q = fold(input.value.trim());
      selected = -1;
      if (!q) { results.innerHTML = '<p class="search__hint">Type to search titles, tags and full text.</p>'; return; }
      if (!index) { results.innerHTML = '<p class="search__hint">Loading…</p>'; load().then(render); return; }
      const terms = q.split(/\s+/).filter(Boolean);
      const hits = [];
      for (const d of index) {
        let score = 0, ok = true;
        for (const t of terms) {
          const s = (d._t.includes(t) ? 12 : 0) + (d._g.includes(t) ? 6 : 0) + (d._d.includes(t) ? 3 : 0) + (d._c.includes(t) ? 1 + Math.min(5, d._c.split(t).length - 2) * .2 : 0);
          if (!s) { ok = false; break; }
          score += s;
        }
        if (ok) hits.push({ d, score });
      }
      hits.sort((a, b) => b.score - a.score);
      if (!hits.length) { results.innerHTML = `<p class="search__empty">No results for “${esc(input.value.trim())}”.</p>`; return; }
      results.innerHTML = hits.slice(0, 12).map(({ d }, i) => `
        <a class="search__result" href="${d.url}" role="option" id="sr-${i}">
          <span class="search__result-title">${highlight(d.title, terms)}</span>
          <span class="search__result-meta">${esc(d.date)}${d.tags?.length ? " · " + d.tags.map((t) => "#" + esc(t)).join(" ") : ""}</span>
          <span class="search__result-snippet">${snippet(d.content, terms) || esc(d.description || "")}</span>
        </a>`).join("");
    };
    let t;
    input.addEventListener("input", () => { clearTimeout(t); t = setTimeout(render, 80); });
    input.addEventListener("keydown", (e) => {
      const items = $$(".search__result", results);
      if (!items.length) return;
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        selected = (selected + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length;
        items.forEach((el, i) => el.classList.toggle("is-selected", i === selected));
        items[selected].scrollIntoView({ block: "nearest" });
      } else if (e.key === "Enter") {
        e.preventDefault();
        (items[selected] || items[0]).click();
      }
    });
  }

  /* ------------------------------------------------------------------
     Post list filters (home): tags (AND) + sort.
     State mirrors the URL: ?tags=loader,yara&sort=asc
     ------------------------------------------------------------------ */
  const root = $("[data-filter-root]");
  const list = $("[data-post-list]");
  const sort = root && $("[data-filter-sort]", root);
  if (root && list && sort) {
    const filters = $("[data-filters]", root);
    filters.hidden = false;
    const cards = $$("[data-post]", list);
    const chips = $$("[data-filter-tag]", root);
    const count = $("[data-filter-count]", root);
    const noun = $("[data-filter-noun]", root);
    const resets = $$("[data-filter-reset]", root);
    const empty = $("[data-filter-empty]", root);
    const featured = $(".card--featured", list);
    const selectedTags = new Set();

    const params = new URLSearchParams(location.search);
    sort.value = ["asc", "title"].includes(params.get("sort")) ? params.get("sort") : "desc";
    (params.get("tags") || params.get("tag") || "").split(",").filter(Boolean).forEach((t) => selectedTags.add(t.toLowerCase()));

    const apply = (push = true) => {
      let n = 0;
      for (const c of cards) {
        const tags = c.dataset.tags.split("|");
        const show = [...selectedTags].every((t) => tags.includes(t));
        c.hidden = !show;
        if (show) n++;
      }
      [...cards].sort((a, b) =>
        sort.value === "title" ? a.dataset.title.localeCompare(b.dataset.title)
          : sort.value === "asc" ? a.dataset.date - b.dataset.date : b.dataset.date - a.dataset.date)
        .forEach((c) => list.appendChild(c));

      const filtered = selectedTags.size > 0;
      // The large "featured" layout only makes sense on the untouched list
      if (featured) featured.classList.toggle("card--featured", !filtered && sort.value === "desc");

      chips.forEach((ch) => ch.setAttribute("aria-pressed", String(selectedTags.has(ch.dataset.filterTag))));
      count.textContent = n;
      noun.textContent = n === 1 ? "article" : "articles";
      resets.forEach((r) => (r.hidden = !filtered));
      empty.hidden = n > 0;

      if (push) {
        const p = new URLSearchParams();
        if (filtered) p.set("tags", [...selectedTags].join(","));
        if (sort.value !== "desc") p.set("sort", sort.value);
        const qs = p.toString();
        history.replaceState(null, "", location.pathname + (qs ? "?" + qs : "") + location.hash);
      }
    };

    sort.addEventListener("change", () => apply());
    chips.forEach((ch) => ch.addEventListener("click", () => {
      const tag = ch.dataset.filterTag;
      selectedTags.has(tag) ? selectedTags.delete(tag) : selectedTags.add(tag);
      apply();
    }));
    // Tag links inside cards filter in place instead of leaving the page
    list.addEventListener("click", (e) => {
      const a = e.target.closest("[data-tag-link]");
      if (!a || e.metaKey || e.ctrlKey || e.shiftKey) return;
      e.preventDefault();
      selectedTags.add(a.dataset.tagLink);
      apply();
      root.scrollIntoView({ behavior: "smooth", block: "start" });
    });
    resets.forEach((r) => r.addEventListener("click", () => { selectedTags.clear(); apply(); }));
    apply(false);
  }

  /* ------------------------------------------------------------------
     Code blocks: copy button (line numbers are never copied)
     ------------------------------------------------------------------ */
  $$("[data-codeblock]").forEach((block) => {
    const btn = $("[data-copy]", block);
    const label = $("[data-copy-label]", block);
    if (!btn) return;
    if (!navigator.clipboard) { btn.hidden = true; return; }
    btn.addEventListener("click", async () => {
      const lines = $$(".cl", block);
      const text = lines.length ? lines.map((l) => l.textContent).join("").replace(/\n$/, "") : $("code", block).textContent;
      try {
        await navigator.clipboard.writeText(text);
        btn.classList.add("is-copied"); label.textContent = "Copied";
      } catch { label.textContent = "Failed"; }
      setTimeout(() => { btn.classList.remove("is-copied"); label.textContent = "Copy"; }, 1600);
    });
  });

  /* ------------------------------------------------------------------
     Image zoom
     ------------------------------------------------------------------ */
  document.addEventListener("click", (e) => {
    const img = e.target.closest("img[data-zoom]");
    if (!img) return;
    const overlay = document.createElement("div");
    overlay.className = "zoom-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-label", img.alt || "Image");
    overlay.innerHTML = `<img src="${img.currentSrc || img.src}" alt="${esc(img.alt || "")}">`;
    const done = () => { overlay.remove(); document.removeEventListener("keydown", onKey); };
    const onKey = (ev) => { if (ev.key === "Escape") done(); };
    overlay.addEventListener("click", done);
    document.addEventListener("keydown", onKey);
    document.body.appendChild(overlay);
  });

  /* ------------------------------------------------------------------
     Article: reading progress, TOC highlight, back-to-top
     ------------------------------------------------------------------ */
  const body = $("[data-post-body]");
  if (body) {
    const bar = $("[data-progress]");
    const top = $("[data-to-top]");
    const toc = $("[data-toc]");
    const links = toc ? $$("nav a[href^='#']", toc) : [];
    const heads = links.map((a) => document.getElementById(decodeURIComponent(a.hash.slice(1)))).filter(Boolean);

    // On large screens the TOC is a sticky sidebar; keep it open there.
    if (toc && matchMedia("(max-width: 87.99rem)").matches && heads.length > 8) toc.open = false;

    let ticking = false;
    const onScroll = () => {
      ticking = false;
      const rect = body.getBoundingClientRect();
      const total = rect.height - innerHeight + 200;
      const p = Math.min(1, Math.max(0, (-rect.top + 100) / total));
      if (bar) bar.style.setProperty("--progress", p.toFixed(4));
      if (top) top.hidden = scrollY < 900;
      if (heads.length) {
        let current = heads[0];
        for (const h of heads) { if (h.getBoundingClientRect().top < 140) current = h; else break; }
        links.forEach((a) => a.classList.toggle("is-active", a.hash.slice(1) === current.id));
      }
    };
    addEventListener("scroll", () => { if (!ticking) { ticking = true; requestAnimationFrame(onScroll); } }, { passive: true });
    onScroll();
    top?.addEventListener("click", () => scrollTo({ top: 0 }));
  }
})();
