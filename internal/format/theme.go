// Package format's shared visual identity for every self-contained HTML
// page it produces (api.html, fleet.html, and any future one). One design
// system, defined once, so every gin-recon HTML output reads as the same
// tool rather than several differently-styled pages that happen to share a
// binary. Deliberately gin-recon's own: its own accent color, its own
// CSS-only mark (a magnifying glass — "recon" — built from a border and a
// pseudo-element, the same zero-asset technique a sibling tool's own brand
// mark uses for its own unrelated shape), never a copied palette or
// literal markup. Still zero network, zero external font/icon/asset, per
// ADR 0009 — a brand mark that needed an image file would be the one part
// of this page reaching outside itself.
package format

// themeCSS defines the shared :root palette (light and dark), typography,
// and page-chrome classes (.site-header/.brand/.brand__mark, .hero/.eyebrow/
// .lede, .metrics/.metric, .panel, .badge) every gin-recon HTML page builds
// on. A page-specific stylesheet (html.go's htmlViewerCSS, fleet_html.go's
// own table rules) is appended after this, so it can reuse these custom
// properties rather than redefining its own palette.
const themeCSS = `
:root {
  color-scheme: light dark;
  --gr-accent: #0f766e;
  --gr-accent-soft: #e6f5f3;
  --gr-bg: #f7f8f9;
  --gr-panel: #ffffff;
  --gr-panel-muted: #eef1f2;
  --gr-ink: #12181a;
  --gr-muted: #4b5a5e;
  --gr-border: #d8e0e1;
  --gr-link: #0b5a53;
  --gr-good: #157a45;
  --gr-good-soft: #e3f8ea;
  --gr-warn: #92660c;
  --gr-warn-soft: #fdf3d9;
  --gr-bad: #a3231b;
  --gr-bad-soft: #fce9e7;
  --gr-shadow: 0 6px 20px rgb(15 30 32 / 7%);
}
@media (prefers-color-scheme: dark) {
  :root {
    --gr-accent: #2dd4bf;
    --gr-accent-soft: #123330;
    --gr-bg: #0c1314;
    --gr-panel: #141d1e;
    --gr-panel-muted: #1b2627;
    --gr-ink: #e9f2f1;
    --gr-muted: #9db2b0;
    --gr-border: #26383a;
    --gr-link: #6fe0d2;
    --gr-good: #4fd88a;
    --gr-good-soft: #103322;
    --gr-warn: #e8c05a;
    --gr-warn-soft: #3a2f10;
    --gr-bad: #f0847c;
    --gr-bad-soft: #3a1613;
    --gr-shadow: 0 6px 20px rgb(0 0 0 / 30%);
  }
}
.gr-shell * { box-sizing: border-box; }
.gr-shell {
  background: var(--gr-bg);
  color: var(--gr-ink);
  font: 15px/1.5 ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
.gr-shell a { color: var(--gr-link); }
.gr-site-header {
  border-bottom: 1px solid var(--gr-border);
  padding: 16px 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  flex-wrap: wrap;
}
.gr-brand {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  font-weight: 750;
  font-size: 16px;
  letter-spacing: -0.01em;
  color: var(--gr-ink);
}
.gr-brand__mark {
  position: relative;
  width: 16px;
  height: 16px;
  border: 2px solid var(--gr-accent);
  border-radius: 50%;
  flex: none;
}
.gr-brand__mark::before {
  content: "";
  position: absolute;
  inset: 0;
  margin: auto;
  width: 4px;
  height: 4px;
  border-radius: 50%;
  background: var(--gr-accent);
}
.gr-brand__mark::after {
  content: "";
  position: absolute;
  top: 50%;
  left: 50%;
  width: 10px;
  height: 2px;
  border-radius: 1px;
  background: var(--gr-accent);
  transform-origin: 0 50%;
  transform: rotate(-40deg);
}
.gr-git-mark { flex: none; vertical-align: -2px; color: var(--gr-muted); }
.gr-header-meta { color: var(--gr-muted); font-size: 13px; text-align: right; }
.gr-hero { padding: 28px 24px 8px; }
.gr-eyebrow {
  margin: 0 0 6px;
  color: var(--gr-accent);
  font-size: 11px;
  font-weight: 800;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}
.gr-hero h1 { margin: 0; font-size: clamp(22px, 3vw, 30px); letter-spacing: -0.02em; }
.gr-lede { max-width: 760px; margin: 8px 0 0; color: var(--gr-muted); font-size: 14px; }
.gr-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 10px;
  margin: 18px 24px 0;
}
.gr-metric {
  border: 1px solid var(--gr-border);
  border-radius: 10px;
  background: var(--gr-panel);
  box-shadow: var(--gr-shadow);
  padding: 12px 14px;
}
.gr-metric__value { display: block; font-size: 21px; font-weight: 750; line-height: 1.1; }
.gr-metric__label { display: block; margin-top: 4px; color: var(--gr-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; }
.gr-panel {
  border: 1px solid var(--gr-border);
  border-radius: 12px;
  background: var(--gr-panel);
  box-shadow: var(--gr-shadow);
  margin: 18px 24px 0;
  overflow: hidden;
}
.gr-panel__title { margin: 0; padding: 12px 16px; border-bottom: 1px solid var(--gr-border); font-size: 13px; font-weight: 700; }
.gr-badge {
  display: inline-block;
  padding: 1px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
  border: 1px solid var(--gr-border);
  color: var(--gr-muted);
}
.gr-badge--good { color: var(--gr-good); border-color: var(--gr-good); background: var(--gr-good-soft); }
.gr-badge--warn { color: var(--gr-warn); border-color: var(--gr-warn); background: var(--gr-warn-soft); }
.gr-badge--bad { color: var(--gr-bad); border-color: var(--gr-bad); background: var(--gr-bad-soft); }
.gr-badge--neutral { color: var(--gr-muted); }
.gr-key-values { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0; padding: 14px 16px; font-size: 13px; }
.gr-key-values dt { color: var(--gr-muted); }
.gr-key-values dd { margin: 0; font-weight: 600; }
.gr-filters { display: flex; align-items: center; gap: 12px; padding: 12px 16px; border-bottom: 1px solid var(--gr-border); flex-wrap: wrap; }
.gr-filters label { display: block; font-size: 11px; color: var(--gr-muted); margin-bottom: 3px; text-transform: uppercase; letter-spacing: 0.03em; }
.gr-filters input, .gr-filters select {
  border: 1px solid var(--gr-border);
  border-radius: 8px;
  padding: 6px 10px;
  font-size: 13px;
  background: var(--gr-panel);
  color: var(--gr-ink);
}
.gr-result-count { color: var(--gr-muted); font-size: 12px; margin-left: auto; align-self: flex-end; }
.gr-table-wrap { overflow-x: auto; }
.gr-footer { margin: 24px 24px 32px; color: var(--gr-muted); font-size: 12px; }
`

// brandMarkHTML is the inline brand mark markup shared by every page's
// header — a plain <span>, styled entirely by .gr-brand__mark above (a
// ringed dot with a short angled sweep, evoking a radar/scan ping — gin-recon's
// own mark, distinct from any other tool's). No image or inline SVG
// payload to keep in sync with the CSS.
const brandMarkHTML = `<span class="gr-brand__mark" aria-hidden="true"></span>`

// gitMarkHTML is an inline SVG marking a target's source as a git remote
// (used next to a --org-discovered target's clone URL) — an original
// three-node graph glyph suggestive of a git branch/commit graph, not any
// specific host's trademarked logo. Sized via its own attributes and
// colored with currentColor so it follows .gr-git-mark's color in both
// themes without a second copy for dark mode.
const gitMarkHTML = `<svg class="gr-git-mark" width="13" height="13" viewBox="0 0 16 16" aria-hidden="true"><circle cx="4" cy="3" r="1.6" fill="none" stroke="currentColor" stroke-width="1.3"/><circle cx="4" cy="13" r="1.6" fill="none" stroke="currentColor" stroke-width="1.3"/><circle cx="12" cy="8" r="1.6" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M4 4.6V11.4M5.5 8H10.4" fill="none" stroke="currentColor" stroke-width="1.3"/></svg>`
