# gin-recon logo assets

The mark combines a broken scan ring with a three-branch route graph. The
negative-space opening gives the ring a subtle `G` silhouette while the graph
keeps the meaning tied to route discovery rather than a generic search icon.

- `lockup.svg` and `mark.svg` respond to `prefers-color-scheme` themselves.
- `*-light.svg` and `*-dark.svg` are explicit variants for renderers that strip
  embedded styles. The repository README uses these through `<picture>`.
- `tile.svg` is the square app/avatar treatment; `../favicon.svg` is its compact
  favicon form.

Primary colors are deep teal `#0F766E` and mint teal `#2DD4BF`, matching the
self-contained HTML reports in `internal/format/theme.go`. SVGs have no scripts,
external fonts, or external resources.
