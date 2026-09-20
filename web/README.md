# Terrarium website

Static SvelteKit, TypeScript, and [Starlight](https://github.com/alis-is/starlight).
Requires Node 22.12+ and pnpm (the version is pinned in `package.json`).

```sh
cd web
pnpm install --frozen-lockfile
TERRA_BIN=../target/debug/terra pnpm dev
```

Set `TERRA_BIN` to an existing Terra binary, or leave it unset to use `terra`
from `PATH`. Build the local binary with `cargo build -p terra` from the
repository root when documenting current source changes.

```sh
TERRA_BIN=../target/debug/terra pnpm build
pnpm check
pnpm test
pnpm preview
```

Deploy the contents of `build/`. All pages are prerendered, with local styles,
scripts, and assets; no runtime server, external fonts, or search service is
required. Client JavaScript powers platform detection on the homepage and
command search, plus the live GitHub star count on every page. All content
is readable without JavaScript.
Set `BASE_PATH=/terrarium` at build time for a GitHub Pages project site;
leave it empty for a domain root. Deep links use directory `index.html` files.

## Content

The setup section detects desktop Linux, macOS, or Windows in the browser and
selects the appropriate installer. Visitors can switch platforms manually.
Mobile and unknown clients get a choice; without JavaScript both installers
remain visible. The installers themselves select the native architecture.

Guides read `../docs/{usage,recipe,manifest,security}.md` during the build.
Edit those source documents to update their website pages.

`pnpm generate` recursively reads the binary's `--help` and `--version`.
Both `dev` and `build` regenerate the command index before starting; generated
files are ignored by Git. Re-run the command after rebuilding a local binary.
Search runs entirely in the browser and matches command names, flags, and help
text. The reference shows which binary version generated it. The homepage links
the release identified by that binary; development binaries omit the release
badge. CI sets `TERRA_RELEASE_TAG` and generation rejects a mismatched binary.

The Pages workflow rebuilds on website/documentation changes and releases.
It downloads the latest stable Linux release, verifies its checksum, and
generates the reference from that binary. Guides track the repository;
the command reference tracks the displayed release version. Each guide labels
this distinction so unreleased features are not mistaken for released commands. A successful
Release workflow also triggers Pages, including releases created by
`GITHUB_TOKEN`. Pull requests build and check the site without deploying.
GitHub's Pages configuration supplies the deployment base path.

## Theme and dependencies

`src/theme.css` defines the custom Starlight theme, preserving the original
`#f9f6ed` background, with blue-green glass accents and pale glass buttons.
Fonts are system fonts; the favicon is local SVG.
The title-free `static/terrarium-placeholder.png` was derived from the supplied
frog illustration and can be replaced by the forthcoming SVG in the header and
homepage. CSS provides short entrance animations and hover transitions, with
all motion disabled when the visitor requests reduced motion.

Starlight is pinned to a public GitHub source commit because its package
registry requires authentication. pnpm packages that source using its upstream
`prepack` script; `pnpm-workspace.yaml` explicitly permits that step. No GitHub
registry token is needed. Update the pinned URL and lockfile together.

The header fetches the current star count from GitHub’s public API when opened.
It keeps the star link without a count while loading, when JavaScript is disabled,
or if GitHub is unavailable or rate-limits the request. No token or build-time
star lookup is needed; the website remains statically hosted.
