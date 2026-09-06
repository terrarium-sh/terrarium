# Project manifest

`terra.yaml` names a project's boxes and maps each name to a recipe. Commit it
when the project has more than one useful sandbox, so `terra dev` means the
same thing for everyone who clones the project. Recipes themselves are described
in the [recipe reference](recipe.md); commands and lifecycle are in
[usage.md](usage.md).

## Format

```yaml
# terra.yaml
boxes:
  dev: ./dev.yaml
  ci: ~/ci/terra.yaml
```

Each value is a recipe path, not an inline recipe. Relative paths resolve from
the project root; `~` expands in the usual way. A manifest with one entry makes
bare `terra setup` select that box. With several entries, terra lists the boxes
instead of guessing.

## Pinning and trust

`terra <box> setup` reads the manifest, pins the recipe it names, and builds the
box. The manifest is consulted again only by `setup`; booting an existing box
uses its pinned recipe.

The manifest lives in the project root, which a box may mount and write. It is
therefore deliberately a map of references rather than policy in place. A
manifest edit can repoint a box name, but `setup` shows the recipe and asks for
approval before it pins a guest-writable source. References into `~/.terra` are
also protected from ordinary mount configuration: terra refuses any mount that
could contain that state. This is not VMM confinement; see the
[security model](security.md) before enabling mounts.

A bare `terra <box>` never silently pins a new recipe. On a terminal it shows
what the recipe grants and asks before setup; without one it tells the caller to
run `terra <box> setup`.
