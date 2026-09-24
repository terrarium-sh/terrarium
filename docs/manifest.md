# Project manifest

`terra.yaml` gives a project stable names for its recipes. Commit it when a
project has more than one useful box, so each clone uses the same names.

```yaml
boxes:
  dev: ./dev.yaml
  ci: ./ci.yaml
```

Each value is a recipe path, never an inline recipe. Relative paths resolve
from the project directory, and `~` expands for the current user. With one
manifest entry, `terra setup` can choose it without a box name; with several,
specify one:

```sh
terra dev setup
terra ci setup --dry-run
terra dev
```

Setup reads the manifest and pins the referenced recipe. Later boots use the
pinned copy, so changing either file has no effect until `terra <box> setup`
runs again. `terra <box> show` displays the pinned recipe and notes if the
manifest now points elsewhere.

Prefer keeping the manifest and its recipes outside guest-writable shares.
Terra asks before pinning a recipe when current pins indicate that a guest
could have written the recipe or manifest; in noninteractive use, review both
and pass `--trust-recipe`. Removed shares are not tracked, so this warning
cannot identify every guest-written file. See
[recipe storage and trust](security.md#recipe-storage) before granting mounts
or network access.
