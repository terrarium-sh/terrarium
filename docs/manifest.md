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

The manifest is a map of references because a project directory can be mounted
into a guest. Terra asks before pinning a recipe that a guest might have
written; in noninteractive use, review it and pass `--trust-recipe`. Keep
recipes as the policy document and read [security](security.md) before granting
mounts or network access.
