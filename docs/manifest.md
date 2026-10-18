# Project manifest

`terra.yaml` names a project's boxes and points each name at a recipe. Commit
it so every clone uses the same names.

```yaml
boxes:
  dev: ./dev.yaml
  ci: ./ci.yaml
```

Each value is a path to a recipe file, never an inline recipe. Paths are
relative to the project directory, and `~` means your own home. With one entry,
`terra setup` picks it without a box name; with several, name the box:

```sh
terra dev setup
terra ci setup --dry-run
terra dev
```

Setup pins a copy of the recipe in the box, and boots use that copy. Editing
the manifest or the recipe changes nothing until you run `terra <box> setup`
again. `terra <box> show` prints the pinned recipe and says when the manifest
now points elsewhere.

Keep the manifest and its recipes out of writable shares, because the guest
could edit them. Terra asks before pinning a recipe a guest could have written;
without a terminal, review both files and pass `--trust-recipe`. Terra checks
only current shares, so files left by a removed share get no warning. See
[where recipes live](security.md#where-recipes-live).
