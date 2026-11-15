# Project manifest

`terra.yaml` optionally maps box names to recipe paths for setup. Commit it
so every clone uses the same aliases.

```yaml
boxes:
  dev: ./dev.yaml
  ci: ./ci.yaml
```

Box names are case-insensitive: `Dev` and `dev` name the same box. Each value
is a path to a recipe file, never an inline recipe. Paths are
relative to the project directory, and `~` means your own home. With one entry,
`terra setup` picks it without a box name; with several, name the box:

```sh
terra dev setup
terra ci setup --dry-run
terra dev
```

Setup applies a copy of the recipe to the box, and boots use that copy. Editing
the manifest or the recipe changes nothing until you run `terra <box> setup`
again. `terra <box> show` prints the applied recipe and says when the manifest
now points elsewhere.

An explicit recipe path always wins: `terra ./dev.yaml setup` applies that
file to the box named `dev`, whether or not the manifest names it. Only a
bare box name uses the manifest's alias. Without an alias, an existing box
reuses its applied recipe; a new box needs a recipe path. To apply file edits
to a box without an alias, pass the path again. An alias pointing at a missing
file fails setup.

Keep the manifest and its recipes out of writable shares, because the guest
could edit them. Terra asks before applying a recipe a guest could have written;
without a terminal, review both files and pass `--trust-recipe`. Terra checks
only current shares, so files left by a removed share get no warning. See
[where recipes live](security.md#where-recipes-live).
