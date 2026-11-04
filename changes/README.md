# changes/ — une entrée de CHANGELOG par lot

Chaque lot écrit son entrée dans son propre fichier, `changes/<lot>.md` (`changes/CI5.md`,
`changes/SEC20b.md`), jamais dans `[Unreleased]` de `CHANGELOG.md` : deux PR en vol n'écrivent
plus au même endroit, et la fusion de l'une ne met plus l'autre en conflit (CI5, #512).

**La forme** : le texte même que la version recevra, ses sections en titres `###`.

```markdown
### Fixed
- **Ce qui change, en une phrase** (LOT, #N ; `docs/…`). Le détail.
  - Tests : `tests/unit/test_….py`.

### Security
- **…** (LOT, #N).
```

- Les sections : `Security`, `Added`, `Changed`, `Fixed`. Une seule fois chacune, dans l'ordre
  qu'on veut ; aucune autre, et aucun autre titre (`#`, `##`, `####`).
- Rien avant la première section ; aucune section vide. En anglais, comme le CHANGELOG.
- Le nom : le lot, `[A-Za-z0-9][A-Za-z0-9._-]*.md`. Ce dossier ne tient que des fragments et ce README.

Pourquoi cette forme : c'est le Markdown du CHANGELOG, sans syntaxe neuve. Ce qu'on écrit est ce
qu'on lira sous la version ; un lot qui touche deux sections (une faille et sa correction) le dit
dans un seul fichier.

**À la release**, `make release` (`scripts/release.py prepare`) assemble les fragments sous
`[X.Y.Z]` : par section, dans l'ordre Security, Added, Changed, Fixed ; dans une section, ce que
`[Unreleased]` tenait encore d'abord (la transition), puis chaque fragment par le nom de son
fichier. Il vérifie qu'aucune ligne n'est perdue ni ajoutée, puis retire les fragments dans le
commit de la version. `DRY_RUN=1` montre l'assemblage. Un fragment mal formé est refusé : à la
release, et avant, dans la PR qui l'apporte (`tests/unit/test_release.py`).
