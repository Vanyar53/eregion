# Profil « mon infra tient-elle ? » : Glorfindel + Gothmog

[← Les profils](README.md)

**Pour qui.** Une équipe qui veut savoir si une panne est bien vécue, par son infrastructure et par Glorfindel. Une panne bénigne ne doit pas déclencher d'action disruptive. Une dépendance qui tombe doit faire échouer Glorfindel fermé. Une reprise doit se terminer et se vérifier.

**Ce que fait Gothmog.** Il déclare la panne en code, la confie à un moteur public (Chaos Studio d'abord, G0), puis vérifie l'état normal avant, pendant et après.

**Ce qui tourne.**
- **Glorfindel** : sur ton poste ou hébergé (H0).
- **Gothmog** : depuis **Orodruin**, avec la même image et la même identité qu'Annatar. Il n'y agit que si son contrat est `armed`, et seulement sur des cibles inscrites au banc ou au jumeau. Jamais en `production`.

## Installer

```bash
make profile-resilience       # Glorfindel (watch + console) + l'image des injecteurs (Gothmog compris)
```

**Sur ton poste, rien n'écrit.** Le verdict du contrat est `passive`, et Gothmog dit pourquoi :

```bash
docker compose --profile gothmog run --rm gothmog preflight vm-shutdown
```

**Les vraies pannes partent d'Orodruin.** La procédure est dans [`gothmog/README.md`](../../gothmog/README.md) :

```bash
make gothmog-preflight FAULT=vm-shutdown     # contrat, cibles, état normal : rien d'écrit
make gothmog-run FAULT=vm-shutdown           # la panne, et son retour vérifié (~15 min)
```

## Jamais sans Glorfindel

Comme Annatar :
- le service compose dépend de la watch, et lit son battement dans `~/.glorfindel`, en lecture seule ;
- depuis Orodruin, Gothmog lit le canal retour ;
- `gothmog run` et `gothmog preflight` refusent sans battement vivant, avant tout appel au cloud ;
- `WITHOUT_GLORFINDEL=1` permet un run de développement, et le rapport le dit.

## Ce que montre la console

- **L'onglet Gothmog s'active** dès que l'hôte porte un de ses runs.
- Chaque panne y est liée à ce que Glorfindel a vu et fait pendant sa fenêtre d'exercice (`kind: fault`).
- **Annatar reste grisé.**

## Limites

- G0 joue une panne : l'arrêt d'une VM.
- Le bruit bénin (G1), les pannes des dépendances (G2) et l'exercice de reprise (G3) sont dans la feuille de route.
- Les moteurs Kubernetes viennent en 1.x (G4).
