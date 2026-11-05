# La réponse à une identité volée (IR1, #547) — conception

> **IR1a fait (#552, 05/11)** : le plan sur chaque carte `identity_change`, ses paramètres lus dans
> Graph en lecture seule, les commandes complètes, le bouton Verify (held, not held, unreadable),
> `IDENTITY_ACTIONS`, la liste `never_target` d'IDI1 lue — `docs/glorfindel.md`, « Identités », et
> `docs/design/console.md`. Le reste (IR1b à IR1e) est encore une conception.
>
> **Statut : conception, 05/11.** C2 détecte un vol d'identité dans Entra ID, mais n'y
> répond pas : l'escalade donne des commandes à taper. Ce document prépare la réponse : retirer,
> révoquer, désactiver, toujours sur l'approbation d'un humain. Jonathan a tranché les six
> questions du §7 le 05/11 (la section finale, « Les décisions de Jonathan ») ; le document est
> écrit selon ces décisions.
>
> **Règle de lecture.** Ce qui est lu dans le code est une affirmation, avec son fichier et sa
> ligne (au commit `67d1c24d`). Ce qui est dit d'Entra ID et de Microsoft Graph vient de la
> documentation officielle de Microsoft (les sources, §8) : c'est une **hypothèse**, à mesurer sur
> le tenant du banc (§5). Rien n'est mesuré ici : ni ID1 (les journaux d'Entra dans le workspace),
> ni IDI1 (une identité inscrite au banc) ne sont faits.
>
> Ce document suit la file d'actions signée de FS1 (`docs/design/file-actions-signee.md`, #413,
> conception et décisions de Jonathan du 04/11) et en reprend le modèle de l'exécuteur de restore
> (FS1g).

## 0. En bref

- **Aujourd'hui**, C2 détecte quatre constats sur Entra ID : un identifiant ajouté, un
  consentement, un rôle privilégié, une connexion inhabituelle d'un principal de service. La
  décision est construite par le code, sans modèle : une carte `identity_change`, ancrée, sans
  bouton, avec des commandes pour un humain. Aucune action n'existe, même sur approbation.
- **Cinq actions** répondent à ces constats, de la plus légère à la plus lourde : retirer
  l'identifiant ajouté, révoquer les sessions, retirer l'attribution de rôle, retirer ou bloquer
  le consentement, désactiver le principal ou l'utilisateur. Aucune n'est instantanée : un jeton
  déjà émis vit jusqu'à son expiration, 60 à 90 minutes par défaut (doc).
- **Jamais autonome, toutes, quel que soit le mode.** Le faux positif sur une identité est le plus
  cher qui soit, la détection arrive tard (jusqu'à 30 minutes), et aucune précision n'est mesurée.
- **Par la file signée de FS1**, mais **jamais exécutée par la watch** : par un **exécuteur
  d'identité** à part, comme l'exécuteur de restore de FS1g. Il ne relève que des demandes
  signées, rattachées à une proposition que la watch a signée, et il relit lui-même la preuve
  dans les journaux avant d'agir.
- **Le moindre privilège tranche le partage.** Retirer un identifiant et désactiver un principal
  de service tiennent dans `Application.ReadWrite.OwnedBy` : l'exécuteur n'agit que sur les
  applications dont il est propriétaire, c'est-à-dire celles qu'IDI1 inscrit. Désactiver un
  **utilisateur de test** passe par un User Administrator borné à **l'unité administrative du
  banc** (§3.6). Révoquer les sessions est permis, borné par le code aux utilisateurs inscrits.
  Retirer un rôle ou un consentement exige un droit qui permet, selon Microsoft, de « s'accorder
  des privilèges à soi-même » : **aucune identité d'Eregion ne le tient**. Ces deux actions
  restent un plan, que l'humain exécute avec son propre compte, et qu'Eregion vérifie ensuite ;
  en zone `production`, le retrait d'un secret aussi.
- **L'approbation suit le poids** : un clic dans la console pour un verbe léger et réversible ;
  le poste de l'opérateur, le nom de la cible tapé, pour un verbe lourd (retirer un secret,
  désactiver un principal ou un utilisateur). **Le bot montre, il n'agit pas.**
- **Glorfindel ne vise jamais ses propres identités, celle d'Orodruin, ni celle d'un opérateur** :
  une liste `never_target`, refusée deux fois par le code (la proposition, l'exécution), et une
  troisième fois par Entra ID, puisque l'exécuteur n'est propriétaire d'aucune d'elles.
- **D'abord le plan et sa vérification, en lecture seule** (IR1a), sans attendre FS1 ni IDI1.
  L'écriture (IR1c) attend la file (FS1a, FS1b), l'exécuteur (FS1g) et l'inscription (IDI1, et
  IDI1b pour les utilisateurs de test).

---

## 1. Ce que C2 fait aujourd'hui, lu dans le code

### 1.1 Les quatre constats

Les règles sont dans `glorfindel/rules/azure/detection_rules.yaml:390-562`, source `azure_entra`,
lues dans le même workspace que Perf, Syslog et AzureActivity. Les journaux d'Entra n'y arrivent
qu'avec un paramètre de diagnostic **du tenant** (`infra/terraform/entra_logs.tf`, proposé,
désactivé) : c'est ID1.

| Règle | TTP | Table | Seuil (en code, `glorfindel/providers/azure/entra.py:113-125`) |
|---|---|---|---|
| `entra-credential-added` | T1098.001 | `AuditLogs` | chaque ajout réussi d'un secret, d'un certificat ou d'un identifiant fédéré, sur une application ou un principal de service ; un retrait n'est pas un constat |
| `entra-app-consent` | T1528 | `AuditLogs` | chaque consentement réussi, délégué ou d'application, une carte par opération |
| `entra-privileged-role-assigned` | T1098.003 | `AuditLogs` | un rôle d'annuaire de `PRIVILEGED_ROLES` (`entra.py:62`), permanent, éligible ou à portée d'une unité administrative ; un rôle sans nom lu est gardé |
| `entra-sp-unusual-signin` | T1078.004 | `AADServicePrincipalSignInLogs` | une connexion réussie d'un principal de service depuis une adresse jamais vue en 14 jours, s'il a au moins `MIN_BASELINE_DAYS` jours d'historique |

L'adaptateur marque l'identité de Glorfindel, acteur (`GlorfindelIdentity`) ou cible
(`GlorfindelManaged`), sans jamais rien écarter sous elle (`entra.py:127-135`). Les deux marques
rendent la carte critique.

### 1.2 La décision : le code, sans modèle, sans action

- **`decide`** renvoie à `_identity_decision` dès qu'un signal est une identité
  (`glorfindel/agent.py:1576-1577`). Cette fonction (`agent.py:1058`) ne fait ni enquête ni appel
  au modèle : aucun UPN ne part au fournisseur. Elle pose `action: ""`, `escalate: True`,
  `held_by: "identity"`, et ses étapes viennent de `entra.describe`.
- **L'escalade** prend toujours le type `identity_change` (`agent.py:761`, `agent.py:1940-1941`),
  quoi qu'il soit arrivé jusque-là.
- **Deux verrous, mesurés chacun** : `decide` construit la décision, et la route après `decide`
  n'envoie jamais une identité vers une action
  (`tests/unit/test_entra_detection.py::test_the_route_after_decide_never_sends_an_identity_detection_to_an_action`,
  `::test_past_a_decide_that_would_act_nothing_runs`).
- **Ni mémoire ni incident** (`agent.py:276-277`), et la source est toujours `real` : une fenêtre
  d'exercice ne dit rien d'une identité, tant qu'aucune ne s'inscrit (`agent.py:2146`).
- **La carte est ancrée** : jamais approuvable en un clic, ni bouton ni commande à exécuter
  (`_ANCHORED_TYPES`, `eregion_console/api.py:1628`, `glorfindel/bot.py:65`,
  `eregion_console/static/glorfindel.js:81-82` ;
  `test_no_button_nor_command_on_an_identity_card`).

### 1.3 Ce que l'escalade dit de faire à la main

`entra.describe` (`entra.py:160`) écrit le constat et des étapes. Ce sont des commandes pour un
humain, jamais exécutées.

| Constat | Les étapes |
|---|---|
| identifiant ajouté (`:168`) | vérifier avec l'auteur ou le propriétaire ; lister les identifiants (`az ad app credential list`, `az ad sp credential list`) ; non voulu : `az ad app credential delete --id <id> --key-id <keyId>`, puis revoir les connexions du principal depuis l'ajout |
| consentement (`:182`) | vérifier l'application et ses permissions ; révoquer l'octroi (`DELETE oauth2PermissionGrants/<id>`, ou `DELETE servicePrincipals/<id>/appRoleAssignedTo/<id>`) ; bloquer la connexion de l'application cliente (`az ad sp update --set accountEnabled=false`), **jamais** celle du principal de la ressource, qui couperait tout le tenant (`test_a_consent_card_never_proposes_to_block_the_resources_principal`) ; révoquer les sessions de qui a consenti |
| rôle privilégié (`:213`) | vérifier l'attribution ; la retirer (`DELETE roleManagement/directory/roleAssignments/<id>`) ; revoir ce que le nouveau membre a fait, révoquer les sessions de l'auteur |
| connexion inhabituelle (`:225`) | vérifier l'adresse avec le propriétaire ; non attendue : retirer ses identifiants et bloquer sa connexion, « l'usage légitime s'arrête aussi : au propriétaire d'en décider » |
| l'identité de Glorfindel, acteur ou cible (`:245-252`) | renouveler ses identifiants, vérifier ses identifiants et ses rôles |

Toute carte finit par : « Glorfindel n'agit jamais seul sur une identité (détection seule) ».

### 1.4 Ce qui manque

1. **Aucune action**, même approuvée par un humain : il ouvre le portail ou un terminal, sous son
   propre compte.
2. **Des identifiants à trouver** : `<keyId>`, l'id de l'octroi, l'id de l'attribution. La carte
   ne les lit pas dans Graph ; la ligne du journal en donne une partie (`CredentialAdded`).
3. **Aucune vérification après le geste** : la carte ne sait pas si l'identifiant a été retiré,
   ni si le principal est encore actif.
4. **Aucune trace du retour arrière** : ce qui a été retiré n'est noté nulle part, et le
   remettre dépend de la mémoire de l'humain.

---

## 2. Les actions possibles

Elles vont de la plus légère à la plus lourde. Pour chacune : l'API Microsoft Graph, le droit
minimum, la réversibilité, la vérification après l'action, le retour arrière, et l'effet de bord
sur une charge réelle. Ce qui est cité vient de la documentation (§8) ; le reste est marqué
**hypothèse**.

**Ce qui vaut pour toutes** :
- **Un jeton déjà émis vit jusqu'à son expiration.** Sa durée par défaut est tirée entre 60 et
  90 minutes, 75 en moyenne (doc, « Configurable token lifetimes »). Quand le client et la
  ressource prennent en charge l'évaluation continue de l'accès (CAE), elle peut monter à 24 ou
  28 heures, mais ces jetons sont alors « revoked in near real time in response to critical events
  such as account disablement and password changes » (doc). Supprimer un octroi délégué le dit
  aussi : « Existing access tokens will continue to be valid for their lifetime » (doc).
  **Hypothèse** : il en va de même d'un jeton d'application après le retrait de son identifiant.
- **Une écriture ne s'applique pas tout de suite** : « there might be a small delay of a few
  minutes before tokens are revoked » (doc, `revokeSignInSessions`).
- **Une application et son principal de service sont deux objets** : un identifiant s'ajoute à
  l'un ou à l'autre, et C2 dit lequel (`TargetType`). Leurs `id` diffèrent, et leur `appId` est
  commun.
- **Une identité managée est hors champ** : C2 ne lit pas sa table de connexions
  (`detection_rules.yaml:534`), et son principal suit la ressource Azure qui le porte
  (**hypothèse** : Graph ne lui ajoute ni ne lui retire d'identifiant).

### 2.1 Retirer l'identifiant ajouté

- **L'API** :
  - un secret : `POST /applications/{id}/removePassword` ou `POST /servicePrincipals/{id}/removePassword`,
    avec `{"keyId": …}` ; réponse `204` (doc) ;
  - un certificat : `POST /applications/{id}/removeKey` exige une preuve de possession, un JWT
    « signed with a private key that corresponds to one of the existing valid certificates
    associated with the application » (doc). Eregion ne tient pas cette clé : il passe donc par
    `PATCH /applications/{id}` (ou `/servicePrincipals/{id}`) avec la collection `keyCredentials`
    moins ce `keyId` (doc, « Update servicePrincipal » : `keyCredentials` modifiable).
    **Hypothèse** : le `PATCH` remplace la collection entière, sans condition de version ; deux
    écritures concurrentes s'écrasent. Il faut relire juste avant et juste après ;
  - un identifiant fédéré : `DELETE /applications/{id}/federatedIdentityCredentials/{id}` ; réponse
    `204` (doc).
- **Le droit minimum** : en application, `Application.ReadWrite.OwnedBy`, pour les trois (doc). Sa
  description : « It cannot update any apps that it is not an owner of » (doc, « permissions
  reference »). En délégué, `Application.ReadWrite.All` avec le rôle Cloud Application
  Administrator ou Application Administrator, ou bien le propriétaire de l'application (doc).
- **La réversibilité** :
  - **un secret : irréversible.** Sa valeur n'est rendue qu'à sa création (**hypothèse de
    lecture** de `addPassword`) ; une fois retiré, il ne revient pas ;
  - **un certificat : réversible**, si sa partie publique a été lue avant. La propriété `key` « Requires
    `$select` to retrieve; only available for single object requests » (doc, `keyCredential`) :
    `GET /applications/{id}?$select=keyCredentials`, gardé par l'exécuteur avant le retrait ;
  - **un identifiant fédéré : réversible**, sa définition (nom, émetteur, sujet, audiences) se
    recrée à l'identique.
- **La vérification** :
  - `GET /applications/{id}?$select=passwordCredentials,keyCredentials` (ou le principal) ne
    montre plus ce `keyId`, et la liste des identifiants fédérés ne montre plus le sien ;
  - plus tard, la ligne de `AuditLogs` de ce retrait, sous l'identité de l'exécuteur ;
  - **hypothèse** : passé l'expiration des jetons, plus aucune connexion du principal avec cet
    identifiant (`AADServicePrincipalSignInLogs` nommerait l'identifiant utilisé ; colonne à
    mesurer).
- **Le retour arrière** : un certificat se remet par le même `PATCH`, la collection plus la partie
  publique gardée ; un identifiant fédéré par `POST /applications/{id}/federatedIdentityCredentials`.
  Un secret ne se remet pas : le propriétaire en crée un autre et le distribue. C'est un geste
  humain.
- **L'effet de bord** : si l'identifiant retiré est bien celui de l'attaquant, les identifiants
  légitimes restent, et l'application de production ne voit rien. Si c'est un faux positif (la
  rotation d'un pipeline, le cas d'exclusion connu de C2), l'application perd l'identifiant
  qu'elle vient de recevoir : elle échoue à son prochain jeton, dans l'heure et demie (hypothèse).

### 2.2 Révoquer les sessions

- **L'API** : `POST /users/{id}/revokeSignInSessions`. Elle « Invalidates all the refresh tokens
  issued to applications for a user (and session cookies in a user's browser), by resetting the
  signInSessionsValidFromDateTime user property to the current date-time » (doc). Elle ne vaut pas
  pour un utilisateur externe, qui se connecte par son propre tenant (doc).
- **Un principal de service n'a pas de session à révoquer** : le flux des identifiants du client
  ne délivre pas de jeton d'actualisation (**hypothèse**, doc du flux « client credentials »).
  Pour lui, l'équivalent est 2.1, puis 2.5.
- **Le droit minimum** : `User.RevokeSessions.All`, en délégué comme en application (doc). En
  délégué, le rôle dépend du rôle de la cible : le tableau « Who can reset passwords » liste les
  rôles qui peuvent « reset passwords and invalidate refresh tokens », du Helpdesk Administrator
  pour un utilisateur sans rôle au Privileged Authentication Administrator pour tout
  administrateur (doc). **Hypothèse** : en application, la permission seule suffit, pour tout
  utilisateur du tenant, administrateurs compris, et ne se borne pas à une unité administrative. À
  mesurer : c'est la portée que la décision du Q3 demande de mesurer au banc. Et dans une unité
  administrative **restreinte**, une permission d'application ne s'applique pas à ses membres
  (§3.6) : la révocation d'un utilisateur de test y passerait par le rôle borné à l'unité.
- **La réversibilité** : irréversible dans l'acte, il n'y a rien à remettre ; mais l'effet ne
  coûte qu'une nouvelle connexion. C'est l'action la moins lourde dans son effet.
- **La vérification** : `GET /users/{id}?$select=signInSessionsValidFromDateTime` donne une heure
  postérieure à la demande ; ensuite, une actualisation refusée dans `SigninLogs` (**hypothèse** :
  le code d'erreur, à mesurer). Un jeton d'accès déjà émis reste valable jusqu'à son expiration.
- **Le retour arrière** : aucun, et aucun n'est nécessaire : l'utilisateur se reconnecte.
- **L'effet de bord** : l'utilisateur se reconnecte partout, avec son MFA. Un compte d'utilisateur
  qui sert de compte de service (un flux hérité) s'arrête jusqu'à ce que quelqu'un se reconnecte
  (hypothèse). Elle n'arrête pas un attaquant qui tient le mot de passe : il se reconnecte. La
  réinitialisation du mot de passe reste un geste humain, hors de ce lot.

### 2.3 Retirer l'attribution de rôle

- **L'API** :
  - une attribution active : `DELETE /roleManagement/directory/roleAssignments/{id}`, réponse `204` (doc) ;
  - une attribution éligible (PIM) : `POST /roleManagement/directory/roleEligibilityScheduleRequests`
    avec `"action": "adminRemove"`, `roleDefinitionId`, `directoryScopeId` et `principalId` (doc) ;
  - une attribution active par PIM : `roleAssignmentScheduleRequests`, même forme (**hypothèse** :
    page non lue ici).
- **Le droit minimum** : `RoleManagement.ReadWrite.Directory` pour la suppression ;
  `RoleEligibilitySchedule.ReadWrite.Directory` pour l'éligible ; et en délégué, « Privileged Role
  Administrator is the least privileged role supported for this operation » (doc, les deux pages).
  **La mise en garde de Microsoft** : « Permissions that allow granting authorization, such as
  RoleManagement.ReadWrite.Directory, allow an application to grant additional privileges to
  itself, other applications, or any user » (doc, « permissions reference »).
- **La réversibilité** : réversible. L'attribution se recrée avec le même triplet
  (`roleDefinitionId`, `principalId`, `directoryScopeId`) et, pour l'éligible, son échéance ; elle
  prend un nouvel `id`.
- **La vérification** : `GET /roleManagement/directory/roleAssignments?$filter=principalId eq '<p>'
  and roleDefinitionId eq '<r>'` est vide, de même pour les éligibilités ; puis la ligne
  « Remove member from role » de `AuditLogs` (hypothèse sur le nom).
- **Le retour arrière** : la même attribution recréée, avec le même droit.
- **L'effet de bord** : un administrateur légitime ou un pipeline (un principal de Terraform qui
  tient Application Administrator) perd le rôle ; ses écritures suivantes échouent en 403.
- **À côté** : l'attribution d'un rôle Azure (RBAC, que la règle d'AL1 lit dans `AzureActivity`)
  n'est pas un rôle d'annuaire. Elle se retire par l'API d'ARM, avec un droit d'Owner ou de User
  Access Administrator, qui porte la même mise en garde. Même traitement : hors d'IR1.

### 2.4 Retirer ou bloquer le consentement

- **L'API** :
  - un octroi délégué : `DELETE /oauth2PermissionGrants/{id}`, réponse `204` (doc). Deux octrois
    peuvent coexister pour une même application, l'un de l'utilisateur (`Principal`), l'autre de
    l'administrateur (`AllPrincipals`) (doc) : on les lit tous par `clientId` ;
  - une permission d'application (un rôle d'application) :
    `DELETE /servicePrincipals/{resource-id}/appRoleAssignedTo/{id}`, la méthode que la doc
    recommande ;
  - bloquer sans retirer : désactiver le principal de l'application cliente (2.5), ou
    `PATCH /servicePrincipals/{client-id}` avec `appRoleAssignmentRequired: true`, qui exige une
    attribution avant de délivrer un jeton à un utilisateur (doc). **Hypothèse** : cela n'arrête
    pas les jetons d'application.
- **Le droit minimum** :
  - octroi délégué : `DelegatedPermissionGrant.ReadWrite.All` (doc), qui « Allows the app to
    manage permission grants for delegated permissions exposed by any API (including Microsoft
    Graph) » (doc) ;
  - rôle d'application : `AppRoleAssignment.ReadWrite.All` (doc), avec cette mise en garde :
    « Permissions that allow granting authorization, such as AppRoleAssignment.ReadWrite.All, allow
    an application to grant additional privileges to itself, other applications, or any user »
    (doc). En délégué, Privileged Role Administrator est le moindre rôle pour les rôles
    d'application de Microsoft Graph (doc).
- **La réversibilité** : réversible, si l'octroi a été lu avant : `clientId`, `consentType`,
  `principalId`, `resourceId`, `scope` ; ou l'attribution : `principalId`, `resourceId`, `appRoleId`.
- **La vérification** : `GET /oauth2PermissionGrants?$filter=clientId eq '<sp>'` ne montre plus les
  portées retirées ; `GET /servicePrincipals/{client-id}/appRoleAssignments` ne montre plus le rôle.
- **Le retour arrière** : l'octroi ou l'attribution recréés à l'identique, avec le même droit.
- **L'effet de bord** : une intégration légitime perd l'accès au courrier, aux fichiers, à Graph,
  et s'arrête. Le principal de la **ressource** (Microsoft Graph lui-même) n'est jamais une
  cible : C2 le dit déjà (`entra.py:196-210`).

### 2.5 Désactiver le principal ou l'utilisateur

- **L'API** :
  - un principal de service : `PATCH /servicePrincipals/{id}` avec `{"accountEnabled": false}`
    (doc). La doc prévient : un principal hérite de propriétés de son application, et « updating a
    service principal may prompt the directory to refresh properties from the app registration,
    causing updates that weren't part of the original request » ;
  - un utilisateur : `PATCH /users/{id}` avec `{"accountEnabled": false}` (doc).
- **Le droit minimum** :
  - principal : `Application.ReadWrite.OwnedBy` en application (doc) ; en délégué, Application
    Administrator ou Cloud Application Administrator (doc) ;
  - utilisateur : « User.EnableDisableAccount.All + User.Read.All is the least privileged
    combination of permissions » (doc). C'est une **action sensible** : en application, il faut en
    plus un rôle d'administrateur, selon le rôle de la cible (doc, « Who can perform sensitive
    actions ») : Authentication Administrator ou User Administrator pour un utilisateur sans rôle,
    Privileged Authentication Administrator pour tout administrateur. **Décidé (Q2)** : un User
    Administrator attribué à la portée de l'unité administrative du banc, qui ne contient que ses
    utilisateurs de test (§3.6). La doc dit qu'à cette portée, « role permissions apply only when
    managing members of the administrative unit itself ».
- **La réversibilité** : réversible, `accountEnabled: true`, à condition de savoir qu'il était actif
  avant.
- **La vérification** : `GET …?$select=accountEnabled` vaut `false` ; puis des connexions refusées
  dans les journaux (**hypothèse** : le code d'erreur d'une application désactivée, à mesurer). Un
  client CAE perd ses jetons presque aussitôt ; les autres les gardent jusqu'à leur expiration
  (doc).
- **Le retour arrière** : `accountEnabled: true`, seulement si l'exécuteur l'a désactivé lui-même et
  l'a vu actif juste avant. Il ne réactive jamais ce qui l'était déjà avant lui.
- **L'effet de bord** : le plus lourd. L'application s'arrête entièrement, pour tous ses
  utilisateurs et toutes ses charges, et la production tombe. Un utilisateur est fermé dehors ; si
  c'est un administrateur, c'est peut-être celui qui doit répondre.

### 2.6 En une table

| Action | API | Droit minimum (application) | Réversible | Effet de bord si faux positif |
|---|---|---|---|---|
| retirer un secret | `removePassword` | `Application.ReadWrite.OwnedBy` | **non** | l'application perd l'identifiant qu'elle utilise |
| retirer un certificat | `PATCH keyCredentials` | `Application.ReadWrite.OwnedBy` | oui (partie publique gardée) | idem |
| retirer un identifiant fédéré | `DELETE federatedIdentityCredentials` | `Application.ReadWrite.OwnedBy` | oui | un pipeline fédéré (CI) s'arrête |
| révoquer les sessions | `revokeSignInSessions` | `User.RevokeSessions.All` (portée : hypothèse) | rien à remettre | une reconnexion |
| retirer un rôle d'annuaire | `DELETE roleAssignments`, `adminRemove` | `RoleManagement.ReadWrite.Directory` (**s'accorde des privilèges**) | oui | un administrateur ou un pipeline en 403 |
| retirer un consentement | `DELETE oauth2PermissionGrants`, `appRoleAssignedTo` | `DelegatedPermissionGrant.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All` (**s'accorde des privilèges**) | oui (lu avant) | une intégration s'arrête |
| désactiver un principal | `PATCH accountEnabled` | `Application.ReadWrite.OwnedBy` | oui | l'application tombe |
| désactiver un utilisateur | `PATCH accountEnabled` | un rôle d'administrateur (retenu : User Administrator borné à l'unité du banc, §3.6), avec `User.EnableDisableAccount.All` + `User.Read.All` hors d'une unité restreinte | oui | un humain fermé dehors |

---

## 3. La place de chaque action dans Eregion

### 3.1 Jamais autonome : toutes, quel que soit le mode

C'est vrai pour les cinq, et en `full_auto` comme en `human_only`. Les raisons :

1. **Le faux positif le plus cher.** Une identité n'est pas bornée à une VM : un principal
   désactivé arrête une application partout, un administrateur fermé dehors ne répond plus. C2
   l'écrit déjà : « an autonomous action on an identity is the costliest false positive there is »
   (`agent.py:1063-1065`).
2. **Le faux positif connu est fréquent.** La rotation d'un identifiant par un pipeline ressemble
   trait pour trait à l'ajout d'un attaquant ; seul le propriétaire sait.
3. **L'autonomie n'achète pas de vitesse ici.** Les journaux d'Entra arrivent en minutes, parfois
   bien plus (`expected_latency_s: 1800`) ; un jeton volé vit 60 à 90 minutes, et l'attaquant a
   déjà agi. Le gain d'une réponse sans humain se compte en minutes, sur une fenêtre de plus d'une
   heure.
4. **Rien n'est mesuré.** Ni la précision des quatre règles, ni leur latence (ID1). Les critères de
   maturité qui ouvrent l'autonomie (ROADMAP) ne sont pas remplis, même pour une VM.
5. **Révoquer les sessions est le seul candidat sérieux**, parce que son effet est léger. Il reste
   humain : un attaquant qui provoque des événements (il peut enregistrer une application,
   choisir son nom) ferait déconnecter l'opérateur, encore et encore, au pire moment. Ce serait
   un déni de service contre le défenseur. À rouvrir après une observation mesurée, pas avant.

**Ce que cela donne dans le code, proposé pour IR1a et IR1c** :
- Un ensemble `IDENTITY_ACTIONS` (les verbes du §3.3), **disjoint** d'`AUTONOMOUS_ACTIONS` et
  inclus dans `HUMAN_APPROVAL_REQUIRED` (`glorfindel/response/policy.py:10`, `:20`), avec un test
  et un mutant par propriété.
- `_identity_decision` garde `action: ""`. Les deux verrous de C2 ne bougent pas. Aucun mode ne
  débloque un verbe d'identité : `_apply_autonomy_mode` ne le voit jamais, puisqu'aucune décision
  ne le porte.
- La carte reste `identity_change`, ancrée. L'approbation ne passe pas par son champ `action` :
  elle passe par des propositions distinctes, une par verbe (§3.2).

### 3.2 Ce que l'humain approuve : un plan, verbe par verbe

1. **La watch écrit un plan sur la carte**, par le code, depuis la ligne du journal et jamais par
   le modèle. Le plan dit les verbes dans l'ordre, chacun avec ses paramètres exacts : l'`id` de
   l'objet, le `keyId`, l'`id` de l'octroi ou de l'attribution. Avec IR1a, ces paramètres sont lus
   dans Graph, en lecture seule (§3.4).
2. **Chaque verbe que l'exécuteur peut faire porte une proposition**, signée par la watch sous
   `eregion.action-queue/1` (FS1 §2.4), avec `kind: "proposal"` et `plane: "identity"`. Elle porte
   en plus le tenant, l'objet visé et son type, les paramètres, et la preuve : le `CorrelationId`
   et l'`EventId` du constat.
3. **Les verbes que l'exécuteur ne peut pas faire** (le rôle, le consentement, le secret en zone
   `production`, une cible de `never_target`) restent des étapes : la commande exacte, à taper par
   l'humain avec son propre compte, puis un bouton **Vérifier** qui relit Graph et dit « tenu » ou
   « pas tenu ».
4. **L'humain approuve un verbe à la fois, selon son poids** (décision du Q4) :
   - **léger et réversible, un clic dans la console** : retirer un certificat ou un identifiant
     fédéré, les remettre, réactiver un principal ou un utilisateur, révoquer des sessions ;
   - **lourd ou irréversible, sur le poste de l'opérateur, le nom de la cible tapé** : retirer un
     secret, désactiver un principal, **désactiver un utilisateur**. C'est le geste d'un fil
     destructif de Dagorlad (DG-b) : la console ne fait que poser la demande ; une commande du
     poste (`make identity-act`, nom à fixer) la montre, demande le nom de la cible, le compare
     au nom que l'exécuteur relit dans Graph, puis la signe avec une clé de l'opérateur, épinglée
     chez l'exécuteur. Une console compromise ne peut donc pas taper ce nom à la place de
     l'humain. La forme exacte de cette clé (une troisième clé de FS1, à côté de celles de la
     console et du bot) se fixe dans IR1c.
5. **Le bot montre, il n'agit pas** (décision du Q5) : il dit le plan et donne le lien vers la
   console. Aucun verbe d'identité ne lui est permis ; une demande d'identité dans son répertoire
   est refusée, `verb_not_allowed`, carte critique.

Le plan, par constat :

| Constat | Verbes de l'exécuteur | Étapes pour l'humain |
|---|---|---|
| identifiant ajouté | `entra_remove_credential` (l'identifiant ajouté seul) | la rotation des autres identifiants, si l'auteur n'est pas attendu |
| consentement | `entra_disable_principal` (l'application **cliente**, jamais la ressource) | retirer l'octroi ou l'attribution ; révoquer les sessions de qui a consenti |
| rôle privilégié | `entra_revoke_sessions` (le membre ajouté, l'auteur s'il n'est pas attendu) ; `entra_disable_user` si l'auteur est un utilisateur de test inscrit | retirer l'attribution |
| connexion inhabituelle | `entra_remove_credential` (l'identifiant que la connexion a utilisé, s'il est lu), sinon `entra_disable_principal` | la rotation des autres identifiants |
| l'identité de Glorfindel, acteur ou cible | aucun | renouveler ses identifiants (§3.5) |

Pour le consentement, s'ajoutent `entra_revoke_sessions` et, le cas échéant, `entra_disable_user`
sur l'utilisateur de test qui a consenti. Un verbe sur un utilisateur n'est jamais proposé pour un
utilisateur qui n'est pas inscrit (§3.6) : il reste une étape.

Et les verbes de retour : `entra_restore_credential` (certificat ou identifiant fédéré, depuis ce
que l'exécuteur a gardé), `entra_enable_principal` et `entra_enable_user` (seulement s'il l'a
désactivé lui-même).

### 3.3 Par la file signée de FS1, exécutée par un exécuteur d'identité

**Oui, la file de FS1.** Même format de demande (FS1 §2.3), mêmes clés par service (Q1 de FS1),
même vérification avant tout appel au cloud (FS1 §2.8). Les verbes d'identité s'y ajoutent, en
liste fermée : `entra_remove_credential`, `entra_restore_credential`, `entra_disable_principal`,
`entra_enable_principal`, `entra_revoke_sessions`, `entra_disable_user` et `entra_enable_user`
(décision du Q2). Ils ne sont permis qu'à la console, et chacun selon son poids : un verbe lourd
n'est accepté que signé par la clé de l'opérateur (§3.2).

**Mais jamais la watch.** Elle agit seule dans le graphe, et elle lit du texte que l'attaquant
écrit. SEC7 a fixé la même règle pour le restore : « même un bogue ou une décision détournée ne le
pourrait pas ». Un droit d'écriture sur Entra ID dans la watch serait à portée de toute
décision autonome mal routée. FS1g a tranché le restore par **un exécuteur à part** (décision du
04/11) ; Jonathan a retenu le même modèle pour l'identité (décision du Q1, 05/11).

**L'exécuteur d'identité** est un service qui :
- n'a **aucun chemin autonome** : il ne fait que relever des demandes signées ;
- relève son propre répertoire de demandes, distinct de celui de la watch, pour que la watch ne
  lise jamais un verbe d'identité et que lui ne lise jamais un verbe de VM. La forme exacte suit
  celle que FS1g fixera pour le restore ;
- vérifie la demande comme la watch (FS1 §2.8 : forme, signature, clé épinglée du service,
  fraîcheur, nonce, verbe permis à ce service) ;
- vérifie la proposition avec **la clé publique de la watch, épinglée chez lui**
  (`EREGION_WATCH_KEY`, comme un injecteur, SEC19), jamais lue sur le disque partagé ;
- puis rejoue ses propres gardes, avant tout appel d'écriture :
  1. le tenant de la proposition est le sien ;
  2. la cible est **inscrite** (IDI1 pour une application ou un principal, IDI1b pour un
     utilisateur de test, §3.6 ; lue maintenant dans Graph) et dans une zone qui permet ce
     verbe : en `production`, jamais un verbe irréversible (le retrait d'un secret) ;
  3. la cible n'est pas dans `never_target` (§3.5) : jamais un opérateur ni un compte de secours ;
  4. un verbe sur un utilisateur respecte son débit (décision du Q3) : au plus quelques
     révocations et une désactivation par heure et par utilisateur, et un plafond pour tout le
     banc (les chiffres se fixent dans IR1c) ; au-delà, `rate_limited`, carte ;
  5. un verbe lourd est signé par la clé de l'opérateur, et le nom tapé est celui que
     l'exécuteur relit dans Graph (§3.2) ; sinon `operator_gesture_missing` ;
  6. **la preuve tient** : il relit lui-même la ligne de `AuditLogs` (ou de
     `AADServicePrincipalSignInLogs`) par son `CorrelationId`, avec son propre rôle de lecture du
     workspace, et elle dit ce que dit la proposition. Une watch compromise ne lui fait donc pas
     croire à un constat qui n'existe pas ;
  7. **l'état tient** : le `keyId` est encore sur l'objet, le principal ou l'utilisateur est encore
     actif. Sinon : `nothing_to_do`, et c'est dit ;
- garde ce qu'il faut pour le retour (la partie publique d'un certificat, la définition d'un
  identifiant fédéré, l'état `accountEnabled` d'avant) dans un répertoire que lui seul monte ;
- agit, vérifie (§2), et écrit un reçu signé par **sa** clé, avec le résultat et la vérification.

Les codes de refus de FS1 (§2.11) valent tels quels. Il s'y ajoute `not_enrolled`, `zone`,
`never_target`, `operator_gesture_missing`, `evidence_mismatch`, `nothing_to_do` et
`beyond_contract` (§3.4). Un
`never_target` ou un `evidence_mismatch` fait une carte critique, décidée par le code.

### 3.4 Qui tient le droit d'écriture sur Entra ID

| Identité | Sur Entra ID |
|---|---|
| la watch | **aucune écriture, jamais.** Les journaux par Log Analytics Reader, comme aujourd'hui. Avec IR1a, une lecture de Graph pour écrire le plan et vérifier le geste d'un humain : `Application.Read.All`, `RoleManagement.Read.Directory`, `User.Read.All` (droits exacts à mesurer) |
| la console, le bot | aucune (FS1 : lecteurs) |
| l'exécuteur de restore (FS1g) | aucune |
| **l'exécuteur d'identité** | `Application.ReadWrite.OwnedBy`, et la **propriété** de chaque application inscrite et de son principal, posée par IDI1 (Celebrimbor), jamais par lui ; `User.RevokeSessions.All`, borné par le code aux utilisateurs inscrits (Q3) ; **User Administrator à la portée de l'unité administrative du banc**, avec Directory Readers au tenant que la doc exige pour qu'un principal s'en serve, et `User.EnableDisableAccount.All` + `User.Read.All` si l'unité n'est pas restreinte (§3.6) ; Attribute Assignment Reader à la portée de l'ensemble d'attributs d'Eregion (§3.6) ; Log Analytics Reader sur le workspace, pour relire la preuve |
| l'opérateur | son propre compte, avec ses rôles (activés par PIM là où c'est possible) : c'est lui qui retire un rôle ou un consentement, depuis le plan |

**Refusés à toute identité d'Eregion**, dits dans `docs/operations.md` (« Identités Azure ») et
vérifiés en code :
- les permissions `RoleManagement.ReadWrite.Directory`, `RoleEligibilitySchedule.ReadWrite.Directory`,
  `RoleAssignmentSchedule.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`,
  `DelegatedPermissionGrant.ReadWrite.All`, `Application.ReadWrite.All`, `Directory.ReadWrite.All` ;
- les rôles Global Administrator, Privileged Role Administrator, Privileged Authentication
  Administrator, et Application Administrator, Cloud Application Administrator ou User
  Administrator à la portée du tenant. User Administrator n'est permis qu'à la portée de l'unité
  du banc, et nulle part ailleurs.

La raison est dans la doc : chacune permet d'agir comme une autre entité ou de s'accorder des
privilèges (les mises en garde citées au §2, et pour `Application.ReadWrite.All` : « Permissions
that allow managing credentials […] allow an application to act as other entities, and use the
privileges they were granted »). Une identité d'Eregion qui les tiendrait tiendrait le tenant.

**Le contrat, vérifié au démarrage**, comme celui d'Orodruin (SEC11 : tout autre droit le rend
passif). L'exécuteur lit ses propres permissions d'application
(`GET /servicePrincipals/{lui}/appRoleAssignments`) et ses rôles d'annuaire
(`GET /roleManagement/directory/roleAssignments?$filter=principalId eq '<lui>'`). Il refuse
d'écrire, `beyond_contract`, s'il tient un droit de la liste refusée, un droit qu'il ne connaît pas,
un User Administrator à une autre portée que `/administrativeUnits/<l'unité du banc>` (son `id`
épinglé dans son environnement, jamais cherché par son nom), ou s'il ne peut pas lire les siens
(fermé). Hypothèse à mesurer : les droits qu'il faut pour lire
les siens.

**Sur H0**, l'exécuteur est un conteneur à qui le point de jeton de la VM est coupé (FS1, Q3,
décision du 04/11). Il a donc son propre principal, avec un certificat dont la clé est tirée sur
l'hôte, dans un répertoire que lui seul monte. FS1 l'a noté (son hypothèse 4) : un certificat volé
s'utilise **depuis n'importe où**. L'accès conditionnel pour les identités de charge de travail
pourrait le borner à l'adresse de H0 (**hypothèse**, licence à vérifier) : c'est un point ouvert
(§4).

### 3.5 Ne jamais viser Glorfindel, Orodruin, ni l'opérateur

**La liste `never_target`**, comme `NEVER_BLOCK_SHIPPED` pour les adresses
(`glorfindel/response/policy.py:105-109`) : ce qui est livré, puis ce que la configuration ajoute.
Elle tient :
- les identités de Glorfindel : chaque `*_AZURE_CLIENT_ID` des services (watch, console, bot,
  exécuteur de restore, exécuteur d'identité), `GLORFINDEL_OWN_CALLERS`, l'identité managée de H0 ;
  et pour chacune, l'objet de l'application **et** celui du principal (C2 l'a appris : l'objet de
  l'application n'est pas dans le jeton, `entra.py:38-39`) ;
- l'identité d'Orodruin (une sortie de l'état d'`infra/orodruin`) et le principal d'Annatar ;
- les opérateurs et les comptes de secours, nommés par l'opérateur (`never_target` dans
  `glorfindel-config.yaml`, par `id` d'objet) ;
- toute application dont le propriétaire est Microsoft (`appOwnerOrganizationId`), et le principal
  de la ressource d'un consentement ;
- toute identité qui tient un rôle de `PRIVILEGED_ROLES` : sa réponse revient à un humain qui a ce
  niveau.

**Fermée** : une liste illisible refuse tout, comme `never_block` (`policy.py:116-120`, `:143-152`). Un `id`
qu'on ne sait pas rattacher à son application et à son principal est refusé.

**Trois verrous** :
1. **La watch** n'écrit jamais de proposition sur une cible de la liste : son plan devient une
   étape pour l'humain.
2. **L'exécuteur** la refuse, `never_target`, et c'est une carte critique : une proposition qui
   la vise est signée par la watch, donc quelque chose ne va pas.
3. **Entra ID** : l'exécuteur n'est propriétaire d'aucune de ces identités, et
   `Application.ReadWrite.OwnedBy` lui vaut un 403. Aucun opérateur ni compte de secours n'est
   membre de l'unité du banc, donc son User Administrator borné ne les atteint pas.
   **Ce verrou n'existe pas pour `entra_revoke_sessions`** si sa permission vaut pour tout le
   tenant (hypothèse 4) : là, seuls le code, l'inscription et le débit tiennent. C'est dit, et
   c'est ce que la mesure au banc doit trancher (décision du Q3).

**Quand la cible est Glorfindel** (`GlorfindelManaged`, `GlorfindelIdentity`) : jamais
l'exécuteur. Un attaquant qui ajoute un identifiant à l'application de la watch ne doit pas
pouvoir faire désactiver la watch par Eregion. La réponse est le renouvellement de ses
identifiants, un geste de l'opérateur, et la carte le dit.

**Quand la cible est l'exécuteur lui-même** : refusé, carte critique. Il ne se désactive pas et ne
se retire rien.

### 3.6 L'unité administrative du banc, et l'inscription d'un utilisateur de test (IDI1b)

La décision du Q2 donne à l'exécuteur la désactivation d'un **utilisateur de test**, par un User
Administrator borné à une unité administrative du banc. Ce qui suit décrit cette unité ; ce qui
vient de la doc est cité, le reste est une proposition pour IDI1b.

**Ce qu'est une unité administrative** (doc, « Administrative units ») : un conteneur d'objets
d'Entra ID, qui « can contain only users, groups, or devices ». Un rôle attribué à sa portée ne
vaut que pour ses membres : « role permissions apply only when managing members of the
administrative unit itself, and don't apply to tenant-wide settings or configurations » (doc,
« Assign Microsoft Entra roles »). Les unités ne s'imbriquent pas. Un groupe ajouté y entre seul,
sans ses membres (doc).

**Une unité restreinte** *(proposé)*. Une unité administrative peut être créée « à gestion
restreinte » (doc, « Restricted management administrative units ») :
- seuls les administrateurs attribués **à sa portée** modifient ses membres. Global Administrator
  et Privileged Role Administrator au tenant ne les modifient pas ; ils gèrent l'unité elle-même
  (ses membres, ses attributions), et se donner un rôle à sa portée est « an auditable event »
  (doc) ;
- « If you assign Microsoft Graph application permissions to the application, those permissions
  won't apply because it's restricted » ; il faut un rôle à la portée de l'unité (doc). Les
  permissions larges qu'une identité d'Eregion tiendrait ne touchent donc pas ses membres : seul
  le rôle borné les touche ;
- chaque entrée et chaque sortie d'un membre, et chaque rôle attribué à sa portée, s'écrit dans
  `AuditLogs` (catégories `AdministrativeUnit` et `RoleManagement`, doc) : C2 peut les lire ;
- ses limites (doc) : le caractère restreint se fixe **à la création** et ne change plus ; ses
  membres ne se gèrent ni par PIM ni par les autres outils de gouvernance ; à sa suppression, les
  protections peuvent mettre 30 minutes à se lever ; 100 unités restreintes au plus par tenant.

Pourquoi restreinte : les utilisateurs de test ne sont modifiables que par le rôle borné, et
l'inscription (l'appartenance) devient un geste d'administrateur tracé. **Ce que ça coûte** : la
permission `User.RevokeSessions.All` ne s'appliquerait pas à ses membres, et une révocation
passerait par le rôle borné (hypothèse 12). La décision du Q3 se mesure donc aussi ici.

**Qui la crée** : Celebrimbor (`infra/terraform/`), dans un fichier désactivé par défaut, comme
`entra_logs.tf`. Le plan et l'apply sont faits par Jonathan, avec un compte Privileged Role
Administrator. Le fichier crée :
- l'unité, restreinte, dont le nom dit le banc ; son `id` sort en `output`, et c'est cet `id`,
  jamais le nom, que l'exécuteur et la garde d'IDI1b épinglent ;
- un ou plusieurs utilisateurs de test, sans aucun rôle, sans licence au-delà du nécessaire, et
  leur appartenance à l'unité ;
- le User Administrator à la portée de l'unité (`directoryScopeId: /administrativeUnits/<id>`), et
  Directory Readers au tenant, pour le principal de l'exécuteur : la doc dit qu'un principal de
  service ne se sert d'un rôle borné qu'avec une lecture du répertoire au tenant.

**Hypothèse** : le fournisseur `azuread` de Terraform sait créer une unité restreinte ; sinon, la
même chose par l'API de Graph, dans le même fichier. À vérifier dans IDI1b.

**Le rôle à sa portée, et ses limites** :
- User Administrator, à cette portée, « Can manage all aspects of users and groups, including
  resetting passwords for limited admins within the assigned administrative unit only » (doc) ;
- une partie de ses permissions ne vaut que pour un membre **sans rôle** : la doc liste la lecture
  et la modification des méthodes d'authentification, la réinitialisation du mot de passe, les
  propriétés sensibles, la suppression. Un utilisateur de test sans rôle (décision du Q6) reste
  donc à sa portée, et un utilisateur qui en aurait un sortirait de ce que l'exécuteur peut faire ;
- **ce qu'il ouvre** : l'exécuteur compromis pourrait réinitialiser le mot de passe d'un
  utilisateur de test, et le prendre. C'est pourquoi l'unité ne contient que des utilisateurs de
  test, jamais un groupe, et aucun ne tient de rôle ni de droit (§4) ;
- **plus étroit, à mesurer** : un rôle personnalisé, borné à l'unité, qui ne porterait que
  l'activation, la désactivation et l'invalidation des jetons d'actualisation d'un utilisateur
  (**hypothèse** : les noms de ces permissions de rôle personnalisé). La décision dit User
  Administrator ; un rôle plus étroit se proposerait à Jonathan après la mesure ;
- **la licence** : « Microsoft Entra ID P1 license for each administrative unit administrator »
  (doc). **Hypothèse** : ce qu'elle veut dire pour un principal de service, à vérifier sur le
  tenant du banc, comme la licence des journaux de connexion (C2).

**Comment un utilisateur de test s'inscrit (IDI1b)**. Un utilisateur n'a pas de `tags`, et O0 ne
lit que des tags d'ARM (`eregion_core/inscription.py:36-37`). Pour une VM, l'inscription tient en
deux moitiés qui doivent s'accorder : la VM et son groupe de ressources portent tous deux
`eregion-target=<banc>`, et la zone (`enrollment`, `inscription.py:158-184`). Pour un utilisateur, la même
forme *(proposé)* :
1. **l'appartenance à l'unité du banc**, l'équivalent du groupe de ressources : posée par
   Celebrimbor, lue par son `id` épinglé ;
2. **la même clé que sur ARM**, `eregion-target=<banc>` et `eregion-zone=<zone>`, portée par
   l'utilisateur lui-même. Le support proposé : un **attribut de sécurité personnalisé**, dans un
   ensemble d'attributs d'Eregion. La doc dit qu'il vaut pour les utilisateurs et les principaux
   de service, qu'il est gratuit, et que sa lecture et son écriture ont leurs propres rôles :
   « By default, Global Administrator and other administrator roles do not have permissions to
   read, define, or assign custom security attributes ». **User Administrator ne l'écrit donc
   pas** : l'exécuteur ne peut ni inscrire ni désinscrire un utilisateur. Les noms d'attribut
   n'admettent pas le tiret (doc) : la clé `eregion-target` s'y écrit sous un nom sans tiret, et
   la garde fait la correspondance.

Un utilisateur dont une moitié manque, dont les deux moitiés ne s'accordent pas, sans zone, d'un
autre tenant, ou qui tient un rôle, est refusé : la même garde que pour une VM. Un opérateur ou un
compte de secours n'est jamais membre de l'unité, et la garde le vérifie contre `never_target`.
Le même attribut pourrait inscrire un principal de service (IDI1) : à proposer dans ce lot, contre
les `tags` d'une application que #546 envisage.

---

## 4. Le modèle de menace

Ce que le nouveau droit ouvre, selon la position de l'attaquant. Le droit en jeu, c'est celui de
l'exécuteur : retirer un identifiant et désactiver un principal **sur les applications dont il est
propriétaire**, gérer **les utilisateurs de l'unité du banc** (User Administrator borné), et
révoquer des sessions (décisions des Q2 et Q3).

| Position | Ce qu'il pourrait faire avec ce droit | Ce qui le tient | Ce qui reste |
|---|---|---|---|
| **La console** (son jeton, sa clé de file) | demander un verbe d'identité | il ne peut viser qu'une proposition que la watch a signée, avec ses paramètres à elle ; l'exécuteur rejoue l'inscription, `never_target`, le débit, la preuve et l'état ; un verbe lourd ou irréversible (retirer un secret, désactiver un principal ou un utilisateur) exige la clé de l'opérateur et le nom tapé sur son poste (décision du Q4) | approuver un verbe léger en attente : retirer un certificat ajouté, réactiver, révoquer les sessions d'un utilisateur inscrit, dans le débit |
| **Le bot** | idem | aucun verbe d'identité pour le bot : il montre, il n'agit pas (décision du Q5) ; une demande d'identité de son répertoire est une carte critique | rien |
| **La watch** (sa clé, son hôte) | forger une proposition sur n'importe quelle cible | une proposition n'est qu'une proposition : un humain l'approuve ; l'exécuteur relit la preuve lui-même dans les journaux, avec sa propre identité (`evidence_mismatch`) ; inscription et `never_target` relus chez lui | la lecture de Graph d'IR1a : l'énumération du tenant (I) |
| **L'exécuteur** (son certificat volé, son conteneur) | retirer les identifiants et désactiver les applications inscrites ; révoquer les sessions de tout utilisateur (si la permission vaut pour tout le tenant : hypothèse) ; **créer des applications** (`OwnedBy` le permet) ; **ajouter un identifiant à une application qu'il possède et agir comme elle** ; désactiver un utilisateur de test, ou **réinitialiser son mot de passe et le prendre** (User Administrator borné) | rien ne lui permet de s'accorder un droit (la liste refusée, vérifiée au démarrage) ; une application ou un utilisateur inscrits ne tiennent aucun privilège (décision du Q6), donc agir comme eux ne donne rien ; il ne peut ni inscrire ni désinscrire un utilisateur (l'appartenance à l'unité restreinte et l'attribut de sécurité ne sont pas à sa portée, §3.6) ; chaque écriture d'Entra sous son identité sans reçu est une carte critique (IR1d, comme SID1 pour Run Command) ; un identifiant ajouté par lui est vu par C2, acteur marqué `GlorfindelIdentity` | un déni de service sur les identités du banc, et des déconnexions en masse (Q3) ; le certificat utilisable hors de H0 tant que l'accès conditionnel ne le borne pas |
| **Root sur H0, ou sa clé SSH** | tout ce que tient l'exécuteur | le même périmètre que ci-dessus : rien qui accorde un droit | ce qui est déjà ouvert sur H0 (§5 du modèle) |
| **Le contenu des journaux** (un nom d'application, un événement provoqué) | faire proposer une action sur une identité légitime | une proposition ne vise que la cible de l'événement, par son `id`, jamais par son nom ; pour viser une application de production, il faut déjà l'avoir compromise, et la proposer est alors juste ; un humain approuve | le bruit : des cartes, jamais une action |
| **Un rejeu** | rejouer une demande ou une proposition | le nonce de FS1, une proposition consommée une fois | — |
| **D** : l'exécuteur arrêté | aucune action d'identité | le plan reste sur la carte : l'humain l'exécute avec son compte, et Eregion vérifie | une perte de disponibilité, assumée comme pour la watch (FS1 §2.13) |
| **R** : une action sans trace | — | la demande, le reçu signé, et la ligne d'`AuditLogs` qu'Entra écrit lui-même, hors de l'hôte | — |

**Le point qui pèse le plus**, et qu'IDI1 porte (décision du Q6) : être propriétaire d'une
application, c'est pouvoir lui ajouter un identifiant, donc agir comme elle ; gérer un utilisateur,
c'est pouvoir réinitialiser son mot de passe. L'exécuteur ne doit posséder ou gérer que des
identités qui ne tiennent rien de plus que lui. **L'inscription refuse donc toute identité qui a un
rôle privilégié ou une permission de Graph en écriture**, et la garde de l'exécuteur le relit avant
chaque verbe : une identité qui en a gagné un depuis son inscription est refusée (`not_enrolled`),
et c'est une carte.

**Ce que le lot qui ferme IR1c écrit dans `docs/design/modele-de-menace.md`** :
- **§5, la ligne « E »** des identités : l'exécuteur d'identité, ses droits, la liste refusée, le
  contrat au démarrage ; « jamais une identité, un rôle » reste vrai pour la watch et H0 ;
- **§5, « Ouvert »** : l'accès conditionnel du certificat de l'exécuteur ; la portée de
  `User.RevokeSessions.All` ;
- **§5, le banc** : l'unité administrative restreinte du banc, son rôle borné, l'attribut
  d'inscription (IDI1b) ;
- **§1** et **§3** : les verbes d'identité de la console, selon leur poids, la clé de l'opérateur
  pour les verbes lourds, et rien pour le bot ;
- **§2** : le répertoire des demandes d'identité, l'état et les reçus de l'exécuteur.

---

## 5. Les hypothèses à mesurer

Tirées de la documentation, jamais mesurées ici. Chacune se mesure sur le tenant du banc, avec
Jonathan, avant d'être écrite comme un fait.

1. `Application.ReadWrite.OwnedBy` permet `removePassword`, le `PATCH` de `keyCredentials`, le
   `DELETE` d'un identifiant fédéré et le `PATCH` d'`accountEnabled` sur une application et un
   principal dont l'exécuteur est propriétaire, et donne un 403 sur tout autre.
2. Être propriétaire de l'application suffit pour son principal de service, ou il faut être
   propriétaire des deux objets.
3. Le `PATCH` de `keyCredentials` accepte la collection relue (avec `key` par `$select`) moins un
   élément, sans perdre les autres ; il n'a pas de condition de version.
4. `User.RevokeSessions.All`, en application, vaut pour tout utilisateur du tenant, administrateurs
   compris, et ne se borne pas à une unité administrative (la portée réelle que la décision du Q3
   demande de mesurer).
5. Un User Administrator à la portée de l'unité du banc ne désactive que les membres de l'unité,
   et seulement ceux sans rôle ; dans une unité non restreinte, il lui faut en plus
   `User.EnableDisableAccount.All` + `User.Read.All`, dans une unité restreinte non.
6. Après le retrait d'un identifiant ou la désactivation d'un principal, le jeton déjà émis reste
   valable jusqu'à son expiration (60 à 90 minutes) ; le délai réel de l'effet.
7. `AADServicePrincipalSignInLogs` nomme l'identifiant qu'une connexion a utilisé.
8. Les codes d'erreur d'une connexion refusée après chaque action, lisibles dans les journaux.
9. Les noms d'opération de `AuditLogs` pour chaque écriture de l'exécuteur, et leur latence
   (pour IR1d).
10. Les droits qu'il faut à l'exécuteur pour lire ses propres permissions et ses rôles (le
    contrat), et à la watch pour lire le plan (IR1a).
11. L'accès conditionnel pour les identités de charge de travail : ce qu'il borne (l'adresse), et
    sa licence.
12. Dans une unité restreinte, `User.RevokeSessions.All` ne touche pas ses membres, et le User
    Administrator borné révoque leurs sessions. Si c'est le cas, la permission large n'atteint plus
    que des utilisateurs non inscrits, que le code refuse déjà : la retirer serait alors à proposer
    à Jonathan.
13. Le fournisseur `azuread` de Terraform crée une unité restreinte, son rôle borné et les
    attributs de sécurité personnalisés ; sinon, l'API de Graph.
14. La licence P1 qu'exige un administrateur d'unité, pour un principal de service.
15. Un attribut de sécurité personnalisé se lit par Attribute Assignment Reader à la portée de son
    ensemble, et aucun rôle de l'exécuteur ne l'écrit.

---

## 6. La suite en lots

En jours de travail effectif, à ±50 %, comme la ROADMAP.

| Lot | Contenu | Attend | Sessions | Estimation |
|---|---|---|---|---|
| **IR1a** (fait, 05/11) | **Le plan et sa vérification, en lecture seule.** Le plan écrit par le code sur chaque carte `identity_change` (§3.2), avec ses paramètres lus dans Graph ; les commandes complètes, sans `<id>` à chercher ; le bouton **Vérifier**, qui relit Graph et dit « tenu » ou « pas tenu », noté au fil. La liste `never_target` dans `eregion_core/` (partagée avec IDI1). `IDENTITY_ACTIONS` disjoint d'`AUTONOMOUS_ACTIONS`. Graph seulement dans `glorfindel/providers/azure/` (`test_provider_boundary.py`). Un faux Graph, des tests, des mutants. | rien pour le code ; ID1 pour la mesure | Glorfindel, Console | 3–4 j |
| **IR1b** | **Le contrat de l'exécuteur** : la liste refusée, la lecture de ses droits, `beyond_contract` ; `docs/operations.md` (« Identités Azure ») ; l'application de l'exécuteur en Terraform, désactivée par défaut, ses permissions consenties par Jonathan. | IR1a | Glorfindel, Infra | 2 j |
| **IDI1b** | **L'inscription d'un utilisateur de test** (§3.6) : l'unité administrative restreinte du banc, ses utilisateurs de test sans rôle, le User Administrator à sa portée et Directory Readers pour l'exécuteur, l'ensemble d'attributs d'Eregion, en Terraform de Celebrimbor désactivé par défaut (plan et apply par Jonathan) ; la garde en deux moitiés (l'appartenance, l'attribut), la même que pour une VM ; tests sans réseau, mutants. | IDI1 (#546) | Infra, Glorfindel | 2–3 j |
| **IR1c** | **L'exécuteur d'identité** : les verbes du §3.3, la vérification de la demande et de la proposition, les gardes (inscription, zone, `never_target`, débit, clé de l'opérateur, preuve, état), l'état pour le retour, les reçus signés, les cartes critiques. Les verbes déposés par la console, la commande du poste pour les verbes lourds. | FS1a, FS1b (la file), FS1g (le modèle d'exécuteur), IDI1 et IDI1b (l'inscription et la propriété), IR1b | Glorfindel, Console | 5–7 j |
| **IR1d** | **L'exécuteur surveillé** : toute écriture d'Entra sous son identité sans reçu est une carte critique, comme SID1 pour Run Command ; le modèle de menace (§4). | IR1c, ID1 | Glorfindel | 1–2 j |
| **IR1e** | **Au banc, avec Jonathan** : les journaux d'Entra allumés et mesurés (ID1), une application et un utilisateur de test inscrits (IDI1, IDI1b), une technique d'une bibliothèque publique sur eux (R2) ; puis le plan, l'approbation, l'exécution, la vérification et le retour, chacun mesuré ; la portée réelle de la révocation des sessions (Q3) ; les hypothèses du §5. | IR1c, ID1, IDI1, IDI1b, R2 | Tests, Glorfindel | gestes |

**Ce qui vient d'abord** : IR1a. Il rend la carte utile tout de suite (des commandes complètes,
une vérification), sans aucun droit d'écriture, et il sert de repli à tout le reste : quand
l'exécuteur est arrêté ou qu'un verbe lui est refusé, c'est le plan qui reste.

**Ce qui attend ID1** (les journaux allumés) : toute mesure. Les tests d'IR1a et d'IR1c tournent sur
un faux Graph et de faux journaux, mais rien ne dit que les colonnes, les noms d'opération et les
latences sont les bons avant ID1.

**Ce qui attend IDI1** (#546) : toute écriture. Sans identité inscrite, aucune cible n'est permise,
et l'exécuteur n'est propriétaire de rien. IDI1 doit aussi porter : la propriété donnée à
l'exécuteur, le refus d'inscrire une identité qui tient un rôle privilégié ou une permission de
Graph en écriture (décision du Q6), et la liste `never_target`, partagée. **IDI1b** (§3.6) porte
l'utilisateur de test, qui n'a pas de `tags` : l'appartenance à l'unité du banc et la clé d'ARM
transposée en attribut de sécurité. Les verbes sur un utilisateur attendent IDI1b.

**Ce qui n'est pas prévu** : le retrait d'un rôle ou d'un consentement par Eregion (décision du
Q2) ; la réinitialisation d'un mot de passe ; un utilisateur hors de l'unité du banc ; une identité
managée ; un rôle Azure (ARM).

---

## 7. Questions pour Jonathan

Une à la fois, l'option recommandée en premier. Elles sont gardées telles qu'elles ont été posées ;
Jonathan les a tranchées le 05/11 (la section finale).

**Q1. Qui exécute une écriture sur Entra ID ?**
1. **Un exécuteur d'identité à part**, séparé de la watch et de l'exécuteur de restore, sur le
   modèle de FS1g *(recommandé)*. Raison : la watch agit seule et lit du texte de l'attaquant ;
   l'exécuteur n'a aucun chemin autonome, il relit la preuve lui-même, et ses droits ne se mêlent
   pas à ceux du restore. Ce que ça change : un service et un principal de plus, avec un
   certificat sur H0 (IMDS coupé, FS1 Q3).
2. **L'exécuteur de restore de FS1g, élargi** à l'identité. Ce que ça change : un service de moins,
   mais une seule identité qui tient le restore et l'écriture sur Entra ID ; sa compromission
   ouvre les deux.
3. **Personne dans Eregion** : le plan, les commandes et la vérification (IR1a) seulement ;
   l'humain exécute tout avec son compte. Ce que ça change : aucun droit d'écriture nouveau, mais
   aucune action en un geste, et la réponse dépend d'un humain qui tape juste.
4. **La watch.** Ce que ça change : le plus simple, mais un droit sur Entra ID à portée de toute
   décision autonome détournée, contre la règle de SEC7. Déconseillé.

**Q2. Quels verbes Eregion exécute-t-il lui-même ?**
1. **Retirer un identifiant, désactiver et réactiver un principal, révoquer des sessions**, sur
   des identités inscrites ; le retrait d'un rôle ou d'un consentement reste un plan, que l'humain
   exécute avec son compte ; en zone `production`, le retrait d'un secret reste aussi un plan
   *(recommandé)*. Raison : tout tient dans `Application.ReadWrite.OwnedBy`, borné à ce qu'IDI1
   inscrit, et aucun droit ne permet de s'en accorder d'autres. Ce que ça change : les deux
   réponses au rôle et au consentement restent manuelles, mais vérifiées.
2. **Les mêmes, plus la désactivation d'un utilisateur de test**, par un User Administrator à la
   portée d'une unité administrative (hypothèse 5). Ce que ça change : un rôle d'administrateur de
   plus, à mesurer, et une licence peut-être.
3. **Les cinq**, rôle et consentement compris. Ce que ça change : l'exécuteur tiendrait
   `RoleManagement.ReadWrite.Directory` et `AppRoleAssignment.ReadWrite.All`, qui permettent de
   s'accorder tout droit : il tiendrait le tenant. Déconseillé.

**Q3. Révoquer les sessions : une permission qui vaut sans doute pour tout le tenant ?**
1. **La donner à l'exécuteur**, le code la bornant aux utilisateurs inscrits et hors de
   `never_target`, avec un débit borné, au banc d'abord *(recommandé)*. Raison : c'est la réponse la
   plus utile contre un jeton volé, et son effet n'est qu'une reconnexion. Ce que ça change : un
   exécuteur compromis peut déconnecter tout le monde, sans rien prendre (hypothèse 4).
2. **La laisser à l'humain** : la révocation reste une étape du plan. Ce que ça change : aucune
   permission large, mais la réponse la plus fréquente reste manuelle.
3. **Attendre la mesure** de l'hypothèse 4 avant de décider. Ce que ça change : IR1c sans ce verbe,
   ajouté plus tard.

**Q4. Le geste d'approbation ?**
1. **Un clic dans la console pour les verbes légers et réversibles** (retirer un certificat ou un
   identifiant fédéré, réactiver, révoquer des sessions) ; **sur le poste de l'opérateur, le nom
   de la cible tapé**, pour les verbes lourds ou irréversibles (retirer un secret, désactiver),
   comme un fil destructif de Dagorlad (DG-b) *(recommandé)*. Raison : une console compromise ne
   fait alors que des gestes légers. Ce que ça change : un terminal pour désactiver.
2. **Tout dans la console**, le nom tapé dans la console pour les verbes lourds. Ce que ça change :
   le plus rapide, mais une console compromise tape aussi le nom.
3. **Tout sur le poste de l'opérateur.** Ce que ça change : le plus sûr, et le plus lent pour un
   geste léger.

**Q5. Le bot ?**
1. **Aucun verbe d'identité** : il montre le plan et le lien vers la console *(recommandé)*.
   Raison : le bot nomme l'humain, il ne le prouve pas (FS1 §3.2). Ce que ça change : un geste de
   plus en pleine urgence.
2. **La révocation des sessions seulement.** Ce que ça change : le geste le plus utile depuis
   Discord, mais un bot compromis déconnecte les utilisateurs inscrits.

**Q6. Quelles identités IDI1 peut-il confier à l'exécuteur (la propriété) ?**
1. **Seulement des identités de test sans privilège** : ni rôle d'annuaire de `PRIVILEGED_ROLES`,
   ni permission de Graph en écriture ; l'inscription refuse les autres, et le dit
   *(recommandé)*. Raison : posséder une application, c'est pouvoir agir comme elle (§4). Ce que
   ça change : une identité de production privilégiée n'a qu'un plan, jamais un verbe de
   l'exécuteur.
2. **Toute identité inscrite**, ses privilèges dits sur la carte. Ce que ça change : la réponse en
   un geste partout, mais l'exécuteur hérite des droits de ce qu'il possède.

---

## 8. Les sources (documentation de Microsoft, lue le 05/11)

- `application: removePassword` — https://learn.microsoft.com/en-us/graph/api/application-removepassword?view=graph-rest-1.0
- `servicePrincipal: removePassword` — https://learn.microsoft.com/en-us/graph/api/serviceprincipal-removepassword?view=graph-rest-1.0
- `application: removeKey` — https://learn.microsoft.com/en-us/graph/api/application-removekey?view=graph-rest-1.0
- `keyCredential` — https://learn.microsoft.com/en-us/graph/api/resources/keycredential?view=graph-rest-1.0
- Delete `federatedIdentityCredential` — https://learn.microsoft.com/en-us/graph/api/federatedidentitycredential-delete?view=graph-rest-1.0
- `user: revokeSignInSessions` — https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0
- Delete `unifiedRoleAssignment` — https://learn.microsoft.com/en-us/graph/api/unifiedroleassignment-delete?view=graph-rest-1.0
- Create `roleEligibilityScheduleRequest` — https://learn.microsoft.com/en-us/graph/api/rbacapplication-post-roleeligibilityschedulerequests?view=graph-rest-1.0
- Delete `oAuth2PermissionGrant` — https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-delete?view=graph-rest-1.0
- Delete `appRoleAssignedTo` — https://learn.microsoft.com/en-us/graph/api/serviceprincipal-delete-approleassignedto?view=graph-rest-1.0
- Update `servicePrincipal` — https://learn.microsoft.com/en-us/graph/api/serviceprincipal-update?view=graph-rest-1.0
- Update `user` — https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0
- Working with users (les actions sensibles, qui peut les faire) — https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0
- Microsoft Graph permissions reference — https://learn.microsoft.com/en-us/graph/permissions-reference
- Configurable token lifetimes — https://learn.microsoft.com/en-us/entra/identity-platform/configurable-token-lifetimes
- Le flux des identifiants du client (non relu ici, d'où l'hypothèse du §2.2) — https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
- Administrative units — https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units
- Restricted management administrative units — https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management
- Assign Microsoft Entra roles (la portée d'une unité administrative) — https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/manage-roles-portal
- Custom security attributes — https://learn.microsoft.com/en-us/entra/fundamentals/custom-security-attributes-overview

---

## Les décisions de Jonathan (05/11)

| Question | Décision |
|---|---|
| Q1, qui exécute | **Un exécuteur d'identité à part**, séparé de la watch et de l'exécuteur de restore, sur le modèle de FS1g. La watch n'écrit jamais sur Entra ID. |
| Q2, les verbes | **Les mêmes, plus les utilisateurs.** Après approbation, sur les identités inscrites, Eregion retire l'identifiant ajouté, désactive puis réactive un principal, révoque les sessions. Il désactive aussi un **utilisateur de test**, par un User Administrator borné à une **unité administrative** du banc (§3.6). Retirer un rôle ou un consentement reste un plan, exécuté par l'humain ; en zone `production`, le retrait d'un secret aussi. |
| Q3, révoquer les sessions | **La permission est donnée**, mais le code la borne aux utilisateurs inscrits, avec un débit limité, et jamais sur un opérateur ni sur un compte de secours. On commence au banc, puis on mesure sa portée réelle (hypothèses 4 et 12). |
| Q4, le geste | **Selon le poids** : un clic dans la console pour un verbe léger et réversible ; le poste de l'opérateur, le nom de la cible tapé, pour un verbe lourd. La désactivation d'un utilisateur est un verbe lourd. |
| Q5, le bot | **Il montre, il n'agit pas** : aucun verbe d'identité. |
| Q6, les identités confiées | **Seulement des identités sans privilège** : l'inscription refuse toute identité qui a un rôle privilégié ou une permission de Graph en écriture. Transmis à IDI1 (#546). |

Ce que ces décisions ajoutent au plan : le lot **IDI1b** (l'unité administrative restreinte du
banc et l'inscription d'un utilisateur de test, §3.6), et dans IR1c la clé de l'opérateur pour les
verbes lourds et le débit des verbes sur un utilisateur.

Les lots, dans l'ordre : IR1a, IR1b, puis IDI1b (après IDI1), IR1c (après FS1a, FS1b, FS1g, IDI1
et IDI1b), IR1d, IR1e (de 13 à 18 jours estimés, hors gestes).
