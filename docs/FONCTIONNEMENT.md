# ARIA — Fonctionnement détaillé

> Document de référence à jour, en français. Il décrit l'arborescence complète, le
> rôle de chaque paquet, le cycle de vie d'une mission et surtout la **chaîne de
> garde-fous** qui encadre chaque action. Le document `architecture.md` (en
> anglais) est la note de conception initiale ; ce fichier-ci reflète le code réel.

---

## 0. Cadre d'usage (rappel)

ARIA ne s'utilise **que** sur des systèmes que l'on possède ou pour lesquels on
dispose d'une **autorisation écrite**. Les cibles de démonstration sont des VMs/
conteneurs volontairement vulnérables (OWASP Juice Shop, DVWA…) sur un **réseau
isolé**. ARIA refuse de démarrer sans un engagement valide et signé.

---

## 1. Vue d'ensemble

ARIA est un **copilote de pentest méthodologique**. Il assiste un opérateur humain
sur une mission : il choisit la prochaine action, interprète les sorties, accumule
les découvertes et (à terme) rédige le rapport. **L'humain garde la main** ;
l'exploitation reste sous validation humaine.

Deux idées structurent tout le projet :

1. **Le LLM raisonne, il n'exécute pas.** Il ne produit jamais de commande shell :
   il choisit une **action typée** dans un catalogue et fournit des **paramètres
   validés et bornés**. Sa sortie est un JSON contraint par un schéma.
2. **Les garde-fous sont le cœur du projet**, pas une option. Ils sont appliqués
   en Go, en aval du LLM, et échouent « fermé » (*fail-closed*) : au moindre doute,
   on refuse.

Le LLM est **local** (Ollama) : aucune donnée de mission ne quitte la machine.

---

## 2. Les garde-fous

| # | Garde-fou | Où c'est appliqué dans le code |
|---|-----------|-------------------------------|
| 1 | Le LLM choisit une action typée, jamais du shell | `internal/llm` (sortie JSON contrainte) + `internal/tools` (catalogue) |
| 2 | **Scope** : toute cible vérifiée contre le périmètre | `engagement.InScope` + `tools.EnforceScope` |
| 3 | **RoE** : catégories activables ; interdits durs impossibles | `engagement.RoE` + `hardProhibited` |
| 4 | **Tiers d'approbation** : recon auto, intrusif validé par l'humain (dry-run) | `agent.Approver` + `Executor` (gating) + `Tool.RequiresApproval` / playbook `requires_approval` |
| 5 | **Sandbox** : conteneur jetable, réseau limité | `internal/sandbox` (DockerRunner durci) |
| 6 | **Audit** : journal horodaté rejouable | `internal/audit` (JSONL append-only, branché CLI + TUI) |
| 7 | **Anti-injection** : sorties cibles = données, pas instructions | parsing dans les adapters + prompts de rôle |

Deux invariants globaux :
- **Pas d'engagement valide ⇒ ARIA ne démarre pas.**
- **Fail-closed** : une cible non prouvée dans le scope, ou une sortie LLM non
  conforme au schéma, est **refusée**, jamais devinée.

---

## 3. Arborescence complète

```
aria/
├── go.mod                      # module github.com/Tag59/aria (Go 1.25)
├── go.sum
├── .gitignore                  # ignore binaires, artefacts de mission, etc.
├── README.md                   # disclaimer + principes + schéma + statut
│
├── cmd/
│   ├── aria/main.go            # CLI/TUI : -check, -recon, -tui, -report
│   └── ariabench/main.go       # banc d'évaluation multi-modèles
│
├── internal/                   # code privé de l'application
│   ├── engagement/             # ✅ périmètre + RoE + validation (cœur des garde-fous)
│   │   ├── types.go            #   types (Engagement, Authorization, RoE, Category)
│   │   ├── scope.go            #   Scope compilé + InScope + matchers + normalisation
│   │   ├── load.go             #   Load / ParseAndValidate / Validate
│   │   ├── scope_test.go
│   │   └── load_test.go
│   │
│   ├── sandbox/                # ✅ exécution isolée jetable
│   │   ├── sandbox.go          #   interface Runner + Spec + Result + NetworkPolicy
│   │   ├── docker.go           #   DockerRunner durci (buildArgs, Run, Available)
│   │   ├── docker_test.go
│   │   └── integration_test.go #   test avec Docker réel (skippe sinon)
│   │
│   ├── tools/                  # ✅ catalogue d'actions typées
│   │   ├── tools.go            #   interface Tool + Registry + Invocation + EnforceScope
│   │   ├── portscan.go         #   adapter port_scan (nmap) : Prepare / Parse / schémas
│   │   ├── nuclei.go           #   adapter nuclei_scan (vuln web) : Parse JSONL
│   │   ├── smbenum.go          #   adapter smb_enum (nmap NSE)
│   │   ├── sqli.go             #   adapter sqli_probe (sqlmap, exploitation GATED)
│   │   ├── tools_test.go
│   │   ├── portscan_test.go
│   │   ├── nuclei_test.go
│   │   └── smbenum_test.go
│   │
│   ├── graph/                  # ✅ knowledge graph
│   │   ├── graph.go            #   doc de paquet
│   │   ├── model.go            #   types Host, Service, Finding
│   │   ├── store.go            #   Store (Merge, MergeFindings, dédoublonnage, Summary)
│   │   └── store_test.go
│   │
│   ├── llm/                    # ✅ client Ollama + sortie contrainte
│   │   ├── llm.go              #   doc de paquet
│   │   ├── client.go           #   Client + OllamaClient + Prompt + DecodeStrict
│   │   └── integration_test.go #   test avec Ollama réel (skippe sinon)
│   │
│   ├── agent/                  # ✅ machine à états + rôles LLM
│   │   ├── agent.go            #   doc de paquet
│   │   ├── planner.go          #   Planner : Next (action) + Params (paramètres)
│   │   ├── recon.go            #   RunRecon : la boucle de reconnaissance
│   │   ├── analyst.go          #   Analyst : services -> findings candidats
│   │   ├── executor.go         #   Executor : exécution autonome du plan par phases
│   │   ├── approval.go         #   Approver + DryRun : tiers d'approbation (n°4)
│   │   ├── planner_test.go
│   │   ├── analyst_test.go
│   │   └── executor_test.go
│   │
│   ├── profiler/               # ✅ classification de cible + choix de playbook
│   │   ├── profiler.go
│   │   └── profiler_test.go
│   ├── playbook/               # ✅ chargement + validation + moteur (when/plan)
│   │   ├── playbook.go
│   │   ├── condition.go        #   EvalWhen : évaluation des conditions `when`
│   │   ├── engine.go           #   Engine.PlanForHost : plan applicable (when+RoE)
│   │   └── *_test.go
│   ├── report/                 # ✅ rapport Markdown / JSON / HTML
│   │   ├── report.go           #   Model + BuildModel (tri/compte des findings)
│   │   ├── render.go           #   rendus Markdown et JSON
│   │   ├── html.go             #   rendu HTML (html/template, échappé)
│   │   ├── files.go            #   WriteAll (md/json/html)
│   │   └── report_test.go
│   ├── tui/                    # ✅ interface terminal (Bubble Tea)
│   │   ├── tui.go              #   modèle, messages, goroutine de mission
│   │   ├── view.go             #   rendu Lipgloss + modale d'approbation
│   │   ├── approver.go         #   approbateur relié à la modale
│   │   └── tui_test.go
│   ├── eval/                   # ✅ banc d'évaluation multi-modèles
│   │   ├── eval.go             #   scénarios Planner/Analyst + métriques
│   │   ├── render.go           #   tableaux console / Markdown
│   │   └── eval_test.go
│   └── audit/                  # ✅ journal de mission horodaté (JSONL rejouable)
│       ├── audit.go            #   Journal, événements, WrapApprover, Render, Load
│       └── audit_test.go
│
├── playbooks/
│   ├── web.yaml                # playbook web déclaratif (WSTG/PTES)
│   └── network-host.yaml       # playbook hôte réseau (Linux/Windows/générique)
│
├── examples/
│   ├── engagement.example.yaml # exemple générique
│   ├── engagement.lab.yaml     # engagement prêt à l'emploi pour le lab local
│   └── engagement.lab-exploit.yaml # idem, avec exploitation activée (démo approbation)
│
├── labs/
│   ├── docker-compose.yml      # Juice Shop sur réseau isolé aria-lab (IP fixe)
│   └── README.md
│
├── docker/
│   ├── nmap.Dockerfile         # image aria/nmap (Alpine + nmap, non-root)
│   ├── nuclei.Dockerfile       # image aria/nuclei (nuclei + templates embarqués)
│   └── sqlmap.Dockerfile       # image aria/sqlmap (sqlmap, détection seule)
│
└── docs/
    ├── architecture.md         # note de conception initiale (EN)
    └── FONCTIONNEMENT.md       # ce document (FR, à jour)
```

Légende : ✅ implémenté · ⏳ placeholder (à venir).

---

## 4. Machine à états (cycle de vie)

```
recon → profiling (choix playbook) → énumération → identification-vulns
      → [exploitation gated] → post-exploitation (lab) → reporting
```

Aujourd'hui la boucle **recon** est implémentée (`RunRecon`) et l'**identification
de vulnérabilités** l'est via l'**Analyst**. Les autres phases sont en placeholder.

Le Planner peut **boucler** dans une phase (par ex. scanner, puis rescanner un
nouvel hôte) avant d'avancer. Un compteur `maxSteps` empêche toute boucle infinie.

---

## 5. Le flux d'une action (la chaîne de garde-fous)

C'est le point le plus important à comprendre (et à présenter en soutenance).
Voici ce qui se passe pour **une** action de reconnaissance :

```
1. Planner.Next
   → le LLM choisit une ACTION parmi les outils recon autorisés (enum) + "stop"
   → sortie JSON contrainte, décodée en mode STRICT (clé inconnue = rejet)
   → on revérifie que l'action est bien dans la liste autorisée

2. Planner.Params
   → 2e appel LLM : les PARAMÈTRES, contraints par le schéma de l'outil choisi
     (ex. port_scan impose 'target', borne 'ports' et 'timing' à des enums)

3. Tool.Prepare(params)
   → valide et BORNE les paramètres (refus si target manquante, CIDR, preset
     inconnu…) et construit l'Invocation {Targets, Spec sandboxée}

4. tools.EnforceScope(engagement, invocation)
   → chaque cible passe par engagement.InScope
   → une seule cible hors périmètre ⇒ STOP NET (l'action n'est pas exécutée)

5. (tiers d'approbation)
   → recon = automatique. Les actions intrusives exigeront une validation
     humaine avec dry-run (étape à venir).

6. sandbox.Runner.Run(spec)
   → exécution dans un conteneur DURCI et JETABLE, réseau limité au lab

7. Tool.Parse(result)
   → la sortie BRUTE (XML nmap) est transformée en objets structurés
     (Host, Service) — jamais renvoyée telle quelle au LLM

8. graph.Store.Merge(hosts)
   → accumulation SANS DOUBLON dans le knowledge graph
```

Le LLM n'intervient qu'aux étapes 1 et 2, et il ne fait que **proposer**. Tout le
reste (validation, scope, exécution isolée, parsing) est du code Go déterministe.
Même une injection réussie dans une bannière ne peut, au pire, que faire *proposer*
une action — qui échouera ensuite aux étapes 3-4.

---

## 6. Détail par paquet

### 6.1 `engagement` — périmètre & règles

- **`Engagement`** : la mission parsée et validée. Non utilisable tant que non
  validée (le scope compilé `compiled` est nil ⇒ `InScope` échoue fermé).
- **`InScope(target)`** : le contrôle central. Normalise la cible (retire schéma,
  userinfo, port, chemin), puis applique la règle :
  1. correspond à une entrée **OUT** ⇒ hors scope (les exclusions gagnent) ;
  2. sinon correspond à une entrée **IN** ⇒ dans le scope ;
  3. sinon ⇒ hors scope.
  Types d'entrées gérés : IP (v4/v6), **CIDR**, nom d'hôte exact, **wildcard**
  `*.domaine` (sous-domaines uniquement, pas l'apex).
- **`Validate()`** : refuse un scope vide, une autorisation absente/non signée, une
  fenêtre de dates incohérente, une catégorie RoE inconnue ou **interdite dure**.
  Le YAML est lu en mode strict (`KnownFields(true)`) : une clé mal tapée est une
  erreur, pas un oubli silencieux.
- **`Category`** + **`RoE.Allows`** : les catégories activables (recon, enumeration,
  vuln_scan, exploitation, post_exploit) ; les interdits durs
  (denial_of_service, data_destruction, exfiltration) ne sont **pas sélectionnables**
  et renvoient toujours `false`.

### 6.2 `sandbox` — exécution isolée

- **`Runner`** (interface) : `Available` + `Run`. Le runtime est abstrait pour
  pouvoir remplacer Docker par gVisor/Podman plus tard sans toucher aux adapters.
- **`Spec`** : image, `Argv` (vecteur d'arguments, **pas** de chaîne shell), env,
  montage de travail, politique réseau, capabilities, timeout.
- **`DockerRunner`** : à chaque exécution, un `docker run` **durci** :
  `--rm` (jetable), `--cap-drop=ALL`, `--security-opt no-new-privileges`, rootfs
  `--read-only` + `/tmp` en tmpfs `noexec,nosuid`, limites mémoire/CPU/pids,
  utilisateur non-root optionnel. **Jamais** `--privileged` ni `--network host`.
- **Réseau** : `NetNone` par défaut (sûr) ; `NetIsolated` attache à un réseau isolé
  nommé (les noms `host`/`bridge` sont refusés). L'ajout de capabilities est
  restreint à une **liste blanche** (`NET_RAW`, `NET_BIND_SERVICE`).
- Un code de sortie non nul du conteneur est **un résultat** (`Result.ExitCode`),
  pas une erreur Go ; les dépassements de délai sont bornés et signalés.

### 6.3 `tools` — catalogue d'actions typées

- **`Tool`** (interface) : `Name`, `Description`, `ParamsSchema`, `Category`,
  `RequiresApproval`, `Prepare`, `Parse`.
- **`Invocation`** : le résultat de `Prepare` — les `Targets` (pour le scope) et le
  `Spec` sandboxé à exécuter.
- **`Registry`** : enregistrement sans doublon, `Get`, `List` (trié).
- **`EnforceScope`** : vérifie chaque cible d'une invocation via `InScope`.
- **`port_scan`** (adapter nmap) :
  - `Prepare` : `target` obligatoire (refus des **CIDR** — le scope se vérifie
    cible par cible), `ports` (preset borné), `timing` (T2–T4), `service_detection`.
    Construit la commande `nmap -sT -Pn -T… [ports] [-sV] -oX - target`.
    - `-sT` : scan TCP connect (pas besoin de privilège) ;
    - `-Pn` : pas de ping préalable (les VMs de lab bloquent souvent l'ICMP) ;
    - `-oX -` : sortie XML sur stdout, pour un parsing fiable.
  - `Parse` : lit le XML nmap, ne garde que les hôtes *up* et les ports *open*,
    et renvoie des `graph.Host`/`graph.Service`.
- **`nuclei_scan`** (adapter nuclei, `vuln_scan`) : scanne un service HTTP avec des
  templates non destructifs. Image `aria/nuclei` (templates embarqués au build) ;
  au runtime, aucun accès Internet (`-t /nuclei-templates`, `-duc`, `-ni`,
  `HOME=/tmp`). `Parse` lit le JSONL et produit des `graph.Finding`.
- **`smb_enum`** (adapter nmap NSE, `enumeration`) : énumère SMB (partages, OS,
  mode de sécurité) ; convertit la sortie des scripts en findings informationnels.
- **`sqli_probe`** (adapter sqlmap, `exploitation`, `RequiresApproval=true`) :
  confirme une injection SQL en **détection seule** (`--batch`, pas de `--dump`).
  Ne s'exécute jamais sans validation humaine (voir §6.6, tiers d'approbation).

### 6.4 `graph` — knowledge graph

- **Modèle** : `Host` (adresse, noms d'hôte, services), `Service` (port, protocole,
  état, nom, produit, version), `Finding` (vulnérabilité **candidate** : titre,
  sévérité, hôte, port, description, preuve, impact, remédiation, références).
- **`Store`** : accumule **sans doublon**. `Merge` fusionne par adresse d'hôte
  (services fusionnés par port/protocole, la dernière info non vide gagne ; noms
  d'hôte en union). `MergeFindings` dédoublonne par hôte|port|titre. Les accesseurs
  renvoient des **copies** (l'appelant ne peut pas corrompre l'état interne). Sûr
  en concurrence (`RWMutex`).

### 6.5 `llm` — client Ollama & sortie contrainte

- **`Client`** (interface) : `Generate(ctx, Prompt) []byte`. Permet de tester sans
  Ollama (faux client).
- **`OllamaClient`** : appelle `/api/chat` en `stream=false`, **température 0**
  (décisions reproductibles), et transmet un **schéma JSON** via le champ `format`
  d'Ollama pour contraindre la sortie. URL via `OLLAMA_HOST` (défaut localhost).
- **`DecodeStrict`** : désérialise en **refusant les champs inconnus** — c'est le
  garde-fou appliqué aux sorties : une réponse non conforme est rejetée.

### 6.6 `agent` — machine à états & rôles LLM

- **`Planner`** (rôle « quoi faire ensuite »), en **deux temps** :
  - `Next` : le LLM choisit une **action** parmi les outils recon autorisés (enum)
    ou `stop` ; décodage strict + revalidation ;
  - `Params` : 2e appel, les **paramètres** contraints par le `ParamsSchema` de
    l'outil choisi (les valeurs restent validées par `Prepare`).
- **`RunRecon`** : la boucle décrite en §5, jusqu'à `stop` ou `maxSteps`. Renvoie la
  liste des `Step` exécutés (utile pour l'affichage et, plus tard, l'audit).
- **`Analyst`** (rôle « interprétation ») : à partir des services d'un hôte, propose
  des **findings candidats** (schéma JSON contraint, sévérité revalidée contre une
  échelle qualitative). Les données analysées viennent de la cible : le prompt les
  traite comme des **données, pas des instructions**. `AnalyzeStore` parcourt tous
  les hôtes et réinjecte les findings.
- **`Executor`** (exécution autonome) : `ExecutePlaybook` enchaîne, contre un hôte,
  les steps du plan (`Engine.PlanForHost`) dont l'outil est disponible, puis ingère
  hôtes/findings dans le graph. La cible est toujours l'hôte courant (jamais choisie
  par le LLM) ; `EnforceScope` est appliqué avant chaque exécution.
- **`Approver` + `DryRun`** (tiers d'approbation, garde-fou n°4) : une action
  intrusive (`requires_approval`, ou catégorie exploitation/post_exploit) est
  présentée à l'opérateur sous forme de **dry-run** (action, cible, commande exacte,
  justification) — après le contrôle de scope — et n'est exécutée qu'après
  validation. Refus ⇒ step « refusé », rien ne s'exécute. Sans approbateur
  (`AutoDeny`), tout l'intrusif est refusé (fail-closed).

### 6.7 `profiler` — classification de cible

- **`Classify(host)`** : déduit le **type** de la cible (web-app, ad, windows-host,
  linux-host, network-host, unknown) à partir de ses services, de façon
  **déterministe** (règles sur ports/services — pas de LLM, donc fiable, explicable
  et sans surface d'injection), et recommande le **playbook** adapté. Priorité :
  AD > web-app > windows > linux > network-host. Chaque `Profile` porte ses raisons.
- **`ClassifyStore(store)`** : classe tous les hôtes du graph.

### 6.8 `playbook` — chargement + moteur

- **`Load` / `ParseAndValidate`** : transforment un playbook YAML en structures
  (`Playbook` / `Phase` / `Step`) **validées** : nom et `target_type` obligatoires,
  au moins une phase, chaque step a une `action`, et les catégories (`category`,
  `gated_by_roe`) sont des catégories connues, **jamais un interdit dur**. YAML lu
  en mode strict.
- **`EvalWhen`** : évalue les conditions `when` des steps contre des faits
  (langage minuscule évalué par le moteur, jamais le LLM ; condition inconnue =
  false, fail-closed).
- **`Engine.PlanForHost`** : calcule, phase par phase, les steps **applicables** à
  un hôte — condition `when` satisfaite **et** catégorie autorisée par les RoE.
  `FactsForHost` dérive les faits (`service.http/https/smb/ssh/snmp`,
  `target.is_hostname`) des services découverts. C'est le « cadre » dans lequel le
  Planner raisonnera. L'exécution autonome pilotée par les phases (faire enchaîner
  au Planner les steps applicables) viendra avec les adapters d'énumération/vuln.

### 6.9 `report` — génération du rapport

- **`BuildModel`** : assemble le modèle (engagement, hôtes/services, findings triés
  par sévérité, décompte par sévérité, journal des actions).
- **`Markdown` / `JSON` / `HTML`** : trois rendus. Le HTML est une page autonome
  (badges de sévérité) rendue via `html/template` — tout contenu issu de la cible
  (preuve, description) est **échappé**, donc une preuve piégée ne peut pas injecter
  de code dans le rapport. **`WriteAll`** écrit les trois fichiers dans un dossier.
- PDF : imprimer le HTML depuis un navigateur (Ctrl/Cmd+P → PDF).

### 6.10 `tui` — interface terminal

- Dashboard Bubble Tea qui déroule la mission **en direct** : phases, hôtes/
  services, findings colorés par sévérité, journal.
- La mission tourne dans une goroutine qui communique avec l'interface uniquement
  par messages ; l'`agent` l'alimente via les hooks `Planner.OnStep` /
  `Executor.OnStep`.
- **Modale d'approbation** : quand l'Executor rencontre une action intrusive,
  l'`approver` TUI affiche un dry-run plein écran et bloque la goroutine jusqu'à la
  décision (y/n) de l'opérateur — le garde-fou n°4, en version graphique.
- Lancement : `-tui` (voir §6.11).

### 6.11 `cmd/aria` — la CLI

- Sans option : valide l'engagement et affiche son résumé (garde-fou n°1).
- `-check <cible>` : indique si une cible est dans le périmètre.
- `-recon` : recon + profilage + exécution autonome du plan + analyse, puis affiche
  hôtes/services, profils et findings. `-report <dir>` écrit le rapport.
- `-tui` : même mission dans l'interface terminal.
  Options : `-model`, `-network`, `-image`, `-nuclei-image`, `-sqlmap-image`,
  `-max-steps`, `-playbooks`, `-report`.

### 6.12 `eval` / `ariabench` — banc d'évaluation

- **`eval.Run`** rejoue deux scénarios (Planner sur graph vide ; Analyst sur un
  service web connu) contre chaque modèle, N fois, et agrège des métriques
  **objectives** : décision valide, action attendue, paramètres acceptés par
  `Prepare`, analyse valide, findings produits, latence par rôle. Le client LLM est
  injectable (fake en test).
- **`cmd/ariabench`** : `ariabench -models qwen3:8b,llama3.1 -runs 5 -out bench.md`.
  N'exécute aucun outil (il n'évalue que les décisions du LLM) ; il faut juste
  Ollama lancé avec les modèles récupérés.

### 6.13 `audit` — journal de mission (garde-fou n°6)

- **`Journal`** consigne des événements datés et ordonnés (début de mission,
  phase, step, demande/décision d'approbation, finding, erreur, fin), thread-safe.
  Écriture **JSONL append-only** au fil de l'eau → relisable et vérifiable
  (`Load` relit, `Render` produit une chronologie lisible).
- **`WrapApprover`** enveloppe l'approbateur pour tracer chaque validation
  (qui a approuvé/refusé quoi, et quand).
- La CLI et la TUI alimentent le journal (via `OnStep` et le wrapper) et l'écrivent
  dans `<report>/audit.jsonl` (ou `-audit <fichier>`).

---

## 7. Modèle de menace (résumé)

Tout ce qui revient d'une cible (bannières, corps HTTP, sortie d'outil) est une
**donnée non fiable**, jamais une instruction.

- **Injection de prompt** via la cible : le LLM ne peut qu'exécuter une action
  *typée*, et sa proposition passe ensuite par scope + RoE + (approbation). Les
  adapters **parsent** la sortie ; le LLM ne reçoit pas le texte brut comme consigne.
- **Sortie de scope** : `InScope` est le point de contrôle unique ; le sandbox
  n'a de réseau que vers le lab (défense en profondeur). Les cibles CIDR sont
  refusées côté `port_scan` pour ne pas déborder.
- **Actions destructrices** : DoS / destruction / exfiltration sont des interdits
  durs — impossibles à activer, aucun adapter ne les implémente.
- **Évasion du conteneur** : conteneur jetable, non privilégié, capabilities
  minimales, rootfs en lecture seule.
- **Fuite de données** : LLM local (Ollama), pas d'appel tiers.

Détails complets : voir `architecture.md` (§ threat model).

---

## 8. Démo pas à pas

Prérequis : Docker lancé, Ollama lancé, modèle récupéré (`ollama pull qwen3:8b`),
images nmap et nuclei construites.

```bash
# 1. Construire les images (une fois)
docker build -t aria/nmap -f docker/nmap.Dockerfile docker
docker build -t aria/nuclei -f docker/nuclei.Dockerfile docker
docker build -t aria/sqlmap -f docker/sqlmap.Dockerfile docker

# 2. Démarrer le lab (OWASP Juice Shop sur le réseau isolé aria-lab)
docker compose -f labs/docker-compose.yml up -d

# 3. Lancer recon + profilage + exécution autonome, et écrire le rapport
go run ./cmd/aria -engagement examples/engagement.lab.yaml -recon -network aria-lab -report reports
# -> reports/report.md, reports/report.json, reports/report.html (ouvrir le HTML, imprimer en PDF)

# 3ter. Mode interface terminal (TUI) : mission en direct + modale d'approbation
go run ./cmd/aria -engagement examples/engagement.lab-exploit.yaml -tui -network aria-lab -report reports

# 3bis. Avec exploitation activée : chaque action intrusive demande une validation
#       (dry-run affiché ; répondre y pour l'exécuter, N/entrée non interactive = refus)
go run ./cmd/aria -engagement examples/engagement.lab-exploit.yaml -recon -network aria-lab

# 4. Vérifier un contrôle de scope (sans rien exécuter)
go run ./cmd/aria -engagement examples/engagement.lab.yaml -check 8.8.8.8   # HORS SCOPE

# 5. Arrêter le lab
docker compose -f labs/docker-compose.yml down
```

Résultat attendu : le Planner scanne `172.28.0.10`, le graph se remplit (port 3000),
et l'Analyst propose des vulnérabilités candidates.

---

## 9. Tests

```bash
go test ./...            # toute la suite (les tests d'intégration s'exécutent si
                         # Ollama/Docker sont disponibles, sinon ils sont skippés)
go test -short ./...     # unitaires seulement (aucune dépendance externe)
go test -race ./internal/graph/   # vérifie l'absence de course de données
```

- **Unitaires** : engagement (scope, validation), sandbox (construction des
  arguments durcis, rejets), tools (commande nmap, parsing XML, registre,
  EnforceScope), graph (dédoublonnage), agent (Planner/Analyst avec faux LLM et
  faux sandbox).
- **Intégration** : `llm` envoie un vrai prompt contraint à Ollama ; `sandbox`
  lance un vrai conteneur. Les deux **skippent** proprement si le service est absent.

---

## 10. État d'avancement & suite

**Fait** : engagement · sandbox · tools (port_scan, nuclei_scan, smb_enum,
sqli_probe) · graph · Planner (recon) · Analyst · profiler · playbooks (moteur
`when`/plan) · exécution autonome par phases (Executor) · tiers d'approbation
(Approver + dry-run) et 1re exploitation gated (sqli_probe) · Reporter
(Markdown/JSON/HTML) · **TUI (dashboard Bubble Tea + modale d'approbation)** ·
CLI recon · banc d'évaluation multi-modèles (ariabench) · **journal d'audit
(JSONL rejouable)** · lab. Démo bout-en-bout fonctionnelle (recon → profil → plan
→ nuclei → exploitation sous validation humaine → rapport + journal d'audit).

**Les 7 garde-fous sont en place.** Suite envisagée : GIF de démonstration
(capture TUI) ; `sqli_probe` générique (ne plus cibler Juice Shop en dur) ;
génération PDF dédiée (le HTML s'imprime en PDF pour l'instant).

**Raffinements connus** : filtrage egress par IP exacte côté hôte (chaîne
`DOCKER-USER`) ; balayage de sous-réseau vérifié bloc par bloc ; dédoublonnage des
findings entre sources (nuclei vs Analyst peuvent produire des intitulés proches).
