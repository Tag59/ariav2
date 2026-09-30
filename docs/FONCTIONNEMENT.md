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
| 4 | **Tiers d'approbation** : recon auto, intrusif validé par l'humain | `Tool.RequiresApproval` + playbook `requires_approval` (câblage à venir) |
| 5 | **Sandbox** : conteneur jetable, réseau limité | `internal/sandbox` (DockerRunner durci) |
| 6 | **Audit** : journal horodaté rejouable | `internal/audit` (à implémenter avec la boucle) |
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
├── cmd/aria/
│   └── main.go                 # CLI : valide l'engagement, -check <cible>, -recon
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
│   │   ├── tools_test.go
│   │   └── portscan_test.go
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
│   │   ├── planner_test.go
│   │   └── analyst_test.go
│   │
│   ├── profiler/               # ⏳ classification de cible (placeholder)
│   ├── playbook/               # ⏳ moteur de playbooks (placeholder)
│   ├── report/                 # ⏳ génération de rapport (placeholder)
│   └── audit/                  # ⏳ journal d'audit (placeholder)
│
├── playbooks/
│   └── web.yaml                # playbook web déclaratif (WSTG/PTES)
│
├── examples/
│   ├── engagement.example.yaml # exemple générique
│   └── engagement.lab.yaml     # engagement prêt à l'emploi pour le lab local
│
├── labs/
│   ├── docker-compose.yml      # Juice Shop sur réseau isolé aria-lab (IP fixe)
│   └── README.md
│
├── docker/
│   └── nmap.Dockerfile         # image aria/nmap (Alpine + nmap, non-root)
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

### 6.7 `cmd/aria` — la CLI

- Sans option : valide l'engagement et affiche son résumé (garde-fou n°1).
- `-check <cible>` : indique si une cible est dans le périmètre.
- `-recon` : assemble `OllamaClient` + `DockerRunner` + registre `port_scan` +
  `Planner.RunRecon` + `Analyst.AnalyzeStore`, puis affiche hôtes/services/findings.
  Options : `-model`, `-network`, `-image`, `-max-steps`.

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
image nmap construite.

```bash
# 1. Construire l'image nmap (une fois)
docker build -t aria/nmap docker

# 2. Démarrer le lab (OWASP Juice Shop sur le réseau isolé aria-lab)
docker compose -f labs/docker-compose.yml up -d

# 3. Lancer une reconnaissance assistée par le LLM contre la cible
go run ./cmd/aria -engagement examples/engagement.lab.yaml -recon -network aria-lab

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

**Fait** : engagement · sandbox · tools/port_scan · graph · Planner (recon) ·
Analyst · CLI recon · lab. Démo bout-en-bout fonctionnelle.

**Suite prévue** : profiler + 2e playbook → tiers d'approbation + exploitation en
lab → Reporter (rapport Markdown/PDF) → banc d'évaluation multi-modèles →
polish/TUI. Le **journal d'audit** (`internal/audit`) sera branché sur la boucle de
l'agent.

**Raffinements connus** : filtrage egress par IP exacte côté hôte (chaîne
`DOCKER-USER`) ; balayage de sous-réseau vérifié bloc par bloc ; port des findings
parfois non renseigné par le LLM (à fiabiliser via le schéma).
