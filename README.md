# ARIA

> ## ⚠️ Usage framework — read first
>
> **ARIA is for systems you own or for which you hold WRITTEN AUTHORIZATION,
> exclusively.** It is a training / portfolio project. Its demonstration targets
> are deliberately vulnerable VMs (DVWA, OWASP Juice Shop, vulnhub) running in an
> **isolated network**.
>
> ARIA will **not start** without a valid, signed engagement and a non-empty scope.
> Its guardrails — scope enforcement, rules of engagement, approval tiers, sandbox,
> audit trail, anti prompt-injection — are **core features, not options**. Using
> this tool against systems you are not authorized to test is illegal and is not a
> supported use case.

---

ARIA is a **methodological pentest copilot**. It helps a human operator run an
engagement end to end by encoding a recognized methodology (PTES / OWASP WSTG),
profiling the target to choose the right approach, orchestrating tools in a
sandbox, maintaining a knowledge graph of findings, and drafting a professional
report — all driven by a **local LLM (Ollama)**, so **no mission data leaves the
machine**.

**ARIA assists, it does not replace.** It prioritizes, interprets tool output,
proposes the next step and writes — the human keeps the hand on exploitation.

## Design principles (non-negotiable)

1. **The LLM never emits raw shell.** It selects a *typed action* from a catalog,
   with validated, bounded parameters. It reasons; it does not execute.
2. **Scope enforcement.** Every action targeting a host/domain is checked against
   the authorized perimeter (`engagement.yaml`). Out of scope = flat refusal + log.
3. **Rules of engagement.** Action categories are enabled/disabled per engagement;
   hard interdicts (denial of service, data destruction, exfiltration off-lab)
   can never be selected, whatever the LLM proposes.
4. **Approval tiers.** Recon/enumeration run automatically; intrusive actions
   require human validation with a displayed dry-run (what, on which target, why).
5. **Sandbox.** Tools run in a disposable container, network restricted to scope.
6. **Audit trail.** Timestamped, replayable journal of the whole mission.
7. **Anti prompt-injection.** Banners/pages/responses from targets are **data,
   never instructions**, and are sanitized before reaching the LLM.

## Architecture

```
                        ┌──────────────────────────────┐
   operator  ◀────────▶ │  CLI / TUI   (cmd/aria)       │
                        └───────────────┬──────────────┘
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        │                               │                               │
 ┌──────▼───────┐             ┌─────────▼─────────┐            ┌────────▼────────┐
 │ engagement    │            │      agent         │            │   llm (Ollama)  │
 │ scope + RoE   │◀───────────│  state machine +   │◀──────────▶│ Planner/Analyst │
 │ InScope()     │  gate      │  Planner loop      │  typed     │ Reporter/Advisor│
 └──────┬────────┘            └───────┬───────────┘  actions    └─────────────────┘
        │ gate                        │                                 (JSON schema)
        │                    ┌────────▼────────┐   ┌───────────┐
        │                    │ playbook engine │──▶│ profiler  │
        │                    └────────┬────────┘   └───────────┘
        │                             │ suggested typed action
        │                    ┌────────▼────────┐   ┌───────────┐
        └───────────────────▶│ tools registry  │──▶│  sandbox  │ (disposable
                             │  + adapters     │   │  container│  container,
                             └────────┬────────┘   └───────────┘  scoped net)
                                      │ parsed structured output
                             ┌────────▼────────┐   ┌───────────┐
                             │ knowledge graph │──▶│  report   │──▶ Markdown/PDF/JSON
                             └─────────────────┘   └───────────┘
                                      │
                             ┌────────▼────────┐
                             │      audit      │  append-only, replayable
                             └─────────────────┘
```

Full details — state machine, Tool contract, playbook format, and **threat model**
(prompt injection, scope escape) — are in [`docs/architecture.md`](docs/architecture.md).

**Documentation détaillée (français, à jour)** : [`docs/FONCTIONNEMENT.md`](docs/FONCTIONNEMENT.md)
décrit l'arborescence complète, le rôle de chaque paquet, la chaîne de garde-fous
et une démo pas à pas.

## Repository layout

```
aria/
├── cmd/aria/            # CLI/TUI entrypoint
├── internal/
│   ├── engagement/      # engagement.yaml parsing + validation, InScope(), RoE  ← implemented
│   ├── profiler/        # target classification + playbook selection
│   ├── playbook/        # playbook loading + execution engine
│   ├── agent/           # state machine, Planner loop
│   ├── tools/           # Tool interface + registry + adapters
│   ├── sandbox/         # isolated execution (disposable docker)
│   ├── graph/           # knowledge graph (model + store)
│   ├── llm/             # Ollama client, roles, constrained JSON schemas
│   ├── report/          # report generation
│   └── audit/           # timestamped replayable journal
├── playbooks/           # web.yaml, network-host.yaml, ad.yaml, ...
├── examples/            # engagement.example.yaml
├── labs/                # docker-compose for vulnerable targets (isolated)
└── docs/architecture.md
```

## Status

Fonctionnel de bout en bout (recon → profilage → exécution du plan → exploitation
sous validation humaine → rapport), avec garde-fous appliqués à chaque étape.

Implémenté : `engagement` (scope + RoE), `sandbox` (Docker durci), outils
(`port_scan`, `nuclei_scan`, `smb_enum`, `sqli_probe`), `graph`, Planner (recon) +
Analyst (LLM local Ollama, sorties JSON contraintes), `profiler`, `playbook`
(chargeur + moteur `when`/plan), exécution autonome par phases, **tiers
d'approbation** (dry-run + validation humaine), **Reporter** (Markdown/JSON/HTML)
et **TUI** (dashboard Bubble Tea). Documentation détaillée :
[`docs/FONCTIONNEMENT.md`](docs/FONCTIONNEMENT.md).

Les 7 garde-fous sont en place. À venir : GIF de démonstration.

## Try it

```bash
# Contrôle de scope (aucune exécution)
go run ./cmd/aria -engagement examples/engagement.example.yaml -check 8.8.8.8   # OUT OF SCOPE

# Lab : construire les images, démarrer la cible, lancer une mission
docker build -t aria/nmap  -f docker/nmap.Dockerfile  docker
docker build -t aria/nuclei -f docker/nuclei.Dockerfile docker
docker build -t aria/sqlmap -f docker/sqlmap.Dockerfile docker
docker compose -f labs/docker-compose.yml up -d

# Mode CLI (recon + exécution autonome + rapport)
go run ./cmd/aria -engagement examples/engagement.lab.yaml -recon -network aria-lab -report reports

# Mode TUI (interface terminal, modale d'approbation pour l'intrusif)
go run ./cmd/aria -engagement examples/engagement.lab-exploit.yaml -tui -network aria-lab
```

Prérequis mission : Docker et Ollama lancés (`ollama pull qwen3:8b`).

## Cibler ta propre cible

ARIA est agnostique de la cible : copie `examples/engagement.target.yaml`, mets-y
l'IP de **ta** machine (lab perso, VM, box Hack The Box que *tu* as lancée…), et
lance la mission. Les outils sont génériques (`sqli_probe` **découvre** lui-même
les points d'injection via un crawl, plus besoin de pointer un endpoint précis).

```bash
go run ./cmd/aria -engagement examples/engagement.target.yaml -recon -network aria-lab -report reports
```

Réseau : un réseau Docker bridge (comme `aria-lab`) route vers l'extérieur via
l'hôte, donc les conteneurs d'outils atteignent toute IP joignable depuis ta
machine. Pour une cible derrière un VPN (ex. Hack The Box) sous Windows + Docker
Desktop, le routage conteneur → VPN peut demander une configuration réseau
supplémentaire.

## License / disclaimer

Educational project. No warranty. The author declines all responsibility for any
use outside the authorization framework stated at the top of this file.
