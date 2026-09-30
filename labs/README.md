# Labs — cibles vulnérables isolées

Stack Docker de démonstration pour ARIA : une cible volontairement vulnérable
(OWASP Juice Shop) sur un **réseau Docker isolé** dédié (`aria-lab`, 172.28.0.0/24),
avec une IP fixe (172.28.0.10) pour que le périmètre de l'engagement soit prévisible.

**À n'utiliser que sur ce réseau isolé**, jamais exposé à Internet ni à un LAN de
production.

## Démarrer / arrêter le lab

```bash
docker compose -f labs/docker-compose.yml up -d      # démarre Juice Shop
docker compose -f labs/docker-compose.yml down       # arrête et nettoie
```

La cible est visible sur http://127.0.0.1:3000 pendant la démo.

## Lancer une reconnaissance ARIA contre le lab

Prérequis : Docker lancé, image nmap construite (`docker build -t aria/nmap docker`),
Ollama lancé avec le modèle voulu (`ollama pull qwen3:8b`).

```bash
go run ./cmd/aria -engagement examples/engagement.lab.yaml -recon -network aria-lab
```

Le conteneur nmap est attaché au réseau `aria-lab` : il peut joindre la cible, et
rien d'autre. Toute cible hors du périmètre défini dans l'engagement est refusée.
