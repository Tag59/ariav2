# Image contenant nuclei + ses templates, utilisée par l'adapter nuclei_scan.
#
# Construction :  docker build -t aria/nuclei -f docker/nuclei.Dockerfile docker
#
# Le binaire et les templates sont récupérés AU BUILD (Internet disponible) et
# embarqués dans l'image. Au runtime, le conteneur tourne sur un réseau isolé sans
# accès Internet : nuclei charge les templates embarqués via -t /nuclei-templates,
# et on désactive la vérification de mise à jour et l'interaction OOB (interactsh).
FROM alpine:3.20

RUN apk add --no-cache ca-certificates wget unzip git

# Récupère la dernière version publiée de nuclei et installe le binaire.
RUN set -eux; \
    VER="$(wget -qO- https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep -oE '"tag_name": *"v[0-9.]+"' | grep -oE 'v[0-9.]+' | head -1)"; \
    NUM="${VER#v}"; \
    wget -qO /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/${VER}/nuclei_${NUM}_linux_amd64.zip"; \
    unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    chmod +x /usr/local/bin/nuclei; \
    rm /tmp/nuclei.zip

# Embarque les templates (clonés au build) dans un dossier fixe, lisible par tous.
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates /nuclei-templates

# Utilisateur non privilégié.
RUN adduser -D -u 1000 scanner
USER scanner
WORKDIR /work
