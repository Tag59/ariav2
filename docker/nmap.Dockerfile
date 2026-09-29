# Image minimale contenant nmap, utilisée par l'adapter port_scan.
#
# Construction :  docker build -t aria/nmap -f docker/nmap.Dockerfile docker
# (ou depuis la racine :  docker build -t aria/nmap docker )
#
# On part d'Alpine (léger) et on installe nmap. Pas d'ENTRYPOINT particulier :
# le bac à sable passe explicitement l'argv ["nmap", ...], ce qui rend la
# commande exécutée lisible et sans surprise.
FROM alpine:3.20

RUN apk add --no-cache nmap nmap-scripts

# Utilisateur non privilégié : le scan TCP connect (-sT) n'a pas besoin de root.
RUN adduser -D -u 1000 scanner
USER scanner

WORKDIR /work
