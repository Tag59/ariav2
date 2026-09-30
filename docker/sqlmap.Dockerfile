# Image contenant sqlmap, utilisée par l'adapter sqli_probe (exploitation GATED).
#
# Construction :  docker build -t aria/sqlmap -f docker/sqlmap.Dockerfile docker
#
# sqlmap est utilisé en DÉTECTION uniquement (--batch, pas de --dump ni d'accès
# système) : on confirme l'existence d'une injection, on n'exfiltre rien.
FROM python:3.12-alpine

RUN apk add --no-cache git

# sqlmap se distribue via son dépôt Git. On l'expose derrière un petit wrapper
# « sqlmap » pour que le bac à sable puisse l'appeler comme n'importe quel outil.
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap /opt/sqlmap
RUN printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap

RUN adduser -D -u 1000 scanner
USER scanner
WORKDIR /work
