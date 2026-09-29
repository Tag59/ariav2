# Labs — isolated vulnerable targets

Docker-compose stacks for the deliberately vulnerable VMs/containers used to
demonstrate ARIA (DVWA, OWASP Juice Shop, …).

**These MUST run on an isolated network** (a dedicated bridge / host-only network),
never exposed to the internet or a production LAN. The example engagement's scope
(`192.168.56.0/24`, `*.lab.local`) is designed for such an isolated lab.

`docker-compose.yml` is added in the sandbox step.
