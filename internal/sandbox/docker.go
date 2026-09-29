package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DefaultTimeout borne toute exécution dont le Spec n'en fixe pas.
const DefaultTimeout = 5 * time.Minute

// allowedCaps est la liste blanche des capabilities Linux qu'un adapter peut
// ajouter par-dessus un --cap-drop=ALL complet. Tout ce qui n'y figure pas est
// refusé : l'intérêt du bac à sable est qu'aucune exécution ne s'octroie
// discrètement des pouvoirs dangereux.
var allowedCaps = map[string]bool{
	"NET_RAW":          true, // sockets bruts, ex. nmap -sS
	"NET_BIND_SERVICE": true, // écouter sur des ports < 1024 (rarement utile)
}

// DockerConfig configure un DockerRunner durci.
type DockerConfig struct {
	// Binary est le CLI conteneur à invoquer. "docker" par défaut ; "podman"
	// fonctionne aussi (compatible pour les options utilisées ici).
	Binary string
	// DefaultNetwork s'applique aux exécutions dont le Spec laisse Network.Mode
	// vide. Par défaut NetNone (aucun réseau) — choix sûr.
	DefaultNetwork NetworkPolicy
	// SeccompProfile est un chemin vers un profil seccomp JSON. Vide = profil
	// Docker par défaut (déjà restrictif). "unconfined" est refusé.
	SeccompProfile string
	// Limites de ressources. Les valeurs vides/nulles retombent sur des défauts
	// conservateurs.
	CPUs      string // ex. "1.0"
	Memory    string // ex. "512m"
	PidsLimit int    // ex. 256
	// RunAsUser fixe --user (ex. "1000:1000") pour ne pas tourner en root dans le
	// conteneur. Vide = utilisateur par défaut de l'image.
	RunAsUser string
	// DefaultTimeout remplace DefaultTimeout pour ce runner quand > 0.
	DefaultTimeout time.Duration
}

// DockerRunner est un Runner adossé à un `docker run` durci.
//
// Chaque exécution est : --rm (jetable), --cap-drop=ALL, --security-opt
// no-new-privileges, rootfs --read-only avec un tmpfs noexec pour /tmp, ressources
// limitées, et jamais --privileged ni --network host.
type DockerRunner struct {
	cfg DockerConfig
}

// NewDockerRunner construit un DockerRunner en appliquant des défauts sûrs et en
// rejetant d'emblée une configuration dangereuse.
func NewDockerRunner(cfg DockerConfig) (*DockerRunner, error) {
	if cfg.Binary == "" {
		cfg.Binary = "docker"
	}
	if cfg.DefaultNetwork.Mode == "" {
		cfg.DefaultNetwork.Mode = NetNone
	}
	if cfg.CPUs == "" {
		cfg.CPUs = "1.0"
	}
	if cfg.Memory == "" {
		cfg.Memory = "512m"
	}
	if cfg.PidsLimit == 0 {
		cfg.PidsLimit = 256
	}
	if cfg.DefaultTimeout == 0 {
		cfg.DefaultTimeout = DefaultTimeout
	}
	if strings.EqualFold(cfg.SeccompProfile, "unconfined") {
		return nil, errors.New("sandbox : seccomp=unconfined est interdit")
	}
	if err := validateNetwork(cfg.DefaultNetwork); err != nil {
		return nil, err
	}
	return &DockerRunner{cfg: cfg}, nil
}

// Available indique si le démon Docker est joignable.
func (r *DockerRunner) Available(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, r.cfg.Binary, "version", "--format", "{{.Server.Version}}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sandbox : %s indisponible : %v : %s", r.cfg.Binary, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Run exécute spec dans un conteneur durci.
func (r *DockerRunner) Run(ctx context.Context, spec Spec) (Result, error) {
	args, err := r.buildArgs(spec)
	if err != nil {
		return Result{}, err
	}

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = r.cfg.DefaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, r.cfg.Binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()
	dur := time.Since(start)

	res := Result{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Duration: dur,
	}

	if runCtx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = -1
		return res, nil
	}

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			// Un code de sortie non nul du conteneur est un résultat normal, pas une
			// erreur du runner.
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		// La commande n'a pas pu être lancée/exécutée du tout.
		return res, fmt.Errorf("sandbox : échec d'exécution : %w : %s", runErr, strings.TrimSpace(stderr.String()))
	}
	res.ExitCode = 0
	return res, nil
}

// buildArgs construit le vecteur d'arguments `docker run ...` durci pour spec, en
// validant tout ce qui touche à la sécurité avant de le renvoyer.
func (r *DockerRunner) buildArgs(spec Spec) ([]string, error) {
	if strings.TrimSpace(spec.Image) == "" {
		return nil, errors.New("sandbox : spec.Image est obligatoire")
	}
	if len(spec.Argv) == 0 {
		return nil, errors.New("sandbox : spec.Argv est obligatoire (pas d'entrypoint shell)")
	}

	net := spec.Network
	if net.Mode == "" {
		net = r.cfg.DefaultNetwork
	}
	if err := validateNetwork(net); err != nil {
		return nil, err
	}

	args := []string{
		"run", "--rm",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
	}

	// Jamais --privileged. (Invariant documenté : --privileged n'est jamais émis.)
	if r.cfg.SeccompProfile != "" {
		args = append(args, "--security-opt", "seccomp="+r.cfg.SeccompProfile)
	}

	// Système de fichiers racine en lecture seule, avec un /tmp inscriptible verrouillé.
	args = append(args,
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
	)

	// Limites de ressources.
	args = append(args,
		"--memory", r.cfg.Memory,
		"--cpus", r.cfg.CPUs,
		"--pids-limit", fmt.Sprintf("%d", r.cfg.PidsLimit),
	)

	if r.cfg.RunAsUser != "" {
		args = append(args, "--user", r.cfg.RunAsUser)
	}

	// Réseau.
	switch net.Mode {
	case NetNone:
		args = append(args, "--network", "none")
	case NetIsolated:
		args = append(args, "--network", net.NetworkName)
	}

	// Uniquement des ajouts de capabilities de la liste blanche.
	for _, c := range spec.ExtraCapAdd {
		norm := strings.ToUpper(strings.TrimSpace(c))
		norm = strings.TrimPrefix(norm, "CAP_")
		if !allowedCaps[norm] {
			return nil, fmt.Errorf("sandbox : la capability %q n'est pas dans la liste blanche", c)
		}
		args = append(args, "--cap-add", norm)
	}

	// Montage de l'espace de travail dédié.
	if spec.WorkdirMount != "" {
		if !isAbs(spec.WorkdirMount) {
			return nil, fmt.Errorf("sandbox : WorkdirMount doit être un chemin absolu, reçu %q", spec.WorkdirMount)
		}
		args = append(args, "-v", spec.WorkdirMount+":/work:rw", "-w", "/work")
	}

	// Variables d'environnement.
	for _, e := range spec.Env {
		args = append(args, "--env", e)
	}

	// L'image, puis l'argv. Docker arrête d'analyser les options au nom de l'image :
	// tout ce qui suit est passé tel quel au conteneur (pas de shell, pas de
	// réinterprétation des arguments comme des options docker).
	args = append(args, spec.Image)
	args = append(args, spec.Argv...)
	return args, nil
}

func validateNetwork(n NetworkPolicy) error {
	switch n.Mode {
	case NetNone:
		return nil
	case NetIsolated:
		name := strings.TrimSpace(n.NetworkName)
		if name == "" {
			return errors.New("sandbox : NetIsolated exige un NetworkName")
		}
		if strings.EqualFold(name, "host") || strings.EqualFold(name, "bridge") {
			return fmt.Errorf("sandbox : le réseau %q n'est pas un réseau isolé", name)
		}
		return nil
	case "":
		return errors.New("sandbox : mode réseau vide")
	default:
		return fmt.Errorf("sandbox : mode réseau inconnu %q", n.Mode)
	}
}

// isAbs indique si p est un chemin absolu, sous Unix comme sous Windows, pour
// gérer à la fois un poste de dev Windows et une machine de lab Linux.
func isAbs(p string) bool {
	if strings.HasPrefix(p, "/") {
		return true
	}
	// Chemin avec lettre de lecteur Windows, ex. C:\ ou C:/
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	// Chemin UNC
	if strings.HasPrefix(p, `\\`) {
		return true
	}
	return false
}
