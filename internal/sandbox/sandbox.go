// Package sandbox exécute les adapters d'outils dans un conteneur isolé et jetable.
//
// Le bac à sable est une couche de défense en profondeur SOUS le moteur de scope :
// même si chaque action est déjà vérifiée par engagement.InScope avant de tourner,
// le conteneur qui exécute réellement un outil est durci, éphémère et — quand il a
// besoin du réseau — attaché uniquement à un réseau isolé dédié au lab, jamais au
// réseau de l'hôte.
//
// Le runtime est abstrait derrière Runner, pour pouvoir en changer (un runner
// Docker durci est fourni ; un backend gVisor/runsc ou Podman pourra être ajouté
// plus tard sans toucher aux adapters).
package sandbox

import (
	"context"
	"time"
)

// NetMode choisit l'exposition réseau d'une exécution.
type NetMode string

const (
	// NetNone ne donne aucun réseau au conteneur (--network none). C'est le défaut
	// et le bon choix pour les outils qui ne traitent que des données locales.
	NetNone NetMode = "none"
	// NetIsolated attache le conteneur à un réseau Docker isolé préexistant
	// (NetworkName), dédié au lab. Le filtrage d'egress vers le scope autorisé est
	// appliqué hors bande (voir docs) ; le conteneur n'obtient jamais le réseau hôte.
	NetIsolated NetMode = "isolated"
)

// NetworkPolicy décrit comment une exécution peut atteindre le réseau.
type NetworkPolicy struct {
	Mode NetMode
	// NetworkName est le nom du réseau Docker isolé auquel s'attacher quand Mode
	// vaut NetIsolated. Il doit déjà exister (créé à la mise en place du lab).
	NetworkName string
}

// Spec est une requête d'exécution entièrement spécifiée. L'argv est construit par
// l'adapter à partir de paramètres typés et bornés — jamais par le LLM, et jamais
// une chaîne shell. Il n'y a pas de shell dans l'entrypoint du conteneur.
type Spec struct {
	// Image est l'image conteneur à lancer. Devrait être épinglée (un digest est idéal).
	Image string
	// Argv est la commande d'entrée et ses arguments, passés tels quels au
	// conteneur sans interprétation shell.
	Argv []string
	// Env ajoute des variables d'environnement, sous la forme "CLE=valeur".
	Env []string
	// WorkdirMount, si renseigné, est un répertoire hôte monté en lecture/écriture
	// à /work comme espace de travail dédié du conteneur (pour la sortie de l'outil).
	// Il doit être un chemin absolu maîtrisé par l'appelant.
	WorkdirMount string
	// Network surcharge la politique réseau par défaut du runner pour cette
	// exécution. La valeur zéro (Mode vide) signifie "utiliser le défaut du runner".
	Network NetworkPolicy
	// ExtraCapAdd liste les capabilities Linux à ajouter par-dessus un cap-drop
	// complet. Seule une liste blanche vérifiée est acceptée (ex. NET_RAW).
	ExtraCapAdd []string
	// Timeout borne l'exécution. Zéro = timeout par défaut du runner.
	Timeout time.Duration
}

// Result est le résultat brut d'une exécution. Les adapters PARSENT Stdout/Stderr
// en objets structurés ; rien ici n'est transmis au LLM comme instruction.
type Result struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
	Duration time.Duration
	// TimedOut vaut true quand l'exécution a été tuée pour dépassement de délai.
	TimedOut bool
}

// Runner exécute un Spec dans un environnement isolé.
type Runner interface {
	// Available renvoie nil si le runtime est utilisable maintenant (binaire
	// présent et démon joignable), sinon une erreur expliquant pourquoi.
	Available(ctx context.Context) error
	// Run exécute le spec et renvoie son résultat. Un code de sortie non nul du
	// conteneur est reporté dans Result.ExitCode, pas en tant qu'erreur ; err n'est
	// non nil que si l'exécution n'a pas pu avoir lieu ou qu'un contrôle a échoué.
	Run(ctx context.Context, spec Spec) (Result, error)
}
