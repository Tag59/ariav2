// Command aria est le point d'entrée CLI/TUI d'ARIA.
//
// ARIA est un COPILOTE de pentest méthodologique : il assiste un opérateur humain,
// il ne le remplace pas. Ce point d'entrée initial ne démontre que le premier
// garde-fou non négociable : ARIA refuse de démarrer sans un engagement valide et
// signé, et propose une vérification de scope contre le périmètre de cet engagement.
//
// USAGE UNIQUEMENT sur des systèmes que l'on possède ou que l'on est autorisé PAR
// ÉCRIT à tester.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Tag59/aria/internal/engagement"
)

func main() {
	engPath := flag.String("engagement", "", "chemin vers engagement.yaml (obligatoire)")
	check := flag.String("check", "", "optionnel : affiche si une cible est dans le scope, puis quitte")
	flag.Parse()

	if *engPath == "" {
		fmt.Fprintln(os.Stderr, "aria : --engagement <engagement.yaml> est obligatoire ; ARIA ne démarre pas sans autorisation valide")
		os.Exit(2)
	}

	eng, err := engagement.Load(*engPath)
	if err != nil {
		// Pas d'engagement valide => ARIA ne démarre pas.
		fmt.Fprintf(os.Stderr, "aria : refus de démarrer : %v\n", err)
		os.Exit(1)
	}

	if !eng.Authorization.IsActive(time.Now()) {
		fmt.Fprintln(os.Stderr, "aria : refus de démarrer : la fenêtre d'autorisation n'est pas active actuellement")
		os.Exit(1)
	}

	in, out := eng.ScopeStrings()
	fmt.Printf("ARIA — engagement %q chargé et validé.\n", eng.Name)
	fmt.Printf("  autorisé par  : %s (réf %s)\n", eng.Authorization.AuthorizedBy, eng.Authorization.Reference)
	fmt.Printf("  dans le scope : %v\n", in)
	fmt.Printf("  hors scope    : %v\n", out)
	fmt.Printf("  catégories RoE: %v\n", eng.RoE.AllowedCategories)

	if *check != "" {
		ok, err := eng.InScope(*check)
		if err != nil {
			fmt.Fprintf(os.Stderr, "aria : impossible d'évaluer la cible %q : %v\n", *check, err)
			os.Exit(1)
		}
		if ok {
			fmt.Printf("DANS LE SCOPE : %s\n", *check)
		} else {
			fmt.Printf("HORS SCOPE (refusé) : %s\n", *check)
		}
		return
	}

	fmt.Println("\n(étape en cours) L'orchestrateur, le profiler, le LLM et le reporting ne sont pas encore branchés.")
}
