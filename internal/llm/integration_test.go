package llm

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestOllamaGenerationJSON vérifie, contre un vrai serveur Ollama, que la sortie
// est bien contrainte à un schéma JSON. Ignoré si Ollama n'est pas joignable, pour
// que la suite passe partout.
//
// Le modèle peut être choisi via ARIA_TEST_MODEL (défaut : qwen3:8b).
func TestOllamaGenerationJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("ignoré en mode -short")
	}
	model := os.Getenv("ARIA_TEST_MODEL")
	if model == "" {
		model = "qwen3:8b"
	}
	client := NewOllamaClient(model)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	schema := json.RawMessage(`{
		"type":"object",
		"properties":{"result":{"type":"integer"}},
		"required":["result"]
	}`)

	raw, err := client.Generate(ctx, Prompt{
		System: "Tu réponds uniquement en JSON conforme au schéma imposé.",
		User:   "Combien font 2 + 3 ? Renvoie {\"result\": <nombre>}.",
		Format: schema,
	})
	if err != nil {
		t.Skipf("Ollama indisponible, test ignoré : %v", err)
	}

	var out struct {
		Result int `json:"result"`
	}
	if err := DecodeStrict(raw, &out); err != nil {
		t.Fatalf("la sortie n'est pas un JSON conforme au schéma : %v (brut : %s)", err, raw)
	}
	if out.Result != 5 {
		t.Errorf("result = %d, attendu 5 (brut : %s)", out.Result, raw)
	}
}
