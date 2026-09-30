// Package llm est le client vers Ollama en local, avec des prompts par rôle
// (Planner, Analyst, Reporter, Advisor) et une validation STRICTE de chaque sortie
// du modèle contre un schéma JSON.
//
// Ici on ne fournit que le transport : envoyer des messages à Ollama et récupérer
// la réponse, en demandant au modèle de contraindre sa sortie à un schéma JSON.
// La construction des prompts et la validation métier vivent dans les modules qui
// utilisent le LLM (par ex. le Planner dans internal/agent).
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Client est l'abstraction du LLM. Le Planner (et plus tard les autres rôles) en
// dépendent via cette interface, ce qui permet de les tester avec un faux client,
// sans Ollama.
type Client interface {
	// Generate envoie le prompt et renvoie le contenu texte de la réponse. Si
	// Prompt.Format est fourni, la sortie est contrainte à ce schéma JSON.
	Generate(ctx context.Context, p Prompt) ([]byte, error)
}

// Prompt regroupe ce qu'on envoie au modèle pour une requête.
type Prompt struct {
	System string          // consigne de rôle (peut être vide)
	User   string          // le message concret
	Format json.RawMessage // schéma JSON contraignant la sortie (peut être nil)
}

// OllamaClient parle à un serveur Ollama local via son API HTTP.
type OllamaClient struct {
	Model   string
	BaseURL string
	HTTP    *http.Client
}

// NewOllamaClient crée un client pour le modèle donné. L'URL du serveur vient de
// la variable OLLAMA_HOST si elle est définie, sinon http://localhost:11434.
func NewOllamaClient(model string) *OllamaClient {
	base := os.Getenv("OLLAMA_HOST")
	if base == "" {
		base = "http://localhost:11434"
	}
	return &OllamaClient{
		Model:   model,
		BaseURL: base,
		HTTP:    &http.Client{Timeout: 120 * time.Second},
	}
}

// --- structures de l'API Ollama (/api/chat) ---

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string          `json:"model"`
	Messages []chatMessage   `json:"messages"`
	Stream   bool            `json:"stream"`
	Format   json.RawMessage `json:"format,omitempty"`
	Options  map[string]any  `json:"options,omitempty"`
}

type chatResponse struct {
	Message chatMessage `json:"message"`
}

// Generate envoie le prompt à Ollama et renvoie le contenu de la réponse.
func (c *OllamaClient) Generate(ctx context.Context, p Prompt) ([]byte, error) {
	msgs := make([]chatMessage, 0, 2)
	if p.System != "" {
		msgs = append(msgs, chatMessage{Role: "system", Content: p.System})
	}
	msgs = append(msgs, chatMessage{Role: "user", Content: p.User})

	reqBody := chatRequest{
		Model:    c.Model,
		Messages: msgs,
		Stream:   false,
		Format:   p.Format,
		// température 0 : on veut des décisions reproductibles, pas de créativité.
		Options: map[string]any{"temperature": 0},
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("llm : encodage de la requête : %w", err)
	}

	url := c.BaseURL + "/api/chat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("llm : construction de la requête : %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llm : Ollama injoignable sur %s (le serveur tourne-t-il ?) : %w", c.BaseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("llm : Ollama a renvoyé le statut %d", resp.StatusCode)
	}

	var cr chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, fmt.Errorf("llm : réponse Ollama illisible : %w", err)
	}
	return []byte(cr.Message.Content), nil
}

// DecodeStrict désérialise du JSON dans out en refusant les champs inconnus.
// C'est le garde-fou appliqué aux sorties du LLM : une réponse qui ne colle pas
// exactement à la structure attendue est rejetée plutôt que devinée.
func DecodeStrict(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("llm : sortie JSON non conforme : %w", err)
	}
	return nil
}
