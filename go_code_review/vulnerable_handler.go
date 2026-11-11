// VULNERABLE GO MICROSERVICE HANDLER (PRE-AUDIT)
// Issues Identified During Security Code Review:
// 1. Cross-Tenant Privilege Escalation: trusts unverified UserID without context validation.
// 2. SQL Injection via fmt.Sprintf in database query construction.
// 3. Privacy Leak: writes raw customer PII and API tokens directly to stdout logs.

package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type ToolRequest struct {
	UserID    string `json:"user_id"`
	QueryText string `json:"query_text"`
	ApiToken  string `json:"api_token"`
}

func HandleAgentToolCallVulnerable(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ToolRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		// BUG 1 (Privacy Leak): Logging full struct exposes ApiToken and user PII in plaintext logs
		log.Printf("Executing tool request: %+v\n", req)

		// BUG 2 (Privilege Escalation & SQL Injection): Unverified UserID concatenated into SQL
		query := fmt.Sprintf("SELECT email, billing_address FROM users WHERE id = '%s'", req.UserID)
		row := db.QueryRow(query)

		var email, address string
		if err := row.Scan(&email, &address); err != nil {
			// BUG 3 (Information Disclosure): Returning raw internal DB errors to the caller
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"email": "%s", "billing_address": "%s"}`, email, address)
	}
}
