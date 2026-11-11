// PATCHED GO MICROSERVICE HANDLER (POST-AUDIT GOLD STANDARD)
// Fixes Implemented:
// 1. Enforces authenticated context binding (prevents Horizontal Privilege Escalation).
// 2. Uses parameterized SQL queries with context timeouts.
// 3. Eliminates plaintext token/PII logging and sanitizes JSON serialization.

package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type ctxKey string

const AuthenticatedUserKey ctxKey = "authenticated_user_id"

type SafeToolRequest struct {
	TargetUserID string `json:"user_id"`
}

type SafeToolResponse struct {
	Email          string `json:"email"`
	BillingAddress string `json:"billing_address"`
}

func HandleAgentToolCallSecure(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		// FIX 1: Extract verified identity from authenticated middleware context
		authUserID, ok := r.Context().Value(AuthenticatedUserKey).(string)
		if !ok || authUserID == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var req SafeToolRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		// FIX 2: Strict Authorization check preventing Cross-Tenant Privilege Escalation
		if req.TargetUserID != authUserID {
			log.Printf("[SECURITY ALERT] Tenant %s attempted unauthorized access to %s", authUserID, req.TargetUserID)
			http.Error(w, "Forbidden: cross-tenant access denied", http.StatusForbidden)
			return
		}

		// FIX 3: Parameterized query preventing SQL injection
		var resp SafeToolResponse
		err := db.QueryRowContext(
			ctx,
			"SELECT email, billing_address FROM users WHERE id = $1",
			authUserID,
		).Scan(&resp.Email, &resp.BillingAddress)

		if err != nil {
			log.Printf("[DB ERROR] Lookup failed for tenant %s", authUserID)
			http.Error(w, "Resource not found", http.StatusNotFound)
			return
		}

		// FIX 4: Safe JSON encoding prevents response injection
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
