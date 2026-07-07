package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAudit(t *testing.T) {
	agent := testAgent(t)
	mission := MissionRef{Approver: "https://ps.example", S256: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}

	var got AuditRequest
	terminated := false
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/audit" {
			http.NotFound(rw, r)
			return
		}
		if _, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return
		}
		if terminated {
			WriteMissionStatusError(rw, "terminated")
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		rw.WriteHeader(http.StatusCreated) // §7.5.2
	}))
	defer srv.Close()

	c := NewPSClient(srv.URL, agent)
	err := c.Audit(context.Background(), AuditRequest{
		Mission:     mission,
		Action:      "SendEmail",
		Description: "sent the itinerary",
		Parameters:  map[string]any{"to": "user@example.com"},
		Result:      map[string]any{"message_id": "m-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Action != "SendEmail" || got.Mission != mission || got.Parameters["to"] != "user@example.com" {
		t.Fatalf("PS recorded %+v", got)
	}

	// Mission required client-side (§7.5: no audit outside a mission).
	if err := c.Audit(context.Background(), AuditRequest{Action: "X"}); err == nil {
		t.Fatal("audit without mission accepted")
	}

	// Terminated mission → typed §8.6 error; agent must stop.
	terminated = true
	err = c.Audit(context.Background(), AuditRequest{Mission: mission, Action: "SendEmail"})
	var mse *MissionStatusError
	if !errors.As(err, &mse) || mse.MissionStatus != "terminated" || mse.Code != "mission_terminated" {
		t.Fatalf("err = %v", err)
	}
}
