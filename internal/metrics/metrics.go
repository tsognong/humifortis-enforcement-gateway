package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type Metrics struct{ requests, allows, blocks, challenges, cacheHits, cacheMisses, backendErrors, backendTimeouts, caepEvents, replayEvents, agentAllowed, agentRefused, agentProofRejected, agentReportsFailed atomic.Uint64 }

func (m *Metrics) AuthRequests()       { m.requests.Add(1) }
func (m *Metrics) Allow()              { m.allows.Add(1) }
func (m *Metrics) Block()              { m.blocks.Add(1) }
func (m *Metrics) Challenge()          { m.challenges.Add(1) }
func (m *Metrics) AgentAllowed()       { m.agentAllowed.Add(1) }
func (m *Metrics) AgentRefused()       { m.agentRefused.Add(1) }
func (m *Metrics) AgentProofRejected() { m.agentProofRejected.Add(1) }
func (m *Metrics) CAEP()               { m.caepEvents.Add(1) }
func (m *Metrics) Handler(w http.ResponseWriter, _ *http.Request) {
	values := []struct {
		name  string
		value uint64
	}{{"humifortis_auth_requests_total", m.requests.Load()}, {"humifortis_allow_total", m.allows.Load()}, {"humifortis_block_total", m.blocks.Load()}, {"humifortis_challenge_total", m.challenges.Load()}, {"humifortis_cache_hits_total", m.cacheHits.Load()}, {"humifortis_cache_misses_total", m.cacheMisses.Load()}, {"humifortis_backend_errors_total", m.backendErrors.Load()}, {"humifortis_backend_timeouts_total", m.backendTimeouts.Load()}, {"humifortis_caep_events_total", m.caepEvents.Load()}, {"humifortis_replay_events_total", m.replayEvents.Load()}, {"humifortis_aauth_allowed_total", m.agentAllowed.Load()}, {"humifortis_aauth_refused_total", m.agentRefused.Load()}, {"humifortis_aauth_proof_rejected_total", m.agentProofRejected.Load()}}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	for _, value := range values {
		_, _ = fmt.Fprintf(w, "%s %d\n", value.name, value.value)
	}
}
