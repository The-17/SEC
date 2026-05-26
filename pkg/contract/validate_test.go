package contract

import (
	"testing"
)

func TestMatchAction(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		action  string
		want    bool
	}{
		// Exact matches
		{"exact match success", "api.github.com/repos/The-17/agentsecrets/pulls", "api.github.com/repos/The-17/agentsecrets/pulls", true},
		{"exact match fail", "api.github.com/repos/The-17/agentsecrets/pulls", "api.github.com/repos/The-17/agentsecrets/issues", false},
		{"exact match no protocol", "api.github.com/repos", "https://api.github.com/repos", true},

		// Single segment wildcards (*)
		{"single segment wildcard middle match", "api.github.com/repos/*/pulls", "api.github.com/repos/The-17/pulls", true},
		{"single segment wildcard middle no-match", "api.github.com/repos/*/pulls", "api.github.com/repos/The-17/sub/pulls", false},
		{"single segment wildcard last match", "api.github.com/repos/The-17/*", "api.github.com/repos/The-17/agentsecrets", true},

		// Trailing wildcards
		{"trailing wildcard pulls*", "api.github.com/repos/The-17/agentsecrets/pulls*", "api.github.com/repos/The-17/agentsecrets/pulls", true},
		{"trailing wildcard pulls* with suffix", "api.github.com/repos/The-17/agentsecrets/pulls*", "api.github.com/repos/The-17/agentsecrets/pulls/42", true},
		{"trailing wildcard pulls* with nested", "api.github.com/repos/The-17/agentsecrets/pulls*", "api.github.com/repos/The-17/agentsecrets/pulls/42/comments", true},
		{"trailing wildcard /* under org", "api.github.com/repos/The-17/*", "api.github.com/repos/The-17/agentsecrets/pulls", true},
		{"trailing wildcard /* exact match of base", "api.github.com/repos/The-17/*", "api.github.com/repos/The-17/", true},
		{"trailing wildcard /* does not match sibling", "api.github.com/repos/The-17/*", "api.github.com/repos/The-17-other", false},

		// Protocol stripping
		{"protocol strip pattern https", "https://api.github.com/repos/*", "api.github.com/repos/The-17", true},
		{"protocol strip action https", "api.github.com/repos/*", "https://api.github.com/repos/The-17", true},
		{"protocol strip both", "https://api.github.com/repos/*", "https://api.github.com/repos/The-17", true},
		{"protocol strip http", "http://api.github.com/repos/*", "http://api.github.com/repos/The-17", true},

		// Universal wildcard
		{"universal wildcard matches single", "*", "github.list_pull_requests", true},
		{"universal wildcard matches nested", "*", "api.github.com/repos", true},

		// Path traversal attempts in actions
		{"path traversal escape", "api.github.com/repos/The-17/agentsecrets/*", "api.github.com/repos/The-17/agentsecrets/../../other-org/other-repo", false},
		{"path traversal directory escape", "api.github.com/repos/The-17/agentsecrets/*", "api.github.com/repos/The-17/agentsecrets/..", false},

		// HTTP Verb restrictions
		{"verb restriction exact match", "GET:api.github.com/repos/*", "GET:api.github.com/repos/foo", true},
		{"verb restriction mismatch", "GET:api.github.com/repos/*", "POST:api.github.com/repos/foo", false},
		{"verb restriction action missing verb", "GET:api.github.com/repos/*", "api.github.com/repos/foo", false},
		{"verb restriction pattern missing verb", "api.github.com/repos/*", "GET:api.github.com/repos/foo", true},
		{"verb restriction both missing verb", "api.github.com/repos/*", "api.github.com/repos/foo", true},
		{"verb restriction case insensitivity pattern", "get:api.github.com/repos/*", "GET:api.github.com/repos/foo", true},
		{"verb restriction case insensitivity action", "GET:api.github.com/repos/*", "get:api.github.com/repos/foo", true},
		{"verb restriction on port pattern", "GET:localhost:8080/*", "GET:localhost:8080/foo", true},
		{"verb restriction on port pattern mismatch", "GET:localhost:8080/*", "POST:localhost:8080/foo", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchAction(tt.pattern, tt.action)
			if got != tt.want {
				t.Errorf("MatchAction(%q, %q) = %v; want %v", tt.pattern, tt.action, got, tt.want)
			}
		})
	}
}

func TestIsActionAllowed(t *testing.T) {
	patterns := []string{
		"api.github.com/repos/The-17/agentsecrets/pulls*",
		"github.list_pull_requests",
	}

	if !IsActionAllowed(patterns, "api.github.com/repos/The-17/agentsecrets/pulls/42") {
		t.Error("expected match on trailing wildcard pattern")
	}
	if !IsActionAllowed(patterns, "github.list_pull_requests") {
		t.Error("expected match on exact pattern")
	}
	if IsActionAllowed(patterns, "api.github.com/repos/The-17/agentsecrets/issues") {
		t.Error("expected no match")
	}
}

func TestSECContract_Validate(t *testing.T) {
	validJTI := "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"

	tests := []struct {
		name    string
		c       SECContract
		wantErr bool
	}{
		{
			name: "valid contract",
			c: SECContract{
				JTI:       validJTI,
				IAT:       1716681600,
				EXP:       1716681900,
				Objective: "test",
				Allowed:   []string{"*"},
			},
			wantErr: false,
		},
		{
			name: "missing JTI",
			c: SECContract{
				IAT:       1716681600,
				EXP:       1716681900,
				Objective: "test",
				Allowed:   []string{"*"},
			},
			wantErr: true,
		},
		{
			name: "invalid UUID JTI",
			c: SECContract{
				JTI:       "not-a-uuid",
				IAT:       1716681600,
				EXP:       1716681900,
				Objective: "test",
				Allowed:   []string{"*"},
			},
			wantErr: true,
		},
		{
			name: "missing objective",
			c: SECContract{
				JTI:       validJTI,
				IAT:       1716681600,
				EXP:       1716681900,
				Allowed:   []string{"*"},
			},
			wantErr: true,
		},
		{
			name: "non-positive IAT",
			c: SECContract{
				JTI:       validJTI,
				EXP:       1716681900,
				Objective: "test",
				Allowed:   []string{"*"},
			},
			wantErr: true,
		},
		{
			name: "non-positive EXP",
			c: SECContract{
				JTI:       validJTI,
				IAT:       1716681600,
				Objective: "test",
				Allowed:   []string{"*"},
			},
			wantErr: true,
		},
		{
			name: "EXP before IAT",
			c: SECContract{
				JTI:       validJTI,
				IAT:       1716682000,
				EXP:       1716681900,
				Objective: "test",
				Allowed:   []string{"*"},
			},
			wantErr: true,
		},
		{
			name: "empty Allowed list",
			c: SECContract{
				JTI:       validJTI,
				IAT:       1716681600,
				EXP:       1716681900,
				Objective: "test",
				Allowed:   []string{},
			},
			wantErr: true,
		},
		{
			name: "empty pattern in Allowed list",
			c: SECContract{
				JTI:       validJTI,
				IAT:       1716681600,
				EXP:       1716681900,
				Objective: "test",
				Allowed:   []string{"*", "  "},
			},
			wantErr: true,
		},
		{
			name: "valid verb prefix",
			c: SECContract{
				JTI:       validJTI,
				IAT:       1716681600,
				EXP:       1716681900,
				Objective: "test",
				Allowed:   []string{"GET:api.github.com/*", "POST:api.stripe.com/transfers*"},
			},
			wantErr: false,
		},
		{
			name: "valid host with port",
			c: SECContract{
				JTI:       validJTI,
				IAT:       1716681600,
				EXP:       1716681900,
				Objective: "test",
				Allowed:   []string{"localhost:8080/foo/*"},
			},
			wantErr: false,
		},
		{
			name: "valid protocol prefix",
			c: SECContract{
				JTI:       validJTI,
				IAT:       1716681600,
				EXP:       1716681900,
				Objective: "test",
				Allowed:   []string{"https://api.github.com/*"},
			},
			wantErr: false,
		},
		{
			name: "invalid verb prefix typo",
			c: SECContract{
				JTI:       validJTI,
				IAT:       1716681600,
				EXP:       1716681900,
				Objective: "test",
				Allowed:   []string{"GTE:api.github.com/*"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.c.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
