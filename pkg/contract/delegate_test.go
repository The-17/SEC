package contract

import (
	"testing"
)

func TestIsPatternSubset(t *testing.T) {
	tests := []struct {
		name   string
		parent string
		child  string
		want   bool
	}{
		{"exact match", "api.github.com/repos", "api.github.com/repos", true},
		{"exact mismatch", "api.github.com/repos", "api.github.com/issues", false},
		{"parent universal wildcard", "*", "GET:api.github.com/repos", true},
		{"parent wildcard covers child path", "api.github.com/repos/*", "api.github.com/repos/The-17/agentsecrets", true},
		{"child wider than parent", "api.github.com/repos/The-17/*", "api.github.com/repos/*", false},
		{"verb restriction subset match", "GET:api.github.com/*", "GET:api.github.com/repos", true},
		{"verb restriction subset mismatch", "GET:api.github.com/*", "POST:api.github.com/repos", false},
		{"verb restriction escalation from parent verb", "GET:api.github.com/*", "api.github.com/repos", false},
		{"verb restriction allow any verb parent", "api.github.com/*", "GET:api.github.com/repos", true},
		{"wildcard subset middle segment", "api.github.com/repos/*/pulls", "api.github.com/repos/The-17/pulls", true},
		{"wildcard subset middle mismatch", "api.github.com/repos/*/pulls", "api.github.com/repos/The-17/issues", false},
		{"nested wildcards subset", "api.github.com/repos/*", "api.github.com/repos/*/*", true},
		{"trailing wildcard partial match", "api.github.com/repos/foo*", "api.github.com/repos/foobar/*", true},
		{"trailing wildcard partial mismatch", "api.github.com/repos/foo*", "api.github.com/repos/bar*", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPatternSubset(tt.child, tt.parent)
			if got != tt.want {
				t.Errorf("IsPatternSubset(child=%q, parent=%q) = %v; want %v", tt.child, tt.parent, got, tt.want)
			}
		})
	}
}

func TestValidateDelegation(t *testing.T) {
	parentJTI := "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
	childJTI := "f4e4c89b-9125-4a55-8cc3-8ccf14978c55"
	depthZero := 0
	depthOne := 1
	depthTwo := 2

	parent := SECContract{
		JTI:       parentJTI,
		IAT:       1000,
		EXP:       2000,
		Objective: "parent objective",
		Allowed:   []string{"GET:api.github.com/repos/*", "api.github.com/issues/*"},
	}

	tests := []struct {
		name    string
		setup   func(p *SECContract) SECContract
		wantErr bool
	}{
		{
			name: "valid delegation",
			setup: func(p *SECContract) SECContract {
				return SECContract{
					JTI:       childJTI,
					ParentJTI: parentJTI,
					IAT:       1100,
					EXP:       1900,
					Objective: "child objective",
					Allowed:   []string{"GET:api.github.com/repos/The-17/pulls"},
				}
			},
			wantErr: false,
		},
		{
			name: "expiration exceeds parent",
			setup: func(p *SECContract) SECContract {
				return SECContract{
					JTI:       childJTI,
					ParentJTI: parentJTI,
					IAT:       1100,
					EXP:       2100, // Exceeds 2000
					Objective: "child objective",
					Allowed:   []string{"GET:api.github.com/repos/The-17/pulls"},
				}
			},
			wantErr: true,
		},
		{
			name: "parent JTI mismatch",
			setup: func(p *SECContract) SECContract {
				return SECContract{
					JTI:       childJTI,
					ParentJTI: "wrong-parent-jti-uuid-value",
					IAT:       1100,
					EXP:       1900,
					Objective: "child objective",
					Allowed:   []string{"GET:api.github.com/repos/The-17/pulls"},
				}
			},
			wantErr: true,
		},
		{
			name: "child allow pattern not subset of parent",
			setup: func(p *SECContract) SECContract {
				return SECContract{
					JTI:       childJTI,
					ParentJTI: parentJTI,
					IAT:       1100,
					EXP:       1900,
					Objective: "child objective",
					Allowed:   []string{"POST:api.github.com/repos/The-17/pulls"}, // parent is GET only
				}
			},
			wantErr: true,
		},
		{
			name: "child allow pattern totally uncovered",
			setup: func(p *SECContract) SECContract {
				return SECContract{
					JTI:       childJTI,
					ParentJTI: parentJTI,
					IAT:       1100,
					EXP:       1900,
					Objective: "child objective",
					Allowed:   []string{"api.stripe.com/v1/charges"},
				}
			},
			wantErr: true,
		},
		{
			name: "depth limit ok",
			setup: func(p *SECContract) SECContract {
				p.MaxDepth = &depthTwo
				return SECContract{
					JTI:       childJTI,
					ParentJTI: parentJTI,
					IAT:       1100,
					EXP:       1900,
					Objective: "child objective",
					Allowed:   []string{"GET:api.github.com/repos/The-17/pulls"},
					MaxDepth:  &depthOne,
				}
			},
			wantErr: false,
		},
		{
			name: "depth limit parent zero",
			setup: func(p *SECContract) SECContract {
				p.MaxDepth = &depthZero
				return SECContract{
					JTI:       childJTI,
					ParentJTI: parentJTI,
					IAT:       1100,
					EXP:       1900,
					Objective: "child objective",
					Allowed:   []string{"GET:api.github.com/repos/The-17/pulls"},
					MaxDepth:  &depthZero,
				}
			},
			wantErr: true,
		},
		{
			name: "depth limit child exceeds parent - 1",
			setup: func(p *SECContract) SECContract {
				p.MaxDepth = &depthTwo
				return SECContract{
					JTI:       childJTI,
					ParentJTI: parentJTI,
					IAT:       1100,
					EXP:       1900,
					Objective: "child objective",
					Allowed:   []string{"GET:api.github.com/repos/The-17/pulls"},
					MaxDepth:  &depthTwo, // must be <= 1
				}
			},
			wantErr: true,
		},
		{
			name: "depth limit child missing",
			setup: func(p *SECContract) SECContract {
				p.MaxDepth = &depthOne
				return SECContract{
					JTI:       childJTI,
					ParentJTI: parentJTI,
					IAT:       1100,
					EXP:       1900,
					Objective: "child objective",
					Allowed:   []string{"GET:api.github.com/repos/The-17/pulls"},
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pCopy := parent // Reset parent
			child := tt.setup(&pCopy)
			err := ValidateDelegation(pCopy, child)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDelegation() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
