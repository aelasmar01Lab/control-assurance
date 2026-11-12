package authz

import (
	"errors"
	"os"
	"testing"
)

// want is the permission matrix, written out independently of the
// implementation: for every action, the roles that may attempt it.
var want = map[Action][]Role{
	View:               {Operator, ControlOwner, Reviewer, Auditor},
	Export:             {Operator, ControlOwner, Reviewer, Auditor},
	RunCollection:      {Operator},
	RunEvaluation:      {Operator},
	LoadCatalog:        {Operator},
	SubmitEvidence:     {Operator, ControlOwner},
	ReviewEvidence:     {Reviewer},
	RequestException:   {Operator, ControlOwner, Reviewer},
	DecideException:    {Reviewer},
	AddRemediationNote: {Operator, ControlOwner},
}

// actors, one per role. The control owner owns the control in favourable.
var actors = map[Role]Actor{
	Operator:     {UserID: 1, Username: "operator", Role: Operator},
	ControlOwner: {UserID: 2, Username: "control-owner", Role: ControlOwner},
	Reviewer:     {UserID: 3, Username: "reviewer", Role: Reviewer},
	Auditor:      {UserID: 4, Username: "auditor", Role: Auditor},
}

// favourable is a resource on which every resource rule is satisfied, so the
// outcome depends on the role alone: owned by the control owner, authored by
// somebody who is none of the actors.
var favourable = Resource{ControlOwners: []string{"control-owner"}, AuthorID: 99}

// Every action has an allow test and a deny test for every role.
func TestMatrix(t *testing.T) {
	if len(want) != len(Actions) {
		t.Fatalf("matrix covers %d actions, but %d are defined", len(want), len(Actions))
	}
	for _, action := range Actions {
		allowed := map[Role]bool{}
		for _, r := range want[action] {
			allowed[r] = true
		}
		if len(allowed) == 0 {
			t.Errorf("%s: no role is allowed, so it has no allow test", action)
		}
		if len(allowed) == len(Roles) && action != View && action != Export {
			t.Errorf("%s: every role is allowed, so it has no deny test", action)
		}
		for _, role := range Roles {
			err := Can(actors[role], action, favourable)
			switch {
			case allowed[role] && err != nil:
				t.Errorf("%s as %s: denied, want allowed (%v)", action, role, err)
			case !allowed[role] && err == nil:
				t.Errorf("%s as %s: allowed, want denied", action, role)
			case !allowed[role] && !errors.Is(err, ErrDenied):
				t.Errorf("%s as %s: error does not wrap ErrDenied: %v", action, role, err)
			}
			if RoleMay(role, action) != allowed[role] {
				t.Errorf("RoleMay(%s, %s) = %v, want %v", role, action, RoleMay(role, action), allowed[role])
			}
		}
	}
}

// The auditor can read and export, and every write is denied.
func TestAuditorIsReadOnly(t *testing.T) {
	auditor := actors[Auditor]
	for _, action := range Actions {
		err := Can(auditor, action, favourable)
		readOnly := action == View || action == Export
		if readOnly && err != nil {
			t.Errorf("auditor denied %s: %v", action, err)
		}
		if !readOnly && err == nil {
			t.Errorf("auditor allowed to %s", action)
		}
	}
}

func TestSeparationOfDuties(t *testing.T) {
	reviewer := actors[Reviewer]
	own := Resource{AuthorID: reviewer.UserID}
	others := Resource{AuthorID: 99}
	unknown := Resource{}

	for _, action := range []Action{DecideException, ReviewEvidence} {
		if err := Can(reviewer, action, own); !errors.Is(err, ErrDenied) {
			t.Errorf("%s on the reviewer's own item: err = %v, want denied", action, err)
		}
		if err := Can(reviewer, action, others); err != nil {
			t.Errorf("%s on someone else's item: %v", action, err)
		}
		if err := Can(reviewer, action, unknown); !errors.Is(err, ErrDenied) {
			t.Errorf("%s with no known author: err = %v, want denied", action, err)
		}
	}
}

func TestControlOwnerActsOnlyOnOwnControls(t *testing.T) {
	owner := actors[ControlOwner]
	theirs := Resource{ControlOwners: []string{"someone-else", "control-owner"}}
	notTheirs := Resource{ControlOwners: []string{"someone-else"}}

	for _, action := range []Action{SubmitEvidence, AddRemediationNote, RequestException} {
		if err := Can(owner, action, theirs); err != nil {
			t.Errorf("%s on an owned control: %v", action, err)
		}
		if err := Can(owner, action, notTheirs); !errors.Is(err, ErrDenied) {
			t.Errorf("%s on another owner's control: err = %v, want denied", action, err)
		}
		// The operator is not bound by ownership.
		if err := Can(actors[Operator], action, notTheirs); err != nil {
			t.Errorf("operator %s: %v", action, err)
		}
	}
}

func TestNoActorIsDenied(t *testing.T) {
	for _, a := range []Actor{{}, {UserID: 5, Role: "admin"}, {Role: Operator}} {
		for _, action := range Actions {
			if err := Can(a, action, favourable); !errors.Is(err, ErrDenied) {
				t.Errorf("actor %+v allowed to %s", a, action)
			}
		}
	}
}

// The committed matrix must match the rules Can enforces.
func TestMatrixDocumentIsInSync(t *testing.T) {
	const path = "../../docs/permissions.md"
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with `make guide`)", path, err)
	}
	if string(onDisk) != MatrixMarkdown() {
		t.Errorf("%s is out of date; regenerate with `make guide`", path)
	}
}
