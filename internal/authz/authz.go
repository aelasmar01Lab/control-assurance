// Package authz decides who may do what. Every entry point, whether a web
// handler, a CLI command, an export or a job, reaches data through the
// service layer, and the service layer asks Can before it acts.
package authz

import (
	"errors"
	"fmt"
)

// Role is one of the four lab roles.
type Role string

// The four roles.
const (
	Operator     Role = "operator"      // runs the system: collection, evaluation, catalog
	ControlOwner Role = "control_owner" // answers for specific controls
	Reviewer     Role = "reviewer"      // reviews evidence and decides exceptions
	Auditor      Role = "auditor"       // reads and exports; never writes
)

// Roles lists every role.
var Roles = []Role{Operator, ControlOwner, Reviewer, Auditor}

// ValidRole reports whether r is one of the four roles.
func ValidRole(r Role) bool {
	for _, known := range Roles {
		if r == known {
			return true
		}
	}
	return false
}

// Action is something an actor can attempt.
type Action string

// Every action the service layer performs.
const (
	View               Action = "view"              // read results, findings, evidence, the log
	Export             Action = "export"            // produce an export of the same data
	RunCollection      Action = "collection.run"    // start a collection job
	RunEvaluation      Action = "evaluation.run"    // start an evaluation job
	LoadCatalog        Action = "catalog.load"      // import framework packs
	SubmitEvidence     Action = "evidence.submit"   // submit manual evidence for a control
	ReviewEvidence     Action = "evidence.review"   // accept or reject submitted evidence
	RequestException   Action = "exception.request" // ask for a finding to be accepted for a time
	DecideException    Action = "exception.decide"  // approve or reject an exception request
	AddRemediationNote Action = "remediation.note"  // record remediation progress on a finding
)

// Actions lists every action.
var Actions = []Action{
	View, Export, RunCollection, RunEvaluation, LoadCatalog,
	SubmitEvidence, ReviewEvidence, RequestException, DecideException, AddRemediationNote,
}

// Actor is who is asking.
type Actor struct {
	UserID   int64
	Username string
	Role     Role
}

// Resource carries the facts about the thing being acted on that a decision
// can depend on. Fields that do not apply to an action are left zero.
type Resource struct {
	// ControlOwners are the usernames answerable for the control the
	// evidence or finding belongs to.
	ControlOwners []string
	// AuthorID is who submitted the evidence or requested the exception
	// that is now being reviewed or decided.
	AuthorID int64
}

func (r Resource) ownedBy(username string) bool {
	for _, o := range r.ControlOwners {
		if o == username {
			return true
		}
	}
	return false
}

// ErrDenied is returned, wrapped, when an actor may not perform an action.
var ErrDenied = errors.New("permission denied")

// matrix says which roles may attempt each action at all. Can then applies
// the rules that depend on the resource.
var matrix = map[Action]map[Role]bool{
	View:               {Operator: true, ControlOwner: true, Reviewer: true, Auditor: true},
	Export:             {Operator: true, ControlOwner: true, Reviewer: true, Auditor: true},
	RunCollection:      {Operator: true},
	RunEvaluation:      {Operator: true},
	LoadCatalog:        {Operator: true},
	SubmitEvidence:     {Operator: true, ControlOwner: true},
	ReviewEvidence:     {Reviewer: true},
	RequestException:   {Operator: true, ControlOwner: true, Reviewer: true},
	DecideException:    {Reviewer: true},
	AddRemediationNote: {Operator: true, ControlOwner: true},
}

// RoleMay reports whether a role may ever attempt an action, before any
// resource rule is applied. It exists so the matrix can be shown and tested.
func RoleMay(role Role, action Action) bool {
	return matrix[action][role]
}

// Can returns nil if actor may perform action on res, and an error wrapping
// ErrDenied otherwise.
func Can(actor Actor, action Action, res Resource) error {
	deny := func(why string) error {
		return fmt.Errorf("%w: %s (%s) may not %s: %s", ErrDenied, actor.Username, actor.Role, action, why)
	}
	if actor.UserID == 0 || !ValidRole(actor.Role) {
		return fmt.Errorf("%w: no authenticated actor", ErrDenied)
	}
	if !matrix[action][actor.Role] {
		return deny("the role does not include this action")
	}

	switch action {
	case SubmitEvidence, AddRemediationNote, RequestException:
		// A control owner acts only on controls they answer for.
		if actor.Role == ControlOwner && !res.ownedBy(actor.Username) {
			return deny("they do not own the control concerned")
		}
	case ReviewEvidence, DecideException:
		// Separation of duties: nobody decides on their own submission or request.
		if res.AuthorID == 0 {
			return deny("the author of the item under review is unknown")
		}
		if res.AuthorID == actor.UserID {
			return deny("they authored the item under review")
		}
	}
	return nil
}

// MatrixMarkdown renders the permission matrix, straight from the rules Can
// enforces, so the document cannot drift from behaviour.
func MatrixMarkdown() string {
	out := "# Permission matrix\n\n" +
		"Generated by `cca permissions` from `internal/authz`. Do not edit by hand.\n\n" +
		"Every entry point (web pages, CLI commands, exports and jobs) reaches data through the service layer, " +
		"which calls one function, `authz.Can`, before it acts.\n\n" +
		"| Action |"
	for _, r := range Roles {
		out += " " + string(r) + " |"
	}
	out += "\n| --- |"
	for range Roles {
		out += " --- |"
	}
	out += "\n"
	for _, a := range Actions {
		out += "| `" + string(a) + "` |"
		for _, r := range Roles {
			if RoleMay(r, a) {
				out += " allow |"
			} else {
				out += " deny |"
			}
		}
		out += "\n"
	}
	out += "\nRules that depend on the item, applied after the table:\n\n" +
		"- A control owner may submit evidence, request an exception or add a remediation note only for a control they own.\n" +
		"- Nobody may review evidence they submitted or decide an exception they requested. " +
		"The database enforces the same rule with a constraint.\n" +
		"- A request with no signed-in, known user is denied everything.\n"
	return out
}
