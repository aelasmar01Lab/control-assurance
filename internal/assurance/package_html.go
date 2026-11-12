package assurance

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/store"
)

// packageReport is what the package's index.html is rendered from. It holds
// only what the package's JSON files hold.
type packageReport struct {
	Format       string
	Notice       string
	From, To     time.Time
	Scope        []store.ScopeRow
	Controls     []PackageControl
	Requirements []RequirementView
	Findings     []store.FindingRow
	Exceptions   []PackageException
	Notes        []store.NoteRow
	Evaluations  []store.EvaluationRow
	Runs         []store.RunRow
	Submissions  []store.SubmissionRow
	Log          []store.LogRow
}

var reportFuncs = template.FuncMap{
	"when":  func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	"label": func(v any) string { return strings.ReplaceAll(fmt.Sprint(v), "_", " ") },
	"short": func(sha string) string { return sha[:min(12, len(sha))] },
	"whenPtr": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format("2006-01-02 15:04 UTC")
	},
	"deref": func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	},
}

var reportTemplate = template.Must(template.New("index.html").Funcs(reportFuncs).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Review package {{when .From}} to {{when .To}}</title>
<style>
body { font: 15px/1.5 system-ui, sans-serif; margin: 0 auto; max-width: 1100px; padding: 16px; color: #1b1f24; background: #fff; }
h1 { font-size: 22px; } h2 { font-size: 18px; margin-top: 32px; border-bottom: 1px solid #d0d7de; padding-bottom: 4px; }
table { border-collapse: collapse; width: 100%; } th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid #d0d7de; }
th { background: #f3f5f7; } .scroll { overflow-x: auto; } .dim { color: #57606a; } code { font-size: 13px; }
.tag { display: inline-block; padding: 0 7px; border-radius: 10px; font-weight: 600; font-size: 13px; background: #f3f5f7; border: 1px solid #d0d7de; white-space: nowrap; }
.pass, .supported, .partly_evidenced, .succeeded { background: #dafbe1; color: #116329; border-color: transparent; }
.fail, .needs_attention, .failed { background: #ffe1e0; color: #a40e26; border-color: transparent; }
.not_evaluated, .stale, .accepted_risk { background: #fff3c4; color: #6b4e00; border-color: transparent; }
@media (prefers-color-scheme: dark) { body { background: #0d1117; color: #e6edf3; } th { background: #161b22; } th, td, h2 { border-color: #30363d; } .dim { color: #9198a1; } .tag { background: #161b22; border-color: #30363d; } }
</style>
</head>
<body>
<h1>Review package</h1>
<p><strong>Period:</strong> {{when .From}} (inclusive) to {{when .To}} (exclusive). <span class="dim">Format {{.Format}}.</span></p>
<p>{{.Notice}}</p>
<p class="dim">This page is a reading copy of the JSON files beside it. <code>manifest.json</code> lists the SHA-256 of every file, this one included; check the package with <code>cca package verify</code>.</p>

<h2>Scope</h2>
{{if .Scope}}<div class="scroll"><table>
<thead><tr><th>Source</th><th>Resource</th><th>Scope</th><th>Decided by</th></tr></thead>
<tbody>{{range .Scope}}<tr><td>{{.Provider}} {{.Kind}}</td><td>{{.ExternalID}}</td><td>{{label .Scope}}{{if .ScopeReason}}: {{.ScopeReason}}{{end}}</td><td>{{.DecidedBy}}</td></tr>{{end}}</tbody>
</table></div>{{else}}<p class="dim">No resource was registered before the end of the period.</p>{{end}}

<h2>Controls at the end of the period</h2>
<div class="scroll"><table>
<thead><tr><th>Control</th><th>State</th><th>Why</th><th>Rests on</th><th>Framework mapping</th></tr></thead>
<tbody>{{range .Controls}}<tr>
<td><strong>{{.Title}}</strong> <span class="tag">{{.ReviewLabel}}</span><br>{{.Statement}}<br><span class="dim">Owner: {{.Owner}}. {{if .RevisionAtPeriodEnd}}Wording <code>{{short .RevisionAtPeriodEnd.ContentSHA256}}</code> was in force at the end of the period{{if .WordingChangedSince}}; the control has been reworded since, and this page uses the new wording <code>{{short .ContentSHA256}}</code>{{end}}.{{else}}No wording of this control was on record before the end of the period; this page uses <code>{{short .ContentSHA256}}</code>.{{end}}</span></td>
<td><span class="tag {{.StateAtPeriodEnd}}">{{label .StateAtPeriodEnd}}</span></td>
<td>{{range .Reasons}}<div>{{.}}</div>{{end}}</td>
<td>{{range .Checks}}<code>{{.}}</code> {{end}}{{if .ManualCheck}}<code>{{.ManualCheck}}</code> <span class="dim">manual</span>{{end}}</td>
<td>{{range .Mappings}}<div>{{.Framework}} {{.Requirement}}, {{.EffectiveStrength}}{{if ne .EffectiveStrength .Strength}} <span class="dim">(written as {{.Strength}})</span>{{end}} <span class="tag">{{.Review.Label}}</span></div><div class="dim">{{.Limitation}}</div>{{else}}<span class="dim">none</span>{{end}}</td>
</tr>{{end}}</tbody>
</table></div>

<h2>Framework requirements at the end of the period</h2>
<p class="dim">Partly evidenced means every control mapped to the requirement was supported by current evidence. It does not mean the requirement is met. Controls and mappings are drafted by an AI agent; each is a draft until the maintainer has reviewed it, and is labelled either way.</p>
<div class="scroll"><table>
<thead><tr><th>Requirement</th><th>State</th><th>Rests on</th></tr></thead>
<tbody>{{range .Requirements}}<tr>
<td><strong>{{.Framework}} {{.ID}}</strong> {{if .Title}}{{.Title}}{{else}}{{.Text}}{{end}}{{if .Note}}<div class="dim">{{.Note}}</div>{{end}}</td>
<td><span class="tag {{.State}}">{{label .State}}</span></td>
<td>{{range .Controls}}<div>{{.Title}}: {{label .State}} <span class="dim">({{.Strength}} mapping, {{.Review}}; control {{.ControlReview}})</span></div>{{else}}<span class="dim">No control. {{.Rationale}} ({{.TrackingReview}})</span>{{end}}</td>
</tr>{{end}}</tbody>
</table></div>

<h2>Findings open at some point in the period</h2>
{{if .Findings}}<div class="scroll"><table>
<thead><tr><th>Finding</th><th>Resource</th><th>Check</th><th>Opened</th><th>Closed</th></tr></thead>
<tbody>{{range .Findings}}<tr>
<td>#{{.ID}}</td><td>{{.Resource}}</td><td><code>{{.CheckKey}}</code></td>
<td>{{when .OpenedAt}}<br><span class="dim">evaluation {{.OpeningEvaluationID}}: {{.OpeningExplanation}}</span></td>
<td>{{if .ClosedAt}}{{whenPtr .ClosedAt}}<br><span class="dim">evaluation {{.ClosingEvaluationID}}: {{deref .ClosingExplanation}}</span>{{else}}<span class="tag fail">open at period end</span>{{end}}</td>
</tr>{{end}}</tbody>
</table></div>{{else}}<p class="dim">None.</p>{{end}}

<h2>Exceptions</h2>
{{if .Exceptions}}<div class="scroll"><table>
<thead><tr><th>Finding</th><th>Requested</th><th>Justification</th><th>Expires</th><th>Status at period end</th><th>Decision</th></tr></thead>
<tbody>{{range .Exceptions}}<tr>
<td>#{{.FindingID}} <code>{{.CheckKey}}</code></td><td>{{.RequestedBy}}<br><span class="dim">{{when .RequestedAt}}</span></td><td>{{.Justification}}</td>
<td>{{when .ExpiresAt}}</td><td><span class="tag">{{.StatusAtPeriodEnd}}</span></td>
<td>{{if .DecidedAt}}{{deref .DecidedBy}}, {{whenPtr .DecidedAt}}<br><span class="dim">{{.DecisionReason}}</span>{{else}}<span class="dim">not decided</span>{{end}}</td>
</tr>{{end}}</tbody>
</table></div>{{else}}<p class="dim">None.</p>{{end}}

<h2>Remediation notes</h2>
{{if .Notes}}<div class="scroll"><table>
<thead><tr><th>Finding</th><th>Author</th><th>When</th><th>Note</th></tr></thead>
<tbody>{{range .Notes}}<tr><td>#{{.FindingID}}</td><td>{{.Author}}</td><td>{{when .CreatedAt}}</td><td>{{.Body}}</td></tr>{{end}}</tbody>
</table></div>{{else}}<p class="dim">None.</p>{{end}}

<h2>Manual evidence</h2>
{{if .Submissions}}<div class="scroll"><table>
<thead><tr><th>Control</th><th>Submitted</th><th>File</th><th>Review at period end</th></tr></thead>
<tbody>{{range .Submissions}}<tr>
<td>{{.ControlKey}}</td><td>{{.SubmittedBy}}<br><span class="dim">{{when .SubmittedAt}}</span></td>
<td>{{.Filename}}<br><a href="evidence/{{.PayloadSHA256}}"><code>{{short .PayloadSHA256}}</code></a></td>
<td><span class="tag">{{.ReviewStatus}}</span>{{if .ReviewedAt}} {{deref .ReviewedBy}}, {{whenPtr .ReviewedAt}}<br><span class="dim">{{.ReviewReason}}</span>{{end}}</td>
</tr>{{end}}</tbody>
</table></div>{{else}}<p class="dim">None.</p>{{end}}

<h2>Evaluations of evidence collected in the period</h2>
{{if .Evaluations}}<div class="scroll"><table>
<thead><tr><th>Evaluation</th><th>Resource</th><th>Check</th><th>Result</th><th>Explanation</th><th>Evidence</th><th>Collected</th></tr></thead>
<tbody>{{range .Evaluations}}<tr>
<td>{{.EvaluationID}}</td><td>{{.Resource}}</td><td><code>{{.CheckKey}}</code> <span class="dim">v{{.CheckVersion}}</span></td>
<td><span class="tag {{.Result}}">{{label .Result}}</span></td><td>{{.Explanation}}</td>
<td><a href="evidence/{{.PayloadSHA256}}"><code>{{short .PayloadSHA256}}</code></a></td><td>{{when .CollectedAt}}</td>
</tr>{{end}}</tbody>
</table></div>{{else}}<p class="dim">None.</p>{{end}}

<h2>Collection runs that finished in the period</h2>
<p class="dim">A failed run is a collection problem, not a result. It produced no observation and changed no result.</p>
{{if .Runs}}<div class="scroll"><table>
<thead><tr><th>Run</th><th>Evidence</th><th>Resource</th><th>Why</th><th>Finished</th><th>Outcome</th><th>Error</th></tr></thead>
<tbody>{{range .Runs}}<tr>
<td>#{{.ID}}</td><td><code>{{.Kind}}</code></td><td>{{.Resource}}</td><td>{{.Cause}}, attempt {{.Attempt}}</td><td>{{whenPtr .FinishedAt}}</td>
<td><span class="tag {{.Outcome}}">{{.Outcome}}</span>{{if eq .Outcome "succeeded"}}{{if not .InventoryComplete}} <span class="tag not_evaluated">incomplete coverage</span>{{end}}{{end}}</td>
<td>{{if .ErrorClass}}<code>{{.ErrorClass}}</code> <span class="dim">{{.ErrorDetail}}</span>{{end}}</td>
</tr>{{end}}</tbody>
</table></div>{{else}}<p class="dim">None.</p>{{end}}

<h2>Decision log</h2>
{{if .Log}}<div class="scroll"><table>
<thead><tr><th>When</th><th>Who</th><th>Action</th><th>On</th><th>Reason</th></tr></thead>
<tbody>{{range .Log}}<tr><td>{{when .At}}</td><td>{{.Actor}} <span class="dim">({{label .ActorRole}})</span></td><td><code>{{.Action}}</code></td><td>{{label .ObjectType}} {{.ObjectID}}</td><td>{{.Reason}}</td></tr>{{end}}</tbody>
</table></div>{{else}}<p class="dim">None.</p>{{end}}
</body>
</html>
`))

func renderPackageReport(r packageReport) ([]byte, error) {
	var b bytes.Buffer
	if err := reportTemplate.Execute(&b, r); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
