package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"sort"
	"time"

	"api-fuzzer/internal/types"
)

const ToolVersion = "1.0.0"
const ToolName = "API Fuzzer"

type Summary struct {
	TotalRequests        int                                `json:"totalRequests"`
	AnomaliesCount       int                                `json:"anomaliesCount"`
	AnomaliesBySeverity  map[types.AnomalySeverity]int      `json:"anomaliesBySeverity"`
	Duration             time.Duration                      `json:"duration"`
	EndpointsTested      int                                `json:"endpointsTested"`
	EndpointsSkipped     int                                `json:"endpointsSkipped"`
}

type EndpointCovered struct {
	Path       string            `json:"path"`
	Method     types.HTTPMethod  `json:"method"`
	Tested     bool              `json:"tested"`
	SkipReason string            `json:"skipReason,omitempty"`
	CaseCount  int               `json:"caseCount"`
}

type Report struct {
	Summary           Summary                 `json:"summary"`
	Anomalies         []*types.Anomaly        `json:"anomalies"`
	EndpointCoverage  []*EndpointCovered      `json:"endpointCoverage"`
	StartedAt         time.Time               `json:"startedAt"`
	FinishedAt        time.Time               `json:"finishedAt"`
	BaseURL           string                  `json:"baseURL"`
	SpecFile          string                  `json:"specFile"`
}

func NewReport(baseURL, specFile string) *Report {
	return &Report{
		Summary: Summary{
			AnomaliesBySeverity: make(map[types.AnomalySeverity]int),
		},
		Anomalies:        make([]*types.Anomaly, 0),
		EndpointCoverage: make([]*EndpointCovered, 0),
		StartedAt:        time.Now(),
		BaseURL:          baseURL,
		SpecFile:         specFile,
	}
}

func (r *Report) AddAnomaly(a *types.Anomaly) {
	r.Anomalies = append(r.Anomalies, a)
}

func (r *Report) SetCoverage(covered []*EndpointCovered) {
	r.EndpointCoverage = covered
}

func (r *Report) Finalize(totalRequests int, duration time.Duration) {
	r.FinishedAt = time.Now()
	r.Summary.TotalRequests = totalRequests
	r.Summary.Duration = duration
	r.Summary.AnomaliesCount = len(r.Anomalies)

	bySeverity := make(map[types.AnomalySeverity]int)
	for _, a := range r.Anomalies {
		bySeverity[a.Severity]++
	}
	r.Summary.AnomaliesBySeverity = bySeverity

	tested := 0
	skipped := 0
	for _, ep := range r.EndpointCoverage {
		if ep.Tested {
			tested++
		} else {
			skipped++
		}
	}
	r.Summary.EndpointsTested = tested
	r.Summary.EndpointsSkipped = skipped
}

func (r *Report) SaveJSON(filePath string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}

type templateData struct {
	Report          *Report
	ToolName        string
	ToolVersion     string
	GeneratedAt     string
	SeverityColors  map[types.AnomalySeverity]string
	SeverityLabels  map[types.AnomalySeverity]string
	GroupedAnomalies map[string][]*types.Anomaly
	AllSeverities   []types.AnomalySeverity
}

func (r *Report) SaveHTML(filePath string) error {
	severityColors := map[types.AnomalySeverity]string{
		types.SeverityCritical: "#dc2626",
		types.SeverityHigh:     "#ea580c",
		types.SeverityMedium:   "#ca8a04",
		types.SeverityLow:      "#2563eb",
		types.SeverityInfo:     "#6b7280",
	}

	severityLabels := map[types.AnomalySeverity]string{
		types.SeverityCritical: "CRITICAL",
		types.SeverityHigh:     "HIGH",
		types.SeverityMedium:   "MEDIUM",
		types.SeverityLow:      "LOW",
		types.SeverityInfo:     "INFO",
	}

	allSeverities := []types.AnomalySeverity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}

	grouped := make(map[string][]*types.Anomaly)
	for _, a := range r.Anomalies {
		key := fmt.Sprintf("%s %s", a.APIMethod, a.APIPath)
		grouped[key] = append(grouped[key], a)
	}

	sortedAnomalies := make([]*types.Anomaly, len(r.Anomalies))
	copy(sortedAnomalies, r.Anomalies)
	sort.Slice(sortedAnomalies, func(i, j int) bool {
		return sortedAnomalies[i].Severity.Compare(sortedAnomalies[j].Severity) > 0
	})
	r.Anomalies = sortedAnomalies

	data := templateData{
		Report:           r,
		ToolName:         ToolName,
		ToolVersion:      ToolVersion,
		GeneratedAt:      time.Now().Format(time.RFC1123),
		SeverityColors:   severityColors,
		SeverityLabels:   severityLabels,
		GroupedAnomalies: grouped,
		AllSeverities:    allSeverities,
	}

	funcMap := template.FuncMap{
		"severityColor": func(s types.AnomalySeverity) string {
			if c, ok := severityColors[s]; ok {
				return c
			}
			return "#6b7280"
		},
		"severityLabel": func(s types.AnomalySeverity) string {
			if l, ok := severityLabels[s]; ok {
				return l
			}
			return string(s)
		},
		"formatDuration": func(d time.Duration) string {
			return d.Round(time.Millisecond).String()
		},
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"methodColor": func(m types.HTTPMethod) string {
			switch m {
			case types.MethodGet:
				return "#16a34a"
			case types.MethodPost:
				return "#2563eb"
			case types.MethodPut:
				return "#ca8a04"
			case types.MethodDelete:
				return "#dc2626"
			case types.MethodPatch:
				return "#9333ea"
			default:
				return "#6b7280"
			}
		},
		"jsonEscape": func(s string) string {
			b, _ := json.Marshal(s)
			return string(b)
		},
		"toJSON": func(v interface{}) string {
			b, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return fmt.Sprintf("%v", v)
			}
			return string(b)
		},
		"coveragePercent": func(tested, skipped int) string {
			total := tested + skipped
			if total == 0 {
				return "0.0"
			}
			return fmt.Sprintf("%.1f", float64(tested)/float64(total)*100)
		},
		"add": func(a, b int) int {
			return a + b
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}
	return nil
}

var htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.ToolName}} Report - {{.Report.BaseURL}}</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }
.container { max-width: 1400px; margin: 0 auto; padding: 24px; }
.header { background: linear-gradient(135deg, #1e293b 0%, #334155 100%); color: white; padding: 32px; border-radius: 12px; margin-bottom: 24px; }
.header h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
.header .subtitle { color: #94a3b8; font-size: 14px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
.card { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid #e2e8f0; }
.card-label { font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; margin-bottom: 8px; }
.card-value { font-size: 32px; font-weight: 700; color: #1e293b; }
.card-sub { font-size: 13px; color: #94a3b8; margin-top: 4px; }
.severity-tags { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.severity-tag { padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; color: white; cursor: pointer; user-select: none; transition: transform 0.1s, box-shadow 0.1s; border: none; }
.severity-tag:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
.severity-tag.active { outline: 3px solid rgba(255,255,255,0.3); outline-offset: 2px; }
.severity-tag.disabled { opacity: 0.35; }
.section { background: white; border-radius: 10px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid #e2e8f0; }
.section h2 { font-size: 20px; font-weight: 700; margin-bottom: 16px; color: #1e293b; display: flex; align-items: center; gap: 8px; }
.section h2::before { content: ''; width: 4px; height: 24px; background: #3b82f6; border-radius: 2px; }
.filter-bar { display: flex; align-items: center; gap: 16px; margin-bottom: 16px; padding: 12px 16px; background: #f1f5f9; border-radius: 8px; flex-wrap: wrap; }
.filter-bar label { font-size: 13px; font-weight: 600; color: #475569; }
.filter-bar .group-toggle { display: flex; gap: 8px; margin-left: auto; }
.btn { padding: 8px 16px; border-radius: 6px; border: 1px solid #cbd5e1; background: white; font-size: 13px; font-weight: 600; cursor: pointer; color: #475569; transition: all 0.15s; }
.btn:hover { background: #f8fafc; }
.btn.active { background: #3b82f6; color: white; border-color: #3b82f6; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; color: white; text-transform: uppercase; letter-spacing: 0.3px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #e2e8f0; }
th { background: #f8fafc; font-weight: 600; color: #475569; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; position: sticky; top: 0; }
tr:hover { background: #f8fafc; }
tr.hidden { display: none; }
.method-badge { display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; color: white; text-transform: uppercase; }
.expand-btn { background: none; border: 1px solid #cbd5e1; border-radius: 4px; padding: 4px 12px; cursor: pointer; font-size: 12px; font-weight: 600; color: #475569; transition: all 0.15s; }
.expand-btn:hover { background: #f1f5f9; border-color: #94a3b8; }
.detail-row { background: #fafbfc; }
.detail-row td { padding: 20px 24px; border-bottom: 2px solid #e2e8f0; }
.detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.detail-grid .full { grid-column: 1 / -1; }
.detail-block { background: white; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }
.detail-block-header { padding: 10px 16px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; font-weight: 600; font-size: 13px; color: #334155; display: flex; justify-content: space-between; align-items: center; }
.detail-block-body { padding: 12px 16px; }
code, pre { font-family: 'Monaco', 'Menlo', 'Courier New', monospace; font-size: 12px; }
pre { background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 6px; overflow-x: auto; max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-wrap: break-word; }
code.inline { background: #f1f5f9; padding: 2px 6px; border-radius: 4px; color: #be185d; }
.group-header { background: #f1f5f9 !important; cursor: pointer; user-select: none; }
.group-header td { font-weight: 600; color: #334155; }
.group-header:hover { background: #e2e8f0 !important; }
.group-indicator { display: inline-block; width: 16px; transition: transform 0.2s; }
.group-indicator.collapsed { transform: rotate(-90deg); }
.status-code { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 12px; }
.status-2xx { background: #dcfce7; color: #166534; }
.status-4xx { background: #fef9c3; color: #854d0e; }
.status-5xx { background: #fee2e2; color: #991b1b; }
.status-other { background: #e0e7ff; color: #3730a3; }
.footer { text-align: center; padding: 24px; color: #94a3b8; font-size: 13px; }
.footer strong { color: #64748b; }
.empty { text-align: center; padding: 48px 24px; color: #94a3b8; }
.empty-icon { font-size: 48px; margin-bottom: 12px; opacity: 0.5; }
.progress-bar { height: 8px; background: #e2e8f0; border-radius: 9999px; overflow: hidden; margin-top: 8px; }
.progress-fill { height: 100%; background: linear-gradient(90deg, #10b981, #3b82f6); border-radius: 9999px; transition: width 0.5s; }
.error-list { list-style: none; }
.error-list li { padding: 8px 12px; background: #fef2f2; border-left: 3px solid #dc2626; margin-bottom: 6px; border-radius: 0 4px 4px 0; font-size: 13px; }
.error-list li .err-path { font-family: monospace; color: #991b1b; font-weight: 600; }
.leak-list { list-style: none; }
.leak-list li { padding: 8px 12px; background: #fff7ed; border-left: 3px solid #ea580c; margin-bottom: 6px; border-radius: 0 4px 4px 0; font-size: 13px; }
.leak-list li .leak-name { font-weight: 600; color: #9a3412; }
.leak-matches { margin-top: 4px; display: flex; flex-wrap: wrap; gap: 4px; }
.leak-match { background: white; border: 1px solid #fdba74; padding: 2px 8px; border-radius: 4px; font-family: monospace; font-size: 11px; color: #92400e; }
.description-text { padding: 12px 16px; background: #f0f9ff; border: 1px solid #bae6fd; border-radius: 6px; color: #0c4a6e; font-size: 14px; }
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1>{{.ToolName}} Security Report</h1>
  <div class="subtitle">
    Target: <strong>{{.Report.BaseURL}}</strong> | Spec: <strong>{{.Report.SpecFile}}</strong> | 
    Started: <strong>{{formatTime .Report.StartedAt}}</strong>
  </div>
  <div class="severity-tags">
    {{range $sev := .AllSeverities}}
      {{$count := index $.Report.Summary.AnomaliesBySeverity $sev}}
      <button class="severity-tag active" data-severity="{{$sev}}" style="background: {{severityColor $sev}};" onclick="toggleSeverity('{{$sev}}')">
        {{severityLabel $sev}}: {{$count}}
      </button>
    {{end}}
  </div>
</div>

<div class="cards">
  <div class="card">
    <div class="card-label">Total Requests</div>
    <div class="card-value">{{.Report.Summary.TotalRequests}}</div>
    <div class="card-sub">requests sent</div>
  </div>
  <div class="card">
    <div class="card-label">Anomalies Found</div>
    <div class="card-value" style="color: #dc2626;">{{.Report.Summary.AnomaliesCount}}</div>
    <div class="card-sub">potential issues</div>
  </div>
  <div class="card">
    <div class="card-label">Test Duration</div>
    <div class="card-value" style="font-size: 24px;">{{formatDuration .Report.Summary.Duration}}</div>
    <div class="card-sub">elapsed time</div>
  </div>
  <div class="card">
    <div class="card-label">Endpoint Coverage</div>
    <div class="card-value">{{coveragePercent .Report.Summary.EndpointsTested .Report.Summary.EndpointsSkipped}}%</div>
    <div class="card-sub">{{.Report.Summary.EndpointsTested}} tested / {{.Report.Summary.EndpointsSkipped}} skipped</div>
    <div class="progress-bar"><div class="progress-fill" style="width: {{coveragePercent .Report.Summary.EndpointsTested .Report.Summary.EndpointsSkipped}}%;"></div></div>
  </div>
</div>

<div class="section">
  <h2>Anomalies</h2>
  <div class="filter-bar">
    <label>Filter by severity:</label>
    <div class="severity-tags" style="margin-top: 0;">
      {{range $sev := .AllSeverities}}
        {{$count := index $.Report.Summary.AnomaliesBySeverity $sev}}
        <button class="severity-tag active filter-btn" data-severity="{{$sev}}" style="background: {{severityColor $sev}};" onclick="toggleSeverity('{{$sev}}')">
          {{severityLabel $sev}}
        </button>
      {{end}}
    </div>
    <div class="group-toggle">
      <button class="btn" id="viewFlat" onclick="setView('flat')">Flat View</button>
      <button class="btn active" id="viewGrouped" onclick="setView('grouped')">Group by Endpoint</button>
    </div>
  </div>

  {{if .Report.Anomalies}}
  <div style="overflow-x: auto;">
  <table id="anomaliesTableFlat">
    <thead>
      <tr>
        <th>ID</th>
        <th>Type</th>
        <th>Severity</th>
        <th>Path</th>
        <th>Method</th>
        <th>Timestamp</th>
        <th>Action</th>
      </tr>
    </thead>
    <tbody>
    {{range $i, $a := .Report.Anomalies}}
      <tr data-severity="{{$a.Severity}}" data-id="{{$a.ID}}">
        <td><code class="inline">{{$a.ID}}</code></td>
        <td style="font-weight: 600;">{{$a.Type}}</td>
        <td><span class="badge" style="background: {{severityColor $a.Severity}};">{{severityLabel $a.Severity}}</span></td>
        <td><code class="inline">{{$a.APIPath}}</code></td>
        <td><span class="method-badge" style="background: {{methodColor $a.APIMethod}};">{{$a.APIMethod}}</span></td>
        <td style="color: #64748b; font-size: 12px;">{{formatTime $a.Timestamp}}</td>
        <td><button class="expand-btn" onclick="toggleDetail('{{$a.ID}}')" id="btn-{{$a.ID}}">Details ▼</button></td>
      </tr>
      <tr class="detail-row hidden" id="detail-{{$a.ID}}" data-severity="{{$a.Severity}}">
        <td colspan="7">
          <div class="detail-grid">
            <div class="detail-block">
              <div class="detail-block-header">Request (cURL)</div>
              <div class="detail-block-body">
                <pre>{{$a.MinimalCurl}}</pre>
              </div>
            </div>
            <div class="detail-block">
              <div class="detail-block-header">
                Response
                {{if $a.Response}}
                <span class="status-code {{if and (ge $a.Response.StatusCode 200) (lt $a.Response.StatusCode 300)}}status-2xx{{else if and (ge $a.Response.StatusCode 400) (lt $a.Response.StatusCode 500)}}status-4xx{{else if and (ge $a.Response.StatusCode 500) (lt $a.Response.StatusCode 600)}}status-5xx{{else}}status-other{{end}}">
                  {{$a.Response.StatusCode}}
                </span>
                {{end}}
              </div>
              <div class="detail-block-body">
                {{if $a.Response}}
                <pre>{{if $a.Response.Body}}{{$a.Response.Body}}{{else}}(empty body){{end}}</pre>
                {{else}}
                <div class="empty" style="padding: 24px;">No response data</div>
                {{end}}
              </div>
            </div>
            <div class="detail-block full">
              <div class="detail-block-header">Anomaly Description</div>
              <div class="detail-block-body">
                <div class="description-text">
                  <strong>{{$a.Message}}</strong>
                  {{if $a.Description}}<br><br>{{$a.Description}}{{end}}
                </div>
              </div>
            </div>
            {{if $a.SchemaErrors}}
            <div class="detail-block full">
              <div class="detail-block-header">Schema Validation Errors ({{len $a.SchemaErrors}})</div>
              <div class="detail-block-body">
                <ul class="error-list">
                  {{range $e := $a.SchemaErrors}}
                  <li><span class="err-path">[{{$e.Path}}]</span> {{$e.Message}}</li>
                  {{end}}
                </ul>
              </div>
            </div>
            {{end}}
            {{if $a.LeakPatterns}}
            <div class="detail-block full">
              <div class="detail-block-header">Sensitive Information Leaks ({{len $a.LeakPatterns}})</div>
              <div class="detail-block-body">
                <ul class="leak-list">
                  {{range $lp := $a.LeakPatterns}}
                  <li>
                    <span class="leak-name">{{$lp.Name}}</span>
                    {{if $lp.Matches}}
                    <div class="leak-matches">
                      {{range $m := $lp.Matches}}<span class="leak-match">{{$m}}</span>{{end}}
                    </div>
                    {{end}}
                  </li>
                  {{end}}
                </ul>
              </div>
            </div>
            {{end}}
            {{if $a.Request}}
            <div class="detail-block full">
              <div class="detail-block-header">Full Request Details</div>
              <div class="detail-block-body">
                <pre>{{toJSON $a.Request}}</pre>
              </div>
            </div>
            {{end}}
          </div>
        </td>
      </tr>
    {{end}}
    </tbody>
  </table>

  <table id="anomaliesTableGrouped" style="display: none;">
    <thead>
      <tr>
        <th style="width: 20px;"></th>
        <th>Endpoint</th>
        <th>Method</th>
        <th>Anomalies</th>
        <th>Critical</th>
        <th>High</th>
        <th>Medium</th>
        <th>Low</th>
        <th>Info</th>
      </tr>
    </thead>
    <tbody>
    {{range $key, $anomalies := .GroupedAnomalies}}
      {{$first := index $anomalies 0}}
      {{$critical := 0}}{{$high := 0}}{{$medium := 0}}{{$low := 0}}{{$info := 0}}
      {{range $a := $anomalies}}
        {{if eq $a.Severity "critical"}}{{$critical = add $critical 1}}{{end}}
        {{if eq $a.Severity "high"}}{{$high = add $high 1}}{{end}}
        {{if eq $a.Severity "medium"}}{{$medium = add $medium 1}}{{end}}
        {{if eq $a.Severity "low"}}{{$low = add $low 1}}{{end}}
        {{if eq $a.Severity "info"}}{{$info = add $info 1}}{{end}}
      {{end}}
      <tr class="group-header" onclick="toggleGroup('{{$key}}')">
        <td><span class="group-indicator" id="gi-{{$key}}">▼</span></td>
        <td><code class="inline">{{$first.APIPath}}</code></td>
        <td><span class="method-badge" style="background: {{methodColor $first.APIMethod}};">{{$first.APIMethod}}</span></td>
        <td style="font-weight: 600;">{{len $anomalies}}</td>
        <td>{{if $critical}}<span class="badge" style="background: {{severityColor "critical"}};">{{$critical}}</span>{{end}}</td>
        <td>{{if $high}}<span class="badge" style="background: {{severityColor "high"}};">{{$high}}</span>{{end}}</td>
        <td>{{if $medium}}<span class="badge" style="background: {{severityColor "medium"}};">{{$medium}}</span>{{end}}</td>
        <td>{{if $low}}<span class="badge" style="background: {{severityColor "low"}};">{{$low}}</span>{{end}}</td>
        <td>{{if $info}}<span class="badge" style="background: {{severityColor "info"}};">{{$info}}</span>{{end}}</td>
      </tr>
      {{range $a := $anomalies}}
      <tr data-group="{{$key}}" data-severity="{{$a.Severity}}" data-id="g-{{$a.ID}}">
        <td></td>
        <td colspan="2" style="padding-left: 40px;"><code class="inline">{{$a.ID}}</code> · <strong>{{$a.Type}}</strong></td>
        <td colspan="5"><span class="badge" style="background: {{severityColor $a.Severity}};">{{severityLabel $a.Severity}}</span> {{$a.Message}}</td>
        <td><button class="expand-btn" onclick="toggleDetail('g-{{$a.ID}}')" id="btn-g-{{$a.ID}}">Details ▼</button></td>
      </tr>
      <tr class="detail-row hidden" id="detail-g-{{$a.ID}}" data-group="{{$key}}" data-severity="{{$a.Severity}}">
        <td colspan="9" style="padding-left: 40px;">
          <div class="detail-grid">
            <div class="detail-block">
              <div class="detail-block-header">Request (cURL)</div>
              <div class="detail-block-body"><pre>{{$a.MinimalCurl}}</pre></div>
            </div>
            <div class="detail-block">
              <div class="detail-block-header">
                Response
                {{if $a.Response}}
                <span class="status-code {{if and (ge $a.Response.StatusCode 200) (lt $a.Response.StatusCode 300)}}status-2xx{{else if and (ge $a.Response.StatusCode 400) (lt $a.Response.StatusCode 500)}}status-4xx{{else if and (ge $a.Response.StatusCode 500) (lt $a.Response.StatusCode 600)}}status-5xx{{else}}status-other{{end}}">
                  {{$a.Response.StatusCode}}
                </span>
                {{end}}
              </div>
              <div class="detail-block-body">
                {{if $a.Response}}
                <pre>{{if $a.Response.Body}}{{$a.Response.Body}}{{else}}(empty body){{end}}</pre>
                {{else}}
                <div class="empty" style="padding: 24px;">No response data</div>
                {{end}}
              </div>
            </div>
            <div class="detail-block full">
              <div class="detail-block-header">Anomaly Description</div>
              <div class="detail-block-body">
                <div class="description-text"><strong>{{$a.Message}}</strong>{{if $a.Description}}<br><br>{{$a.Description}}{{end}}</div>
              </div>
            </div>
            {{if $a.SchemaErrors}}
            <div class="detail-block full">
              <div class="detail-block-header">Schema Validation Errors ({{len $a.SchemaErrors}})</div>
              <div class="detail-block-body">
                <ul class="error-list">
                  {{range $e := $a.SchemaErrors}}<li><span class="err-path">[{{$e.Path}}]</span> {{$e.Message}}</li>{{end}}
                </ul>
              </div>
            </div>
            {{end}}
            {{if $a.LeakPatterns}}
            <div class="detail-block full">
              <div class="detail-block-header">Sensitive Information Leaks ({{len $a.LeakPatterns}})</div>
              <div class="detail-block-body">
                <ul class="leak-list">
                  {{range $lp := $a.LeakPatterns}}
                  <li>
                    <span class="leak-name">{{$lp.Name}}</span>
                    {{if $lp.Matches}}
                    <div class="leak-matches">
                      {{range $m := $lp.Matches}}<span class="leak-match">{{$m}}</span>{{end}}
                    </div>
                    {{end}}
                  </li>
                  {{end}}
                </ul>
              </div>
            </div>
            {{end}}
          </div>
        </td>
      </tr>
      {{end}}
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}
  <div class="empty">
    <div class="empty-icon">✓</div>
    <strong>No anomalies detected</strong><br>
    All requests completed without detecting issues.
  </div>
  {{end}}
</div>

<div class="section">
  <h2>Endpoint Coverage</h2>
  <div style="overflow-x: auto;">
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Path</th>
        <th>Method</th>
        <th>Status</th>
        <th>Test Cases</th>
        <th>Skip Reason</th>
      </tr>
    </thead>
    <tbody>
    {{range $i, $ep := .Report.EndpointCoverage}}
      <tr>
        <td>{{add $i 1}}</td>
        <td><code class="inline">{{$ep.Path}}</code></td>
        <td><span class="method-badge" style="background: {{methodColor $ep.Method}};">{{$ep.Method}}</span></td>
        <td>
          {{if $ep.Tested}}
          <span class="badge" style="background: #16a34a;">TESTED</span>
          {{else}}
          <span class="badge" style="background: #94a3b8;">SKIPPED</span>
          {{end}}
        </td>
        <td style="font-weight: 600;">{{$ep.CaseCount}}</td>
        <td style="color: #64748b;">{{if $ep.SkipReason}}{{$ep.SkipReason}}{{else}}—{{end}}</td>
      </tr>
    {{else}}
      <tr><td colspan="6" class="empty">No endpoint data available</td></tr>
    {{end}}
    </tbody>
  </table>
  </div>
</div>

<div class="footer">
  Generated by <strong>{{.ToolName}} v{{.ToolVersion}}</strong> · {{.GeneratedAt}}
</div>

</div>

<script>
var activeSeverities = new Set(['critical', 'high', 'medium', 'low', 'info']);
var currentView = 'grouped';
var collapsedGroups = new Set();

function toggleSeverity(sev) {
  if (activeSeverities.has(sev)) {
    activeSeverities.delete(sev);
  } else {
    activeSeverities.add(sev);
  }
  applyFilters();
  updateTagStyles();
}

function updateTagStyles() {
  document.querySelectorAll('.severity-tag').forEach(function(tag) {
    var s = tag.getAttribute('data-severity');
    if (activeSeverities.has(s)) {
      tag.classList.add('active');
      tag.classList.remove('disabled');
    } else {
      tag.classList.remove('active');
      tag.classList.add('disabled');
    }
  });
}

function applyFilters() {
  document.querySelectorAll('#anomaliesTableFlat tbody tr').forEach(function(tr) {
    var sev = tr.getAttribute('data-severity');
    if (!sev) return;
    if (activeSeverities.has(sev)) {
      tr.classList.remove('hidden');
    } else {
      tr.classList.add('hidden');
    }
  });

  document.querySelectorAll('#anomaliesTableGrouped tbody tr').forEach(function(tr) {
    var sev = tr.getAttribute('data-severity');
    var isGroupHeader = tr.classList.contains('group-header');
    var group = tr.getAttribute('data-group');

    if (isGroupHeader) {
      var groupRows = document.querySelectorAll('#anomaliesTableGrouped tbody tr[data-group="' + group + '"]');
      var anyVisible = false;
      groupRows.forEach(function(gr) {
        var gs = gr.getAttribute('data-severity');
        if (gs && activeSeverities.has(gs)) anyVisible = true;
      });
      if (anyVisible) {
        tr.classList.remove('hidden');
      } else {
        tr.classList.add('hidden');
      }
    } else {
      if (sev && !activeSeverities.has(sev)) {
        tr.classList.add('hidden');
      } else if (group && collapsedGroups.has(group)) {
        tr.classList.add('hidden');
      } else if (sev) {
        tr.classList.remove('hidden');
      }
    }
  });
}

function setView(view) {
  currentView = view;
  document.getElementById('viewFlat').classList.toggle('active', view === 'flat');
  document.getElementById('viewGrouped').classList.toggle('active', view === 'grouped');
  document.getElementById('anomaliesTableFlat').style.display = view === 'flat' ? '' : 'none';
  document.getElementById('anomaliesTableGrouped').style.display = view === 'grouped' ? '' : 'none';
}

function toggleDetail(id) {
  var row = document.getElementById('detail-' + id);
  var btn = document.getElementById('btn-' + id);
  if (row.classList.contains('hidden')) {
    row.classList.remove('hidden');
    btn.textContent = 'Details ▲';
  } else {
    row.classList.add('hidden');
    btn.textContent = 'Details ▼';
  }
}

function toggleGroup(key) {
  if (collapsedGroups.has(key)) {
    collapsedGroups.delete(key);
    document.getElementById('gi-' + key).classList.remove('collapsed');
  } else {
    collapsedGroups.add(key);
    document.getElementById('gi-' + key).classList.add('collapsed');
  }
  applyFilters();
}
</script>
</body>
</html>`
