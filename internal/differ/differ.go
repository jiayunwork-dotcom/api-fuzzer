package differ

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"api-fuzzer/internal/types"
)

const (
	defaultTimeDiffThreshold = 2 * time.Second
	defaultTimeout           = 10 * time.Second
	defaultMaxIdleConns      = 100
	defaultIdleTimeout       = 90 * time.Second
	defaultTLSTimeout        = 10 * time.Second
)

type Differ struct {
	primaryURL       string
	secondaryURL     string
	timeDiffThreshold time.Duration
	bodyDiffCheck    bool
	client           *http.Client
}

func NewDiffer(primary, secondary string, threshold time.Duration, bodyCheck bool, timeout time.Duration) *Differ {
	if threshold <= 0 {
		threshold = defaultTimeDiffThreshold
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        defaultMaxIdleConns,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     defaultIdleTimeout,
		TLSHandshakeTimeout: defaultTLSTimeout,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}

	_ = http2.ConfigureTransport(transport)

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &Differ{
		primaryURL:        primary,
		secondaryURL:      secondary,
		timeDiffThreshold: threshold,
		bodyDiffCheck:     bodyCheck,
		client:            client,
	}
}

func (d *Differ) RunDiff(testCases []*types.TestCase) ([]*types.Anomaly, error) {
	var anomalies []*types.Anomaly

	for _, tc := range testCases {
		if tc == nil || tc.Request == nil {
			continue
		}

		resp1, err1 := d.sendRequest(tc.Request, d.primaryURL)
		resp2, err2 := d.sendRequest(tc.Request, d.secondaryURL)

		if err1 != nil && resp1 == nil {
			resp1 = &types.HTTPResponse{
				Error: err1.Error(),
			}
		}
		if err2 != nil && resp2 == nil {
			resp2 = &types.HTTPResponse{
				Error: err2.Error(),
			}
		}

		caseAnomalies := d.compareResponses(tc, resp1, resp2)
		anomalies = append(anomalies, caseAnomalies...)
	}

	return anomalies, nil
}

func (d *Differ) sendRequest(req *types.HTTPRequest, baseURL string) (*types.HTTPResponse, error) {
	requestCopy := *req
	if requestCopy.Headers == nil {
		requestCopy.Headers = make(map[string]string)
	}
	if requestCopy.Query == nil {
		requestCopy.Query = make(map[string]string)
	}

	fullURL, err := d.buildURL(&requestCopy, baseURL)
	if err != nil {
		return nil, fmt.Errorf("build URL failed: %w", err)
	}

	var bodyReader io.Reader
	if requestCopy.Body != "" {
		bodyReader = strings.NewReader(requestCopy.Body)
	}

	httpReq, err := http.NewRequest(string(requestCopy.Method), fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	for k, v := range requestCopy.Headers {
		httpReq.Header.Set(k, v)
	}
	if requestCopy.Body != "" && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	resp := &types.HTTPResponse{}
	start := time.Now()

	httpResp, doErr := d.client.Do(httpReq)
	elapsed := time.Since(start)
	resp.Duration = elapsed

	if doErr != nil {
		resp.Error = doErr.Error()
		if tErr, ok := doErr.(interface{ Timeout() bool }); ok && tErr.Timeout() {
			resp.IsTimeout = true
		} else if uErr, ok := doErr.(*url.Error); ok && uErr.Timeout() {
			resp.IsTimeout = true
		}
		return resp, nil
	}
	defer httpResp.Body.Close()

	resp.StatusCode = httpResp.StatusCode
	resp.Headers = make(map[string]string)
	for k, vals := range httpResp.Header {
		if len(vals) > 0 {
			resp.Headers[k] = strings.Join(vals, ", ")
		}
	}

	bodyBytes, readErr := io.ReadAll(httpResp.Body)
	if readErr != nil {
		resp.Error = readErr.Error()
	} else {
		resp.Body = string(bodyBytes)
		resp.BodyBytes = bodyBytes
	}

	return resp, nil
}

func (d *Differ) buildURL(req *types.HTTPRequest, baseURL string) (string, error) {
	rawURL := req.URL
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		if baseURL != "" {
			base := strings.TrimRight(baseURL, "/")
			path := rawURL
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			rawURL = base + path
		}
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	if len(req.Query) > 0 {
		q := parsed.Query()
		for k, v := range req.Query {
			q.Set(k, v)
		}
		parsed.RawQuery = q.Encode()
	}

	return parsed.String(), nil
}

func (d *Differ) compareResponses(tc *types.TestCase, resp1, resp2 *types.HTTPResponse) []*types.Anomaly {
	var anomalies []*types.Anomaly

	if resp1.StatusCode != resp2.StatusCode {
		anomaly := &types.Anomaly{
			ID:         fmt.Sprintf("diff-status-%s", tc.ID),
			TestCaseID: tc.ID,
			Type:       types.AnomalyDifferStatus,
			Severity:   types.SeverityMedium,
			Message:    fmt.Sprintf("Status code mismatch: %d vs %d", resp1.StatusCode, resp2.StatusCode),
			Description: fmt.Sprintf("Primary returned %d, secondary returned %d for %s %s",
				resp1.StatusCode, resp2.StatusCode, tc.APIMethod, tc.APIPath),
			Request:    tc.Request,
			Response:   resp1,
			Response2:  resp2,
			APIPath:    tc.APIPath,
			APIMethod:  tc.APIMethod,
			Timestamp:  time.Now(),
		}
		anomalies = append(anomalies, anomaly)
	}

	if d.bodyDiffCheck {
		bodyDiffs := diffJSONBody(resp1.Body, resp2.Body)
		if len(bodyDiffs) > 0 {
			anomaly := &types.Anomaly{
				ID:         fmt.Sprintf("diff-body-%s", tc.ID),
				TestCaseID: tc.ID,
				Type:       types.AnomalyDifferBody,
				Severity:   types.SeverityLow,
				Message:    fmt.Sprintf("Body structure mismatch: %d differences", len(bodyDiffs)),
				Description: fmt.Sprintf("JSON body differences:\n%s", strings.Join(bodyDiffs, "\n")),
				Request:    tc.Request,
				Response:   resp1,
				Response2:  resp2,
				APIPath:    tc.APIPath,
				APIMethod:  tc.APIMethod,
				Timestamp:  time.Now(),
			}
			anomalies = append(anomalies, anomaly)
		}
	}

	timeDiff := resp1.Duration - resp2.Duration
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff > d.timeDiffThreshold {
		anomaly := &types.Anomaly{
			ID:         fmt.Sprintf("diff-time-%s", tc.ID),
			TestCaseID: tc.ID,
			Type:       types.AnomalyDifferTime,
			Severity:   types.SeverityInfo,
			Message:    fmt.Sprintf("Response time difference exceeds threshold: %v vs %v", resp1.Duration, resp2.Duration),
			Description: fmt.Sprintf("Primary: %v, Secondary: %v, Difference: %v, Threshold: %v",
				resp1.Duration, resp2.Duration, timeDiff, d.timeDiffThreshold),
			Request:    tc.Request,
			Response:   resp1,
			Response2:  resp2,
			APIPath:    tc.APIPath,
			APIMethod:  tc.APIMethod,
			Timestamp:  time.Now(),
		}
		anomalies = append(anomalies, anomaly)
	}

	return anomalies
}

func diffJSONBody(a, b string) []string {
	var objA, objB interface{}

	isEmptyA := strings.TrimSpace(a) == ""
	isEmptyB := strings.TrimSpace(b) == ""

	if isEmptyA && isEmptyB {
		return nil
	}
	if isEmptyA != isEmptyB {
		return []string{"$: one body is empty, other is not"}
	}

	errA := json.Unmarshal([]byte(a), &objA)
	errB := json.Unmarshal([]byte(b), &objB)

	if errA != nil && errB != nil {
		return nil
	}
	if errA != nil || errB != nil {
		return []string{"$: one body is valid JSON, other is not"}
	}

	var diffs []string
	diffValues(objA, objB, "$", &diffs)
	return diffs
}

func diffValues(a, b interface{}, path string, diffs *[]string) {
	if a == nil && b == nil {
		return
	}
	if a == nil || b == nil {
		*diffs = append(*diffs, fmt.Sprintf("%s: null vs non-null", path))
		return
	}

	typeA := fmt.Sprintf("%T", a)
	typeB := fmt.Sprintf("%T", b)
	if typeA != typeB {
		*diffs = append(*diffs, fmt.Sprintf("%s: type mismatch %s vs %s", path, typeA, typeB))
		return
	}

	switch va := a.(type) {
	case map[string]interface{}:
		vb := b.(map[string]interface{})
		diffObjects(va, vb, path, diffs)
	case []interface{}:
		vb := b.([]interface{})
		diffArrays(va, vb, path, diffs)
	case float64:
		vb := b.(float64)
		if va != vb {
			*diffs = append(*diffs, fmt.Sprintf("%s: value mismatch %v vs %v", path, va, vb))
		}
	case bool:
		vb := b.(bool)
		if va != vb {
			*diffs = append(*diffs, fmt.Sprintf("%s: value mismatch %v vs %v", path, va, vb))
		}
	case string:
		vb := b.(string)
		if va != vb {
			*diffs = append(*diffs, fmt.Sprintf("%s: value mismatch", path))
		}
	case json.Number:
		vb := b.(json.Number)
		if va.String() != vb.String() {
			*diffs = append(*diffs, fmt.Sprintf("%s: value mismatch %s vs %s", path, va.String(), vb.String()))
		}
	default:
		if fmt.Sprintf("%v", a) != fmt.Sprintf("%v", b) {
			*diffs = append(*diffs, fmt.Sprintf("%s: value mismatch", path))
		}
	}
}

func diffObjects(a, b map[string]interface{}, path string, diffs *[]string) {
	for key := range a {
		subPath := path + "." + key
		if _, exists := b[key]; !exists {
			*diffs = append(*diffs, fmt.Sprintf("%s: field missing in secondary", subPath))
			continue
		}
		diffValues(a[key], b[key], subPath, diffs)
	}
	for key := range b {
		subPath := path + "." + key
		if _, exists := a[key]; !exists {
			*diffs = append(*diffs, fmt.Sprintf("%s: field missing in primary", subPath))
		}
	}
}

func diffArrays(a, b []interface{}, path string, diffs *[]string) {
	if len(a) != len(b) {
		*diffs = append(*diffs, fmt.Sprintf("%s: array length mismatch %d vs %d", path, len(a), len(b)))
	}

	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}

	for i := 0; i < minLen; i++ {
		subPath := fmt.Sprintf("%s[%d]", path, i)
		diffValues(a[i], b[i], subPath, diffs)
	}
}
