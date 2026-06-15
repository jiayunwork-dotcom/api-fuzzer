package regression

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"api-fuzzer/internal/auth"
	"api-fuzzer/internal/detector"
	"api-fuzzer/internal/types"
)

const (
	defaultTimeout      = 10 * time.Second
	defaultMaxIdleConns = 100
	defaultIdleTimeout  = 90 * time.Second
	defaultTLSTimeout   = 10 * time.Second
)

type RegressionCase struct {
	ID                 string            `json:"id"`
	Method             string            `json:"method"`
	Path               string            `json:"path"`
	Query              string            `json:"query,omitempty"`
	Headers            string            `json:"headers,omitempty"`
	BodyJSON           string            `json:"bodyJson,omitempty"`
	ExpectedAnomalyType types.AnomalyType `json:"expectedAnomalyType"`
}

type RegressionResult int

const (
	RegressionResultFixed   RegressionResult = iota
	RegressionResultUnfixed
	RegressionResultNew
)

func (r RegressionResult) String() string {
	switch r {
	case RegressionResultFixed:
		return "Fixed"
	case RegressionResultUnfixed:
		return "Unfixed"
	case RegressionResultNew:
		return "New"
	default:
		return "Unknown"
	}
}

func SaveRegressionCases(anomalies []*types.Anomaly, filePath string) error {
	cases := make([]*RegressionCase, 0, len(anomalies))

	for _, a := range anomalies {
		if a == nil {
			continue
		}

		rc := &RegressionCase{
			ID:                  a.ID,
			ExpectedAnomalyType: a.Type,
		}

		if a.Request != nil {
			rc.Method = string(a.Request.Method)
			rc.Path = a.Request.URL
			rc.BodyJSON = a.Request.Body

			if len(a.Request.Query) > 0 {
				q := url.Values{}
				for k, v := range a.Request.Query {
					q.Set(k, v)
				}
				rc.Query = q.Encode()
			}

			if len(a.Request.Headers) > 0 {
				headersBytes, err := json.Marshal(a.Request.Headers)
				if err == nil {
					rc.Headers = string(headersBytes)
				}
			}
		}

		if rc.Method == "" && a.APIMethod != "" {
			rc.Method = string(a.APIMethod)
		}
		if rc.Path == "" && a.APIPath != "" {
			rc.Path = a.APIPath
		}

		cases = append(cases, rc)
	}

	data, err := json.MarshalIndent(cases, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal regression cases: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("write regression file: %w", err)
	}

	return nil
}

func LoadRegressionCases(filePath string) ([]*RegressionCase, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read regression file: %w", err)
	}

	var cases []*RegressionCase
	if err := json.Unmarshal(data, &cases); err != nil {
		return nil, fmt.Errorf("parse regression file: %w", err)
	}

	return cases, nil
}

func RunRegression(
	cases []*RegressionCase,
	baseURL string,
	timeout time.Duration,
	authConfigs []*types.AuthConfig,
	authTokens map[string]string,
) ([]*types.Anomaly, map[string]RegressionResult, error) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	client := createHTTPClient(timeout)
	det := detector.NewDetector(types.SeverityInfo)

	var allAnomalies []*types.Anomaly
	results := make(map[string]RegressionResult)

	for _, rc := range cases {
		if rc == nil {
			continue
		}

		req := buildRequestFromCase(rc)
		testCase := buildTestCaseFromRegression(rc, req, authConfigs)
		resp, reqErr := sendRequest(client, req, baseURL, authConfigs, authTokens)

		if reqErr != nil {
			anomaly := &types.Anomaly{
				ID:         fmt.Sprintf("regression-conn-%s", rc.ID),
				TestCaseID: rc.ID,
				Type:       types.AnomalyConnectionError,
				Severity:   types.SeverityHigh,
				Message:    fmt.Sprintf("connection error during regression: %v", reqErr),
				Request:    req,
				Response:   resp,
				APIPath:    rc.Path,
				APIMethod:  types.HTTPMethod(rc.Method),
				Timestamp:  time.Now(),
			}
			allAnomalies = append(allAnomalies, anomaly)

			if rc.ExpectedAnomalyType == types.AnomalyConnectionError {
				results[rc.ID] = RegressionResultUnfixed
			} else {
				results[rc.ID] = RegressionResultNew
			}
			continue
		}

		apiSpec := buildAPISpecFromCase(rc, authConfigs)
		detectedAnomalies, detectErr := det.Detect(testCase, resp, apiSpec)
		if detectErr != nil {
			_ = detectErr
		}

		foundExpected := false
		for _, da := range detectedAnomalies {
			da.TestCaseID = rc.ID
			da.APIPath = rc.Path
			da.APIMethod = types.HTTPMethod(rc.Method)
			allAnomalies = append(allAnomalies, da)

			if da.Type == rc.ExpectedAnomalyType {
				foundExpected = true
			}
		}

		if foundExpected {
			results[rc.ID] = RegressionResultUnfixed
		} else if len(detectedAnomalies) > 0 {
			results[rc.ID] = RegressionResultNew
		} else {
			results[rc.ID] = RegressionResultFixed
		}
	}

	return allAnomalies, results, nil
}

func createHTTPClient(timeout time.Duration) *http.Client {
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

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func buildRequestFromCase(rc *RegressionCase) *types.HTTPRequest {
	req := &types.HTTPRequest{
		Method: types.HTTPMethod(rc.Method),
		URL:    rc.Path,
		Body:   rc.BodyJSON,
	}

	if rc.Query != "" {
		queryMap := make(map[string]string)
		parsed, err := url.ParseQuery(rc.Query)
		if err == nil {
			for k, vals := range parsed {
				if len(vals) > 0 {
					queryMap[k] = vals[0]
				}
			}
		}
		req.Query = queryMap
	}

	if rc.Headers != "" {
		headerMap := make(map[string]string)
		if err := json.Unmarshal([]byte(rc.Headers), &headerMap); err == nil {
			req.Headers = headerMap
		}
	}

	return req
}

func buildTestCaseFromRegression(rc *RegressionCase, req *types.HTTPRequest, authConfigs []*types.AuthConfig) *types.TestCase {
	return &types.TestCase{
		ID:        rc.ID,
		APIPath:   rc.Path,
		APIMethod: types.HTTPMethod(rc.Method),
		Name:      fmt.Sprintf("regression-%s", rc.ID),
		Request:   req,
		Auth:      authConfigs,
		Priority:  1,
		CreatedAt: time.Now(),
	}
}

func buildAPISpecFromCase(rc *RegressionCase, authConfigs []*types.AuthConfig) *types.APISpec {
	return &types.APISpec{
		Path:   rc.Path,
		Method: types.HTTPMethod(rc.Method),
		Auth:   authConfigs,
	}
}

func sendRequest(
	client *http.Client,
	req *types.HTTPRequest,
	baseURL string,
	authConfigs []*types.AuthConfig,
	authTokens map[string]string,
) (*types.HTTPResponse, error) {
	if req.Headers == nil {
		req.Headers = make(map[string]string)
	}
	if req.Query == nil {
		req.Query = make(map[string]string)
	}
	if req.Cookies == nil {
		req.Cookies = make(map[string]string)
	}

	if err := auth.InjectAuth(req, authConfigs, authTokens); err != nil {
		return nil, fmt.Errorf("auth injection failed: %w", err)
	}

	fullURL, err := buildFullURL(req, baseURL)
	if err != nil {
		return nil, fmt.Errorf("build URL failed: %w", err)
	}

	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequest(string(req.Method), fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	if req.Body != "" && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	resp := &types.HTTPResponse{}
	start := time.Now()

	httpResp, doErr := client.Do(httpReq)
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

	resp.Request = req
	return resp, nil
}

func buildFullURL(req *types.HTTPRequest, baseURL string) (string, error) {
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
