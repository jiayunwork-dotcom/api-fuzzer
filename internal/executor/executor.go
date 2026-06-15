package executor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/time/rate"

	"api-fuzzer/internal/auth"
	"api-fuzzer/internal/detector"
	"api-fuzzer/internal/progress"
	"api-fuzzer/internal/types"
)

const (
	defaultConcurrency  = 10
	maxConcurrency      = 100
	defaultTimeout      = 10 * time.Second
	saveInterval        = 50
	shutdownTimeout     = 30 * time.Second
	defaultMaxIdleConns = 100
	defaultIdleTimeout  = 90 * time.Second
	defaultTLSTimeout   = 10 * time.Second
)

type ExecutorConfig struct {
	Concurrency int
	RateLimit   int
	Timeout     time.Duration
	BaseURL     string
	AuthTokens  map[string]string
}

type stateFileData struct {
	CompletedIDs []string  `json:"completedIds"`
	SavedAt      time.Time `json:"savedAt"`
}

type Executor struct {
	config      *ExecutorConfig
	client      *http.Client
	semaphore   chan struct{}
	rateLimiter *rate.Limiter
	progress    *progress.ProgressBar
	detector    *detector.Detector
	stateFile   string

	mu            sync.Mutex
	anomalies     []*types.Anomaly
	completedIDs  map[string]struct{}
	completedList []string
}

func NewExecutor(cfg *ExecutorConfig) (*Executor, error) {
	if cfg == nil {
		cfg = &ExecutorConfig{}
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = defaultConcurrency
	}
	if cfg.Concurrency > maxConcurrency {
		cfg.Concurrency = maxConcurrency
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        defaultMaxIdleConns,
		MaxIdleConnsPerHost: cfg.Concurrency * 2,
		IdleConnTimeout:     defaultIdleTimeout,
		TLSHandshakeTimeout: defaultTLSTimeout,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, fmt.Errorf("configure http2 transport: %w", err)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var limiter *rate.Limiter
	if cfg.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateLimit)
	} else {
		limiter = rate.NewLimiter(rate.Inf, 0)
	}

	return &Executor{
		config:       cfg,
		client:       client,
		semaphore:    make(chan struct{}, cfg.Concurrency),
		rateLimiter:  limiter,
		completedIDs: make(map[string]struct{}),
	}, nil
}

func (e *Executor) SetProgressBar(pb *progress.ProgressBar) {
	e.progress = pb
}

func (e *Executor) SetDetector(d *detector.Detector) {
	e.detector = d
}

func (e *Executor) SetStateFile(path string) {
	e.stateFile = path
}

func (e *Executor) loadState() error {
	if e.stateFile == "" {
		return nil
	}
	data, err := os.ReadFile(e.stateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read state file: %w", err)
	}
	var sf stateFileData
	if err := json.Unmarshal(data, &sf); err != nil {
		return fmt.Errorf("parse state file: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, id := range sf.CompletedIDs {
		e.completedIDs[id] = struct{}{}
	}
	e.completedList = append(e.completedList, sf.CompletedIDs...)
	return nil
}

func (e *Executor) saveState() error {
	if e.stateFile == "" {
		return nil
	}
	e.mu.Lock()
	ids := make([]string, len(e.completedList))
	copy(ids, e.completedList)
	e.mu.Unlock()

	sf := stateFileData{
		CompletedIDs: ids,
		SavedAt:      time.Now(),
	}
	data, err := json.MarshalIndent(&sf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	if err := os.WriteFile(e.stateFile, data, 0644); err != nil {
		return fmt.Errorf("write state file: %w", err)
	}
	return nil
}

func (e *Executor) markCompleted(id string) {
	e.mu.Lock()
	if _, ok := e.completedIDs[id]; !ok {
		e.completedIDs[id] = struct{}{}
		e.completedList = append(e.completedList, id)
	}
	e.mu.Unlock()
}

func (e *Executor) isCompleted(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.completedIDs[id]
	return ok
}

func (e *Executor) addAnomaly(a *types.Anomaly) {
	e.mu.Lock()
	e.anomalies = append(e.anomalies, a)
	e.mu.Unlock()
	if e.progress != nil {
		e.progress.AddAnomaly()
	}
}

func (e *Executor) Run(
	ctx context.Context,
	testCases []*types.TestCase,
	anomalyCallback func(*types.TestCase, *types.HTTPResponse, []*types.Anomaly),
) ([]*types.Anomaly, error) {
	if err := e.loadState(); err != nil {
		return nil, err
	}

	var pending []*types.TestCase
	for _, tc := range testCases {
		if tc == nil {
			continue
		}
		if !e.isCompleted(tc.ID) {
			pending = append(pending, tc)
		}
	}

	total := len(pending)
	if e.progress != nil && total != e.progress.Total {
		e.progress.Total = total
	}

	var wg sync.WaitGroup
	var saveCounter int64
	var cancelled int32

	ctxWithCancel, cancelFn := context.WithCancel(ctx)
	defer cancelFn()

	errChan := make(chan error, len(pending))

	go func() {
		<-ctxWithCancel.Done()
		atomic.StoreInt32(&cancelled, 1)
	}()

	for i := range pending {
		tc := pending[i]

		if atomic.LoadInt32(&cancelled) == 1 {
			break
		}

		select {
		case <-ctxWithCancel.Done():
			break
		default:
		}

		if err := e.rateLimiter.Wait(ctxWithCancel); err != nil {
			if !errors.Is(err, context.Canceled) {
				errChan <- err
			}
			break
		}

		e.semaphore <- struct{}{}
		wg.Add(1)

		go func(tc *types.TestCase) {
			defer wg.Done()
			defer func() { <-e.semaphore }()

			if atomic.LoadInt32(&cancelled) == 1 {
				return
			}

			resp, testAnomalies := e.executeTestCase(ctxWithCancel, tc)
			if testAnomalies != nil && len(testAnomalies) > 0 {
				for _, a := range testAnomalies {
					e.addAnomaly(a)
				}
				if anomalyCallback != nil {
					anomalyCallback(tc, resp, testAnomalies)
				}
			}

			e.markCompleted(tc.ID)
			if e.progress != nil {
				e.progress.Increment(1)
			}

			if atomic.AddInt64(&saveCounter, 1)%saveInterval == 0 {
				_ = e.saveState()
			}
		}(tc)
	}

	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()

	select {
	case <-allDone:
	case <-time.After(shutdownTimeout):
		cancelFn()
		<-allDone
	}

	if err := e.saveState(); err != nil {
		return nil, err
	}

	close(errChan)

	var firstErr error
	for err := range errChan {
		if firstErr == nil {
			firstErr = err
		}
	}

	e.mu.Lock()
	result := make([]*types.Anomaly, len(e.anomalies))
	copy(result, e.anomalies)
	e.mu.Unlock()

	if atomic.LoadInt32(&cancelled) == 1 && firstErr == nil {
		firstErr = context.Canceled
	}

	return result, firstErr
}

func (e *Executor) executeTestCase(
	ctx context.Context,
	tc *types.TestCase,
) (*types.HTTPResponse, []*types.Anomaly) {
	if tc == nil || tc.Request == nil {
		return nil, nil
	}

	req := *tc.Request
	if req.Headers == nil {
		req.Headers = make(map[string]string)
	}
	if req.Query == nil {
		req.Query = make(map[string]string)
	}
	if req.Cookies == nil {
		req.Cookies = make(map[string]string)
	}

	var authConfigs []*types.AuthConfig
	if len(tc.Auth) > 0 {
		authConfigs = tc.Auth
	} else if tc.APISpec != nil && len(tc.APISpec.Auth) > 0 {
		authConfigs = tc.APISpec.Auth
	}
	if err := auth.InjectAuth(&req, authConfigs, e.config.AuthTokens); err != nil {
		anom := &types.Anomaly{
			ID:         fmt.Sprintf("auth-error-%s", tc.ID),
			TestCaseID: tc.ID,
			Type:       types.AnomalyConnectionError,
			Severity:   types.SeverityMedium,
			Message:    fmt.Sprintf("auth injection failed: %v", err),
			Timestamp:  time.Now(),
		}
		return nil, []*types.Anomaly{anom}
	}

	reqURL, err := e.buildURL(&req)
	if err != nil {
		anom := &types.Anomaly{
			ID:         fmt.Sprintf("url-error-%s", tc.ID),
			TestCaseID: tc.ID,
			Type:       types.AnomalyConnectionError,
			Severity:   types.SeverityMedium,
			Message:    fmt.Sprintf("invalid URL: %v", err),
			Timestamp:  time.Now(),
		}
		return nil, []*types.Anomaly{anom}
	}

	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, string(req.Method), reqURL, bodyReader)
	if err != nil {
		anom := &types.Anomaly{
			ID:         fmt.Sprintf("req-error-%s", tc.ID),
			TestCaseID: tc.ID,
			Type:       types.AnomalyConnectionError,
			Severity:   types.SeverityMedium,
			Message:    fmt.Sprintf("build request failed: %v", err),
			Timestamp:  time.Now(),
		}
		return nil, []*types.Anomaly{anom}
	}

	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	for k, v := range req.Cookies {
		httpReq.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	if req.Body != "" && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	resp := &types.HTTPResponse{}
	start := time.Now()

	httpResp, doErr := e.client.Do(httpReq)
	elapsed := time.Since(start)
	resp.Duration = elapsed

	if doErr != nil {
		resp.Error = doErr.Error()
		var anomalies []*types.Anomaly
		isTimeout := false
		if errors.Is(doErr, context.DeadlineExceeded) || errors.Is(doErr, context.Canceled) {
			isTimeout = true
		} else if tErr, ok := doErr.(interface{ Timeout() bool }); ok && tErr.Timeout() {
			isTimeout = true
		} else if uErr, ok := doErr.(*url.Error); ok {
			if uErr.Timeout() {
				isTimeout = true
			}
		}
		resp.IsTimeout = isTimeout

		if isTimeout {
			anomalies = append(anomalies, &types.Anomaly{
				ID:          fmt.Sprintf("timeout-%s", tc.ID),
				TestCaseID:  tc.ID,
				Type:        types.AnomalyTimeout,
				Severity:    types.SeverityHigh,
				Message:     fmt.Sprintf("request timed out after %v", elapsed),
				Description: doErr.Error(),
				Request:     &req,
				Response:    resp,
				Timestamp:   time.Now(),
			})
		} else {
			anomalies = append(anomalies, &types.Anomaly{
				ID:          fmt.Sprintf("conn-error-%s", tc.ID),
				TestCaseID:  tc.ID,
				Type:        types.AnomalyConnectionError,
				Severity:    types.SeverityHigh,
				Message:     fmt.Sprintf("connection error: %v", doErr),
				Description: doErr.Error(),
				Request:     &req,
				Response:    resp,
				Timestamp:   time.Now(),
			})
		}
		return resp, anomalies
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
	}

	var anomalies []*types.Anomaly
	if resp.StatusCode >= 500 && resp.StatusCode < 600 {
		anomalies = append(anomalies, &types.Anomaly{
			ID:          fmt.Sprintf("servererr-%s", tc.ID),
			TestCaseID:  tc.ID,
			Type:        types.AnomalyServerError,
			Severity:    types.SeverityCritical,
			Message:     fmt.Sprintf("server error: HTTP %d", resp.StatusCode),
			Description: http.StatusText(resp.StatusCode),
			Request:     &req,
			Response:    resp,
			APIPath:     tc.APIPath,
			APIMethod:   tc.APIMethod,
			Timestamp:   time.Now(),
		})
	}

	if e.detector != nil {
		var apiSpec *types.APISpec
		if tc.APISpec != nil {
			apiSpec = tc.APISpec
		}
		detected, detErr := e.detector.Detect(tc, resp, apiSpec)
		if detErr == nil && len(detected) > 0 {
			for _, a := range detected {
				if a.Request == nil {
					a.Request = &req
				}
				if a.Response == nil {
					a.Response = resp
				}
				if a.APIPath == "" {
					a.APIPath = tc.APIPath
				}
				if a.APIMethod == "" {
					a.APIMethod = tc.APIMethod
				}
			}
			anomalies = append(anomalies, detected...)
		}
	}

	return resp, anomalies
}

func (e *Executor) buildURL(req *types.HTTPRequest) (string, error) {
	rawURL := req.URL
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		if e.config.BaseURL != "" {
			base := strings.TrimRight(e.config.BaseURL, "/")
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
