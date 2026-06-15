package minimizer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"api-fuzzer/internal/types"
)

type VerifyFunc func(req *types.HTTPRequest) (bool, error)

type Minimizer struct {
	verifyFn VerifyFunc
	timeout  time.Duration
	deadline time.Time
}

func NewMinimizer(verifyFn VerifyFunc, timeout time.Duration) *Minimizer {
	return &Minimizer{
		verifyFn: verifyFn,
		timeout:  timeout,
		deadline: time.Now().Add(timeout),
	}
}

func (m *Minimizer) isTimedOut() bool {
	return time.Now().After(m.deadline)
}

func cloneRequest(req *types.HTTPRequest) *types.HTTPRequest {
	cloned := &types.HTTPRequest{
		Method:  req.Method,
		URL:     req.URL,
		Body:    req.Body,
		BodyObj: req.BodyObj,
	}
	if req.Headers != nil {
		cloned.Headers = make(map[string]string, len(req.Headers))
		for k, v := range req.Headers {
			cloned.Headers[k] = v
		}
	}
	if req.Query != nil {
		cloned.Query = make(map[string]string, len(req.Query))
		for k, v := range req.Query {
			cloned.Query[k] = v
		}
	}
	if req.Cookies != nil {
		cloned.Cookies = make(map[string]string, len(req.Cookies))
		for k, v := range req.Cookies {
			cloned.Cookies[k] = v
		}
	}
	return cloned
}

func (m *Minimizer) tryVerify(req *types.HTTPRequest) (bool, bool) {
	if m.isTimedOut() {
		return false, true
	}
	ok, err := m.verifyFn(req)
	if err != nil {
		return false, false
	}
	return ok, false
}

func (m *Minimizer) Minimize(originalReq *types.HTTPRequest, anomalyType types.AnomalyType) (*types.HTTPRequest, string, error) {
	current := cloneRequest(originalReq)
	m.deadline = time.Now().Add(m.timeout)

	if ok, timedOut := m.tryVerify(current); !ok {
		if timedOut {
			return originalReq, BuildCurl(originalReq), context.DeadlineExceeded
		}
		return originalReq, BuildCurl(originalReq), fmt.Errorf("original request does not trigger anomaly")
	}

	current = m.minimizeLongStrings(current)
	current = m.minimizeQueryParams(current)
	current = m.minimizeHeaders(current)
	current = m.minimizeJSONBody(current)
	current = m.minimizeNestedJSON(current)
	current = m.minimizeLongStrings(current)

	return current, BuildCurl(current), nil
}

func (m *Minimizer) minimizeLongStrings(req *types.HTTPRequest) *types.HTTPRequest {
	current := cloneRequest(req)
	const threshold = 1000

	if len(current.Body) > threshold {
		current.Body = m.binarySearchShorten(current.Body, func(s string) bool {
			testReq := cloneRequest(current)
			testReq.Body = s
			ok, _ := m.tryVerify(testReq)
			return ok
		})
	}

	if current.Query != nil {
		keys := make([]string, 0, len(current.Query))
		for k := range current.Query {
			keys = append(keys, k)
		}
		for _, k := range keys {
			if m.isTimedOut() {
				break
			}
			v := current.Query[k]
			if len(v) > threshold {
				shortened := m.binarySearchShorten(v, func(s string) bool {
					testReq := cloneRequest(current)
					testReq.Query[k] = s
					ok, _ := m.tryVerify(testReq)
					return ok
				})
				current.Query[k] = shortened
			}
		}
	}

	return current
}

func (m *Minimizer) binarySearchShorten(s string, verify func(string) bool) string {
	if m.isTimedOut() {
		return s
	}
	if !verify(s) {
		return s
	}

	left, right := 1, len(s)
	result := s

	for left <= right {
		if m.isTimedOut() {
			break
		}
		mid := (left + right) / 2
		candidate := s[:mid]
		if verify(candidate) {
			result = candidate
			right = mid - 1
		} else {
			left = mid + 1
		}
	}

	return result
}

func (m *Minimizer) minimizeQueryParams(req *types.HTTPRequest) *types.HTTPRequest {
	current := cloneRequest(req)
	if current.Query == nil || len(current.Query) == 0 {
		return current
	}

	keys := make([]string, 0, len(current.Query))
	for k := range current.Query {
		keys = append(keys, k)
	}

	for _, k := range keys {
		if m.isTimedOut() {
			break
		}
		testReq := cloneRequest(current)
		delete(testReq.Query, k)
		if ok, _ := m.tryVerify(testReq); ok {
			delete(current.Query, k)
		}
	}

	return current
}

func (m *Minimizer) minimizeHeaders(req *types.HTTPRequest) *types.HTTPRequest {
	current := cloneRequest(req)
	if current.Headers == nil || len(current.Headers) == 0 {
		return current
	}

	keys := make([]string, 0, len(current.Headers))
	for k := range current.Headers {
		kl := strings.ToLower(k)
		if kl == "content-type" || kl == "authorization" || kl == "accept" ||
			kl == "host" || kl == "user-agent" || kl == "connection" {
			continue
		}
		keys = append(keys, k)
	}

	for _, k := range keys {
		if m.isTimedOut() {
			break
		}
		testReq := cloneRequest(current)
		delete(testReq.Headers, k)
		if ok, _ := m.tryVerify(testReq); ok {
			delete(current.Headers, k)
		}
	}

	return current
}

func (m *Minimizer) minimizeJSONBody(req *types.HTTPRequest) *types.HTTPRequest {
	current := cloneRequest(req)
	if current.Body == "" {
		return current
	}

	var bodyObj map[string]interface{}
	if err := json.Unmarshal([]byte(current.Body), &bodyObj); err != nil {
		return current
	}

	keys := make([]string, 0, len(bodyObj))
	for k := range bodyObj {
		keys = append(keys, k)
	}

	for _, k := range keys {
		if m.isTimedOut() {
			break
		}
		testObj := copyJSONMap(bodyObj)
		delete(testObj, k)
		testBody, err := json.Marshal(testObj)
		if err != nil {
			continue
		}
		testReq := cloneRequest(current)
		testReq.Body = string(testBody)
		if ok, _ := m.tryVerify(testReq); ok {
			bodyObj = testObj
		}
	}

	finalBody, err := json.Marshal(bodyObj)
	if err == nil {
		current.Body = string(finalBody)
	}
	return current
}

func copyJSONMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = deepCopyJSON(v)
	}
	return result
}

func copyJSONSlice(s []interface{}) []interface{} {
	result := make([]interface{}, len(s))
	for i, v := range s {
		result[i] = deepCopyJSON(v)
	}
	return result
}

func deepCopyJSON(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		return copyJSONMap(val)
	case []interface{}:
		return copyJSONSlice(val)
	default:
		return val
	}
}

func (m *Minimizer) minimizeNestedJSON(req *types.HTTPRequest) *types.HTTPRequest {
	current := cloneRequest(req)
	if current.Body == "" {
		return current
	}

	var bodyObj interface{}
	if err := json.Unmarshal([]byte(current.Body), &bodyObj); err != nil {
		return current
	}

	simplified := m.simplifyJSONValue(bodyObj, func(v interface{}) bool {
		testBody, err := json.Marshal(v)
		if err != nil {
			return false
		}
		testReq := cloneRequest(current)
		testReq.Body = string(testBody)
		ok, _ := m.tryVerify(testReq)
		return ok
	})

	finalBody, err := json.Marshal(simplified)
	if err == nil {
		current.Body = string(finalBody)
	}
	return current
}

func (m *Minimizer) simplifyJSONValue(v interface{}, verify func(interface{}) bool) interface{} {
	if m.isTimedOut() {
		return v
	}

	switch val := v.(type) {
	case map[string]interface{}:
		emptyMap := map[string]interface{}{}
		if verify(emptyMap) {
			return emptyMap
		}

		nullVal := interface{}(nil)
		if verify(nullVal) {
			return nil
		}

		result := copyJSONMap(val)
		keys := make([]string, 0, len(result))
		for k := range result {
			keys = append(keys, k)
		}

		for _, k := range keys {
			if m.isTimedOut() {
				break
			}
			nested := result[k]
			simplifiedNested := m.simplifyJSONValue(nested, func(testV interface{}) bool {
				testMap := copyJSONMap(result)
				testMap[k] = testV
				return verify(testMap)
			})
			result[k] = simplifiedNested
		}
		return result

	case []interface{}:
		emptyArr := []interface{}{}
		if verify(emptyArr) {
			return emptyArr
		}

		nullVal := interface{}(nil)
		if verify(nullVal) {
			return nil
		}

		result := copyJSONSlice(val)
		for i := range result {
			if m.isTimedOut() {
				break
			}
			nested := result[i]
			simplifiedNested := m.simplifyJSONValue(nested, func(testV interface{}) bool {
				testArr := copyJSONSlice(result)
				testArr[i] = testV
				return verify(testArr)
			})
			result[i] = simplifiedNested
		}
		return result

	default:
		return v
	}
}

func shellEscape(s string) string {
	if s == "" {
		return "''"
	}
	needsQuote := false
	specialChars := []rune{' ', '\t', '\n', '\r', '"', '\'', '\\', '$', '`', '!', '&', ';', '(', ')', '|', '<', '>', '*', '?', '[', ']', '{', '}', '~', '#'}
	for _, r := range s {
		for _, sp := range specialChars {
			if r == sp {
				needsQuote = true
				break
			}
		}
		if needsQuote {
			break
		}
	}
	if !needsQuote {
		return s
	}

	var b strings.Builder
	b.WriteRune('\'')
	for _, r := range s {
		if r == '\'' {
			b.WriteString("'\\''")
		} else {
			b.WriteRune(r)
		}
	}
	b.WriteRune('\'')
	return b.String()
}

func BuildCurl(req *types.HTTPRequest) string {
	var parts []string

	parts = append(parts, "curl")

	if req.Method != "" {
		parts = append(parts, "-X")
		parts = append(parts, string(req.Method))
	}

	url := req.URL
	if req.Query != nil && len(req.Query) > 0 {
		queryParts := make([]string, 0, len(req.Query))
		for k, v := range req.Query {
			queryParts = append(queryParts, fmt.Sprintf("%s=%s", k, v))
		}
		queryStr := strings.Join(queryParts, "&")
		if strings.Contains(url, "?") {
			url = url + "&" + queryStr
		} else {
			url = url + "?" + queryStr
		}
	}
	parts = append(parts, shellEscape(url))

	if req.Headers != nil {
		keys := make([]string, 0, len(req.Headers))
		for k := range req.Headers {
			keys = append(keys, k)
		}
		for _, k := range keys {
			headerStr := fmt.Sprintf("%s: %s", k, req.Headers[k])
			parts = append(parts, "-H")
			parts = append(parts, shellEscape(headerStr))
		}
	}

	if req.Body != "" {
		if len(req.Body) > 200 {
			bodyStr := req.Body
			lines := splitString(bodyStr, 150)
			if len(lines) > 1 {
				first := true
				for _, line := range lines {
					if first {
						parts = append(parts, "--data-raw")
						parts = append(parts, shellEscape(line))
						first = false
					} else {
						parts = append(parts, fmt.Sprintf("--data-raw %s", shellEscape(line)))
					}
				}
			} else {
				parts = append(parts, "-d")
				parts = append(parts, shellEscape(bodyStr))
			}
		} else {
			parts = append(parts, "-d")
			parts = append(parts, shellEscape(req.Body))
		}
	}

	return strings.Join(parts, " \\\n  ")
}

func splitString(s string, n int) []string {
	if len(s) == 0 {
		return []string{}
	}
	var parts []string
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		parts = append(parts, s[i:end])
	}
	return parts
}
