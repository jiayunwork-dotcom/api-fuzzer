package detector

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"api-fuzzer/internal/types"
	"api-fuzzer/pkg/utils"
)

type Detector struct {
	severityThreshold  types.AnomalySeverity
	normalResponseTime time.Duration
}

func NewDetector(threshold types.AnomalySeverity) *Detector {
	return &Detector{
		severityThreshold:  threshold,
		normalResponseTime: 100 * time.Millisecond,
	}
}

func (d *Detector) Detect(testCase *types.TestCase, response *types.HTTPResponse, apiSpec *types.APISpec) ([]*types.Anomaly, error) {
	var anomalies []*types.Anomaly

	if d.isExpectedError(response) {
		return anomalies, nil
	}

	detectors := []func(*types.TestCase, *types.HTTPResponse, *types.APISpec) []*types.Anomaly{
		d.detectServerError,
		d.detectTimeout,
		d.detectSchemaMismatch,
		d.detectSensitiveInfoLeak,
		d.detectSlowResponse,
		d.detectAuthBypass,
	}

	for _, detect := range detectors {
		found := detect(testCase, response, apiSpec)
		for _, a := range found {
			if a.Severity.Compare(d.severityThreshold) >= 0 {
				anomalies = append(anomalies, a)
			}
		}
	}

	return anomalies, nil
}

func (d *Detector) isExpectedError(response *types.HTTPResponse) bool {
	if response.StatusCode < 400 || response.StatusCode >= 500 {
		return false
	}

	if len(response.Body) == 0 {
		return false
	}

	var bodyMap map[string]interface{}
	if err := json.Unmarshal([]byte(response.Body), &bodyMap); err != nil {
		return false
	}

	errorFields := []string{"error", "message", "code"}
	for _, field := range errorFields {
		if _, exists := bodyMap[field]; exists {
			return true
		}
	}

	return false
}

func (d *Detector) detectServerError(testCase *types.TestCase, response *types.HTTPResponse, apiSpec *types.APISpec) []*types.Anomaly {
	var anomalies []*types.Anomaly

	if response.StatusCode >= 500 {
		anomaly := d.createAnomaly(
			types.AnomalyServerError,
			types.SeverityHigh,
			fmt.Sprintf("Server returned %d status code", response.StatusCode),
			fmt.Sprintf("API endpoint %s %s returned HTTP %d, indicating a server-side error", apiSpec.Method, apiSpec.Path, response.StatusCode),
			testCase,
			response,
			apiSpec,
		)
		anomalies = append(anomalies, anomaly)
	}

	return anomalies
}

func (d *Detector) detectTimeout(testCase *types.TestCase, response *types.HTTPResponse, apiSpec *types.APISpec) []*types.Anomaly {
	var anomalies []*types.Anomaly

	isTimeout := response.Duration > 5*time.Second
	if response.Error != "" {
		isTimeout = isTimeout || strings.Contains(response.Error, "context deadline exceeded")
	}

	if isTimeout {
		anomaly := d.createAnomaly(
			types.AnomalyTimeout,
			types.SeverityMedium,
			fmt.Sprintf("Request timed out after %v", response.Duration),
			fmt.Sprintf("API endpoint %s %s exceeded timeout threshold (5s). Response time: %v", apiSpec.Method, apiSpec.Path, response.Duration),
			testCase,
			response,
			apiSpec,
		)
		anomalies = append(anomalies, anomaly)
	}

	return anomalies
}

func (d *Detector) detectSchemaMismatch(testCase *types.TestCase, response *types.HTTPResponse, apiSpec *types.APISpec) []*types.Anomaly {
	var anomalies []*types.Anomaly

	if apiSpec.ResponseSchema == nil {
		return anomalies
	}

	statusCodeStr := strconv.Itoa(response.StatusCode)
	schema, exists := apiSpec.ResponseSchema[statusCodeStr]
	if !exists {
		schema, exists = apiSpec.ResponseSchema["default"]
	}
	if !exists || schema == nil {
		return anomalies
	}

	var body interface{}
	if len(response.Body) > 0 {
		if err := json.Unmarshal([]byte(response.Body), &body); err != nil {
			return anomalies
		}
	}

	schemaErrors := validateSchemaAgainstBody(schema, body, "$")

	if len(schemaErrors) > 0 {
		anomaly := d.createAnomaly(
			types.AnomalySchemaMismatch,
			types.SeverityMedium,
			fmt.Sprintf("Response schema validation failed with %d errors", len(schemaErrors)),
			fmt.Sprintf("API endpoint %s %s returned response that does not match the expected schema for status %d", apiSpec.Method, apiSpec.Path, response.StatusCode),
			testCase,
			response,
			apiSpec,
		)
		anomaly.SchemaErrors = make([]*types.SchemaError, len(schemaErrors))
		for i, errMsg := range schemaErrors {
			anomaly.SchemaErrors[i] = &types.SchemaError{
				Path:    "",
				Message: errMsg,
			}
		}
		anomalies = append(anomalies, anomaly)
	}

	return anomalies
}

func validateSchemaAgainstBody(schema *types.Schema, body interface{}, path string) []string {
	var errors []string

	if schema == nil {
		return errors
	}

	if body == nil {
		if schema.Nullable {
			return errors
		}
		return append(errors, fmt.Sprintf("%s: value is null but schema does not allow nullable", path))
	}

	if schema.Type != "" {
		typeErrors := validateType(schema.Type, body, path)
		errors = append(errors, typeErrors...)
		if len(typeErrors) > 0 {
			return errors
		}
	}

	if schema.Enum != nil && len(schema.Enum) > 0 {
		found := false
		for _, enumVal := range schema.Enum {
			if fmt.Sprintf("%v", enumVal) == fmt.Sprintf("%v", body) {
				found = true
				break
			}
		}
		if !found {
			errors = append(errors, fmt.Sprintf("%s: value %v not in enum %v", path, body, schema.Enum))
		}
	}

	switch v := body.(type) {
	case map[string]interface{}:
		if schema.Required != nil {
			for _, reqField := range schema.Required {
				if _, exists := v[reqField]; !exists {
					errors = append(errors, fmt.Sprintf("%s: missing required field '%s'", path, reqField))
				}
			}
		}

		if schema.Properties != nil {
			for propName, propSchema := range schema.Properties {
				if propValue, exists := v[propName]; exists {
					subPath := fmt.Sprintf("%s.%s", path, propName)
					subErrors := validateSchemaAgainstBody(propSchema, propValue, subPath)
					errors = append(errors, subErrors...)
				}
			}

			if schema.AdditionalProperties == nil {
				for fieldName := range v {
					if _, defined := schema.Properties[fieldName]; !defined {
						errors = append(errors, fmt.Sprintf("%s: additional property '%s' not allowed", path, fieldName))
					}
				}
			}
		}

		if schema.AdditionalProperties != nil {
			for propName, propValue := range v {
				if schema.Properties != nil {
					if _, defined := schema.Properties[propName]; defined {
						continue
					}
				}
				subPath := fmt.Sprintf("%s.%s", path, propName)
				subErrors := validateSchemaAgainstBody(schema.AdditionalProperties, propValue, subPath)
				errors = append(errors, subErrors...)
			}
		}

	case []interface{}:
		if schema.Items != nil {
			for i, item := range v {
				subPath := fmt.Sprintf("%s[%d]", path, i)
				subErrors := validateSchemaAgainstBody(schema.Items, item, subPath)
				errors = append(errors, subErrors...)
			}
		}

		if schema.MinItems != nil && int64(len(v)) < *schema.MinItems {
			errors = append(errors, fmt.Sprintf("%s: array length %d less than minItems %d", path, len(v), *schema.MinItems))
		}
		if schema.MaxItems != nil && int64(len(v)) > *schema.MaxItems {
			errors = append(errors, fmt.Sprintf("%s: array length %d greater than maxItems %d", path, len(v), *schema.MaxItems))
		}
	}

	return errors
}

func validateType(schemaType string, body interface{}, path string) []string {
	var errors []string

	switch schemaType {
	case "object":
		if _, ok := body.(map[string]interface{}); !ok {
			errors = append(errors, fmt.Sprintf("%s: expected object, got %T", path, body))
		}
	case "array":
		if _, ok := body.([]interface{}); !ok {
			errors = append(errors, fmt.Sprintf("%s: expected array, got %T", path, body))
		}
	case "string":
		if _, ok := body.(string); !ok {
			errors = append(errors, fmt.Sprintf("%s: expected string, got %T", path, body))
		}
	case "integer", "number":
		switch body.(type) {
		case float64, json.Number:
		default:
			errors = append(errors, fmt.Sprintf("%s: expected number, got %T", path, body))
		}
	case "boolean":
		if _, ok := body.(bool); !ok {
			errors = append(errors, fmt.Sprintf("%s: expected boolean, got %T", path, body))
		}
	case "null":
		if body != nil {
			errors = append(errors, fmt.Sprintf("%s: expected null, got %T", path, body))
		}
	}

	return errors
}

func (d *Detector) detectSensitiveInfoLeak(testCase *types.TestCase, response *types.HTTPResponse, apiSpec *types.APISpec) []*types.Anomaly {
	var anomalies []*types.Anomaly

	patterns := map[string]*regexp.Regexp{
		"Stack Trace":   regexp.MustCompile(`(at .+\.java:\d+|Traceback|File ".+", line \d+)`),
		"SQL Statement": regexp.MustCompile(`(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE\s+TABLE|ALTER\s+TABLE.*FROM|WHERE)`),
		"Internal Path": regexp.MustCompile(`(C:\\\\|/etc/|/var/|/usr/local|\\\\\\\\server\\\\|file://)`),
		"Debug Info":    regexp.MustCompile(`(DEBUG|debug=1|stack|trace|Exception in thread)`),
	}

	bodyStr := response.Body
	headerStr := headersToString(response.Headers)
	fullContent := bodyStr + "\n" + headerStr

	var matchedPatterns []*types.LeakPattern
	var matchedSnippets []string

	for patternName, regex := range patterns {
		matches := regex.FindAllString(fullContent, -1)
		if len(matches) > 0 {
			matchedPatterns = append(matchedPatterns, &types.LeakPattern{
				Name:    patternName,
				Matches: matches,
			})
			for _, m := range matches {
				if len(m) > 100 {
					m = m[:100] + "..."
				}
				matchedSnippets = append(matchedSnippets, fmt.Sprintf("[%s] %s", patternName, m))
			}
		}
	}

	if len(matchedPatterns) > 0 {
		severity := types.SeverityHigh
		if response.StatusCode >= 500 {
			severity = types.SeverityCritical
		}

		patternNames := make([]string, len(matchedPatterns))
		for i, p := range matchedPatterns {
			patternNames[i] = p.Name
		}

		message := fmt.Sprintf("Sensitive information detected: %s", strings.Join(patternNames, ", "))
		description := fmt.Sprintf("API endpoint %s %s leaked sensitive information in response. Matched patterns: %s. Matched snippets:\n%s",
			apiSpec.Method, apiSpec.Path, strings.Join(patternNames, ", "), strings.Join(matchedSnippets, "\n"))

		anomaly := d.createAnomaly(
			types.AnomalySensitiveInfoLeak,
			severity,
			message,
			description,
			testCase,
			response,
			apiSpec,
		)
		anomaly.LeakPatterns = matchedPatterns
		anomalies = append(anomalies, anomaly)
	}

	return anomalies
}

func headersToString(headers map[string]string) string {
	var sb strings.Builder
	for key, value := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\n", key, value))
	}
	return sb.String()
}

func (d *Detector) detectSlowResponse(testCase *types.TestCase, response *types.HTTPResponse, apiSpec *types.APISpec) []*types.Anomaly {
	var anomalies []*types.Anomaly

	threshold := 5 * time.Second
	if d.normalResponseTime > 0 {
		dynamicThreshold := d.normalResponseTime * 50
		if dynamicThreshold > threshold {
			threshold = dynamicThreshold
		}
	}
	if response.Duration > threshold {
		anomaly := d.createAnomaly(
			types.AnomalySlowResponse,
			types.SeverityMedium,
			fmt.Sprintf("Response time %v exceeds threshold of %v", response.Duration, threshold),
			fmt.Sprintf("API endpoint %s %s responded in %v, which is significantly slower than the normal baseline of %v (dynamic threshold: %v)",
				apiSpec.Method, apiSpec.Path, response.Duration, d.normalResponseTime, threshold),
			testCase,
			response,
			apiSpec,
		)
		anomalies = append(anomalies, anomaly)
	}

	return anomalies
}

func (d *Detector) detectAuthBypass(testCase *types.TestCase, response *types.HTTPResponse, apiSpec *types.APISpec) []*types.Anomaly {
	var anomalies []*types.Anomaly

	needsAuth := apiSpec.Security != nil && len(apiSpec.Security) > 0
	hasAuthInSpec := apiSpec.Auth != nil && len(apiSpec.Auth) > 0
	requiresAuth := needsAuth || hasAuthInSpec

	hasAuthToken := false
	if testCase.Request != nil {
		if testCase.Request.Headers != nil {
			if _, ok := testCase.Request.Headers["Authorization"]; ok {
				hasAuthToken = true
			}
		}
		if !hasAuthToken && testCase.Auth != nil && len(testCase.Auth) > 0 {
			hasAuthToken = true
		}
	}

	if requiresAuth && !hasAuthToken && response.StatusCode == 200 {
		anomaly := d.createAnomaly(
			types.AnomalyAuthBypass,
			types.SeverityLow,
			"Authentication bypass detected: endpoint required auth but request without token succeeded",
			fmt.Sprintf("API endpoint %s %s requires authentication but returned 200 OK when called without authentication token. Expected 401 or 403 status code.",
				apiSpec.Method, apiSpec.Path),
			testCase,
			response,
			apiSpec,
		)
		anomalies = append(anomalies, anomaly)
	}

	return anomalies
}

func (d *Detector) createAnomaly(
	anomalyType types.AnomalyType,
	severity types.AnomalySeverity,
	message string,
	description string,
	testCase *types.TestCase,
	response *types.HTTPResponse,
	apiSpec *types.APISpec,
) *types.Anomaly {
	return &types.Anomaly{
		ID:          fmt.Sprintf("%s-%s-%d", anomalyType, testCase.ID, time.Now().UnixNano()),
		Type:        anomalyType,
		Severity:    severity,
		Message:     message,
		Description: description,
		Response:    response,
		TestCaseID:  testCase.ID,
		APIPath:     apiSpec.Path,
		APIMethod:   apiSpec.Method,
		Timestamp:   time.Now(),
		MinimalCurl: "",
	}
}


