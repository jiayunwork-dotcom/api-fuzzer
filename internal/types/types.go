package types

import (
	"encoding/json"
	"time"
)

type HTTPMethod string

const (
	MethodGet     HTTPMethod = "GET"
	MethodPost    HTTPMethod = "POST"
	MethodPut     HTTPMethod = "PUT"
	MethodDelete  HTTPMethod = "DELETE"
	MethodPatch   HTTPMethod = "PATCH"
	MethodHead    HTTPMethod = "HEAD"
	MethodOptions HTTPMethod = "OPTIONS"
)

const (
	TypeString  = "string"
	TypeInteger = "integer"
	TypeNumber  = "number"
	TypeBoolean = "boolean"
	TypeArray   = "array"
	TypeObject  = "object"
	TypeNull    = "null"
)

type AuthType string

const (
	AuthTypeBearer     AuthType = "bearer"
	AuthTypeAPIKey     AuthType = "apiKey"
	AuthTypeBasic      AuthType = "basic"
	AuthTypeOAuth2     AuthType = "oauth2"
	AuthTypeNone       AuthType = "none"
	AuthTypeHTTPBearer AuthType = "bearer"
	AuthTypeHTTPBasic  AuthType = "basic"
)

type APIKeyLocation string

const (
	APIKeyInHeader APIKeyLocation = "header"
	APIKeyInQuery  APIKeyLocation = "query"
	APIKeyInCookie APIKeyLocation = "cookie"
	AuthInHeader   APIKeyLocation = "header"
	AuthInQuery    APIKeyLocation = "query"
	AuthInCookie   APIKeyLocation = "cookie"
)

type OAuth2Flow struct {
	AuthorizationURL string            `json:"authorizationUrl,omitempty" yaml:"authorizationUrl,omitempty"`
	TokenURL         string            `json:"tokenUrl,omitempty" yaml:"tokenUrl,omitempty"`
	RefreshURL       string            `json:"refreshUrl,omitempty" yaml:"refreshUrl,omitempty"`
	Scopes           map[string]string `json:"scopes,omitempty" yaml:"scopes,omitempty"`
}

type OAuth2Flows struct {
	Implicit          *OAuth2Flow `json:"implicit,omitempty" yaml:"implicit,omitempty"`
	Password          *OAuth2Flow `json:"password,omitempty" yaml:"password,omitempty"`
	ClientCredentials *OAuth2Flow `json:"clientCredentials,omitempty" yaml:"clientCredentials,omitempty"`
	AuthorizationCode *OAuth2Flow `json:"authorizationCode,omitempty" yaml:"authorizationCode,omitempty"`
}

type AuthConfig struct {
	Type         AuthType       `json:"type" yaml:"type"`
	Name         string         `json:"name,omitempty" yaml:"name,omitempty"`
	Scheme       string         `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	BearerFormat string         `json:"bearerFormat,omitempty" yaml:"bearerFormat,omitempty"`
	In           APIKeyLocation `json:"in,omitempty" yaml:"in,omitempty"`
	APIKeyName   string         `json:"apiKeyName,omitempty" yaml:"apiKeyName,omitempty"`
	Flows        *OAuth2Flows   `json:"flows,omitempty" yaml:"flows,omitempty"`
	Scopes       []string       `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	Description  string         `json:"description,omitempty" yaml:"description,omitempty"`
	EnvVar       string         `json:"envVar,omitempty" yaml:"envVar,omitempty"`
	Username     string         `json:"username,omitempty" yaml:"username,omitempty"`
	Password     string         `json:"password,omitempty" yaml:"password,omitempty"`
}

type Schema struct {
	Type                 string              `json:"type,omitempty" yaml:"type,omitempty"`
	Format               string              `json:"format,omitempty" yaml:"format,omitempty"`
	Title                string              `json:"title,omitempty" yaml:"title,omitempty"`
	Description          string              `json:"description,omitempty" yaml:"description,omitempty"`
	Default              interface{}         `json:"default,omitempty" yaml:"default,omitempty"`
	Example              interface{}         `json:"example,omitempty" yaml:"example,omitempty"`
	Enum                 []interface{}       `json:"enum,omitempty" yaml:"enum,omitempty"`
	Const                interface{}         `json:"const,omitempty" yaml:"const,omitempty"`
	MultipleOf           *float64            `json:"multipleOf,omitempty" yaml:"multipleOf,omitempty"`
	Maximum              *float64            `json:"maximum,omitempty" yaml:"maximum,omitempty"`
	ExclusiveMaximum     *float64            `json:"exclusiveMaximum,omitempty" yaml:"exclusiveMaximum,omitempty"`
	Minimum              *float64            `json:"minimum,omitempty" yaml:"minimum,omitempty"`
	ExclusiveMinimum     *float64            `json:"exclusiveMinimum,omitempty" yaml:"exclusiveMinimum,omitempty"`
	MaxLength            *int64              `json:"maxLength,omitempty" yaml:"maxLength,omitempty"`
	MinLength            *int64              `json:"minLength,omitempty" yaml:"minLength,omitempty"`
	Pattern              string              `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	MaxItems             *int64              `json:"maxItems,omitempty" yaml:"maxItems,omitempty"`
	MinItems             *int64              `json:"minItems,omitempty" yaml:"minItems,omitempty"`
	UniqueItems          *bool               `json:"uniqueItems,omitempty" yaml:"uniqueItems,omitempty"`
	MaxProperties        *int64              `json:"maxProperties,omitempty" yaml:"maxProperties,omitempty"`
	MinProperties        *int64              `json:"minProperties,omitempty" yaml:"minProperties,omitempty"`
	Required             []string            `json:"required,omitempty" yaml:"required,omitempty"`
	Items                *Schema             `json:"items,omitempty" yaml:"items,omitempty"`
	Properties           map[string]*Schema  `json:"properties,omitempty" yaml:"properties,omitempty"`
	AdditionalProperties *Schema             `json:"additionalProperties,omitempty" yaml:"additionalProperties,omitempty"`
	AllOf                []*Schema           `json:"allOf,omitempty" yaml:"allOf,omitempty"`
	AnyOf                []*Schema           `json:"anyOf,omitempty" yaml:"anyOf,omitempty"`
	OneOf                []*Schema           `json:"oneOf,omitempty" yaml:"oneOf,omitempty"`
	Not                  *Schema             `json:"not,omitempty" yaml:"not,omitempty"`
	Ref                  string              `json:"$ref,omitempty" yaml:"$ref,omitempty"`
	Nullable             bool                `json:"nullable,omitempty" yaml:"nullable,omitempty"`
	ReadOnly             bool                `json:"readOnly,omitempty" yaml:"readOnly,omitempty"`
	WriteOnly            bool                `json:"writeOnly,omitempty" yaml:"writeOnly,omitempty"`
	Discriminator        *Discriminator      `json:"discriminator,omitempty" yaml:"discriminator,omitempty"`
	XML                  *XML                `json:"xml,omitempty" yaml:"xml,omitempty"`
	ExternalDocs         *ExternalDocs       `json:"externalDocs,omitempty" yaml:"externalDocs,omitempty"`
	XInput               interface{}         `json:"x-input,omitempty" yaml:"x-input,omitempty"`
}

type Discriminator struct {
	PropertyName string            `json:"propertyName" yaml:"propertyName"`
	Mapping      map[string]string `json:"mapping,omitempty" yaml:"mapping,omitempty"`
}

type XML struct {
	Name      string `json:"name,omitempty" yaml:"name,omitempty"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Prefix    string `json:"prefix,omitempty" yaml:"prefix,omitempty"`
	Attribute bool   `json:"attribute,omitempty" yaml:"attribute,omitempty"`
	Wrapped   bool   `json:"wrapped,omitempty" yaml:"wrapped,omitempty"`
}

type ExternalDocs struct {
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	URL         string `json:"url" yaml:"url"`
}

type ParameterLocation string

const (
	ParamInPath   ParameterLocation = "path"
	ParamInQuery  ParameterLocation = "query"
	ParamInHeader ParameterLocation = "header"
	ParamInCookie ParameterLocation = "cookie"
)

type ParameterSpec struct {
	Name            string              `json:"name" yaml:"name"`
	In              ParameterLocation   `json:"in" yaml:"in"`
	Description     string              `json:"description,omitempty" yaml:"description,omitempty"`
	Required        bool                `json:"required,omitempty" yaml:"required,omitempty"`
	Deprecated      bool                `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
	AllowEmptyValue bool                `json:"allowEmptyValue,omitempty" yaml:"allowEmptyValue,omitempty"`
	Style           string              `json:"style,omitempty" yaml:"style,omitempty"`
	Explode         *bool               `json:"explode,omitempty" yaml:"explode,omitempty"`
	AllowReserved   bool                `json:"allowReserved,omitempty" yaml:"allowReserved,omitempty"`
	Schema          *Schema             `json:"schema,omitempty" yaml:"schema,omitempty"`
	Example         interface{}         `json:"example,omitempty" yaml:"example,omitempty"`
	Examples        map[string]*Example `json:"examples,omitempty" yaml:"examples,omitempty"`
}

type Example struct {
	Summary       string      `json:"summary,omitempty" yaml:"summary,omitempty"`
	Description   string      `json:"description,omitempty" yaml:"description,omitempty"`
	Value         interface{} `json:"value,omitempty" yaml:"value,omitempty"`
	ExternalValue string      `json:"externalValue,omitempty" yaml:"externalValue,omitempty"`
}

type MediaTypeSpec struct {
	Schema   *Schema               `json:"schema,omitempty" yaml:"schema,omitempty"`
	Example  interface{}           `json:"example,omitempty" yaml:"example,omitempty"`
	Examples map[string]*Example   `json:"examples,omitempty" yaml:"examples,omitempty"`
	Encoding map[string]*Encoding  `json:"encoding,omitempty" yaml:"encoding,omitempty"`
}

type Encoding struct {
	ContentType   string             `json:"contentType,omitempty" yaml:"contentType,omitempty"`
	Headers       map[string]*Header `json:"headers,omitempty" yaml:"headers,omitempty"`
	Style         string             `json:"style,omitempty" yaml:"style,omitempty"`
	Explode       *bool              `json:"explode,omitempty" yaml:"explode,omitempty"`
	AllowReserved bool               `json:"allowReserved,omitempty" yaml:"allowReserved,omitempty"`
}

type Header struct {
	Description     string      `json:"description,omitempty" yaml:"description,omitempty"`
	Required        bool        `json:"required,omitempty" yaml:"required,omitempty"`
	Deprecated      bool        `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
	AllowEmptyValue bool        `json:"allowEmptyValue,omitempty" yaml:"allowEmptyValue,omitempty"`
	Schema          *Schema     `json:"schema,omitempty" yaml:"schema,omitempty"`
	Example         interface{} `json:"example,omitempty" yaml:"example,omitempty"`
}

type RequestBodySpec struct {
	Description string                    `json:"description,omitempty" yaml:"description,omitempty"`
	Content     map[string]*MediaTypeSpec `json:"content" yaml:"content"`
	Required    bool                      `json:"required,omitempty" yaml:"required,omitempty"`
}

type ResponseSpec struct {
	Description string                    `json:"description" yaml:"description"`
	Headers     map[string]*Header        `json:"headers,omitempty" yaml:"headers,omitempty"`
	Content     map[string]*MediaTypeSpec `json:"content,omitempty" yaml:"content,omitempty"`
	Links       map[string]*Link          `json:"links,omitempty" yaml:"links,omitempty"`
}

type Link struct {
	OperationRef string                 `json:"operationRef,omitempty" yaml:"operationRef,omitempty"`
	OperationID  string                 `json:"operationId,omitempty" yaml:"operationId,omitempty"`
	Parameters   map[string]interface{} `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	RequestBody  interface{}            `json:"requestBody,omitempty" yaml:"requestBody,omitempty"`
	Description  string                 `json:"description,omitempty" yaml:"description,omitempty"`
	Server       *ServerInfo            `json:"server,omitempty" yaml:"server,omitempty"`
}

type ServerInfo struct {
	URL         string                    `json:"url" yaml:"url"`
	Description string                    `json:"description,omitempty" yaml:"description,omitempty"`
	Variables   map[string]*ServerVariable `json:"variables,omitempty" yaml:"variables,omitempty"`
}

type ServerVariable struct {
	Enum        []string `json:"enum,omitempty" yaml:"enum,omitempty"`
	Default     string   `json:"default" yaml:"default"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
}

type SecurityRequirementSpec map[string][]string

type APISpec struct {
	ID             string                      `json:"id,omitempty" yaml:"id,omitempty"`
	Path           string                      `json:"path" yaml:"path"`
	Method         HTTPMethod                  `json:"method" yaml:"method"`
	Summary        string                      `json:"summary,omitempty" yaml:"summary,omitempty"`
	Description    string                      `json:"description,omitempty" yaml:"description,omitempty"`
	Tags           []string                    `json:"tags,omitempty" yaml:"tags,omitempty"`
	OperationID    string                      `json:"operationId,omitempty" yaml:"operationId,omitempty"`
	Deprecated     bool                        `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
	Servers        []*ServerInfo               `json:"servers,omitempty" yaml:"servers,omitempty"`
	Parameters     []*ParameterSpec            `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	RequestBody    *RequestBodySpec            `json:"requestBody,omitempty" yaml:"requestBody,omitempty"`
	Responses      map[string]*ResponseSpec    `json:"responses" yaml:"responses"`
	Security       []SecurityRequirementSpec   `json:"security,omitempty" yaml:"security,omitempty"`
	Auth           []*AuthConfig               `json:"auth,omitempty" yaml:"auth,omitempty"`
	ResponseSchema map[string]*Schema          `json:"responseSchema,omitempty" yaml:"responseSchema,omitempty"`
	Extensions     map[string]interface{}      `json:"-" yaml:"-"`
}

func (s *Schema) ToJSON() (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *Schema) Clone() *Schema {
	if s == nil {
		return nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil
	}
	var clone Schema
	if err := json.Unmarshal(b, &clone); err != nil {
		return nil
	}
	return &clone
}

type HTTPRequest struct {
	Method  HTTPMethod        `json:"method" yaml:"method"`
	URL     string            `json:"url" yaml:"url"`
	Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Query   map[string]string `json:"query,omitempty" yaml:"query,omitempty"`
	Cookies map[string]string `json:"cookies,omitempty" yaml:"cookies,omitempty"`
	Body    string            `json:"body,omitempty" yaml:"body,omitempty"`
	BodyObj interface{}       `json:"-" yaml:"-"`
}

type HTTPResponse struct {
	StatusCode int               `json:"statusCode" yaml:"statusCode"`
	Headers    map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Body       string            `json:"body,omitempty" yaml:"body,omitempty"`
	BodyBytes  []byte            `json:"-" yaml:"-"`
	Duration   time.Duration     `json:"duration" yaml:"duration"`
	Error      string            `json:"error,omitempty" yaml:"error,omitempty"`
	IsTimeout  bool              `json:"isTimeout,omitempty" yaml:"isTimeout,omitempty"`
	Request    *HTTPRequest      `json:"request,omitempty" yaml:"request,omitempty"`
}

type MutationMarker struct {
	Path        string      `json:"path" yaml:"path"`
	Original    interface{} `json:"original,omitempty" yaml:"original,omitempty"`
	Mutated     interface{} `json:"mutated,omitempty" yaml:"mutated,omitempty"`
	MutationType string     `json:"mutationType" yaml:"mutationType"`
}

type TestCase struct {
	ID              string            `json:"id" yaml:"id"`
	APISpec         *APISpec          `json:"apiSpec,omitempty" yaml:"apiSpec,omitempty"`
	APIPath         string            `json:"apiPath" yaml:"apiPath"`
	APIMethod       HTTPMethod        `json:"apiMethod" yaml:"apiMethod"`
	Name            string            `json:"name" yaml:"name"`
	Description     string            `json:"description,omitempty" yaml:"description,omitempty"`
	Request         *HTTPRequest      `json:"request" yaml:"request"`
	Auth            []*AuthConfig     `json:"auth,omitempty" yaml:"auth,omitempty"`
	Priority        int               `json:"priority" yaml:"priority"`
	Mutated         bool              `json:"mutated,omitempty" yaml:"mutated,omitempty"`
	MutationMarkers []*MutationMarker `json:"mutationMarkers,omitempty" yaml:"mutationMarkers,omitempty"`
	MutatedPath     []string          `json:"mutatedPath,omitempty" yaml:"mutatedPath,omitempty"`
	MutatedDesc     []string          `json:"mutatedDesc,omitempty" yaml:"mutatedDesc,omitempty"`
	Tags            []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	CreatedAt       time.Time         `json:"createdAt,omitempty" yaml:"createdAt,omitempty"`
}

type AnomalySeverity string

const (
	SeverityInfo     AnomalySeverity = "info"
	SeverityLow      AnomalySeverity = "low"
	SeverityMedium   AnomalySeverity = "medium"
	SeverityHigh     AnomalySeverity = "high"
	SeverityCritical AnomalySeverity = "critical"
)

func (s AnomalySeverity) Compare(other AnomalySeverity) int {
	order := map[AnomalySeverity]int{
		SeverityInfo:     0,
		SeverityLow:      1,
		SeverityMedium:   2,
		SeverityHigh:     3,
		SeverityCritical: 4,
	}
	return order[s] - order[other]
}

func (s AnomalySeverity) IsAtLeast(threshold AnomalySeverity) bool {
	return s.Compare(threshold) >= 0
}

type AnomalyType string

const (
	AnomalyServerError        AnomalyType = "server_error"
	AnomalyTimeout            AnomalyType = "timeout"
	AnomalyConnectionError    AnomalyType = "connection_error"
	AnomalySchemaMismatch     AnomalyType = "schema_mismatch"
	AnomalySensitiveInfoLeak  AnomalyType = "sensitive_info_leak"
	AnomalySlowResponse       AnomalyType = "slow_response"
	AnomalyAuthBypass         AnomalyType = "auth_bypass"
	AnomalyUnexpectedStatus   AnomalyType = "unexpected_status"
	AnomalyDifferStatus       AnomalyType = "differ_status"
	AnomalyDifferBody         AnomalyType = "differ_body"
	AnomalyDifferTime         AnomalyType = "differ_time"
	AnomalyRegressionFixed    AnomalyType = "regression_fixed"
	AnomalyRegressionUnfixed  AnomalyType = "regression_unfixed"
	AnomalyRegressionNew      AnomalyType = "regression_new"
)

type SchemaError struct {
	Path    string `json:"path" yaml:"path"`
	Message string `json:"message" yaml:"message"`
}

type LeakPattern struct {
	Name  string   `json:"name" yaml:"name"`
	Matches []string `json:"matches" yaml:"matches"`
}

type Anomaly struct {
	ID              string           `json:"id" yaml:"id"`
	TestCaseID      string           `json:"testCaseId" yaml:"testCaseId"`
	Type            AnomalyType      `json:"type" yaml:"type"`
	Severity        AnomalySeverity  `json:"severity" yaml:"severity"`
	Message         string           `json:"message" yaml:"message"`
	Description     string           `json:"description,omitempty" yaml:"description,omitempty"`
	Request         *HTTPRequest     `json:"request,omitempty" yaml:"request,omitempty"`
	Response        *HTTPResponse    `json:"response,omitempty" yaml:"response,omitempty"`
	SchemaErrors    []*SchemaError   `json:"schemaErrors,omitempty" yaml:"schemaErrors,omitempty"`
	LeakPatterns    []*LeakPattern   `json:"leakPatterns,omitempty" yaml:"leakPatterns,omitempty"`
	Response2       *HTTPResponse    `json:"response2,omitempty" yaml:"response2,omitempty"`
	MinimalCurl     string           `json:"minimalCurl,omitempty" yaml:"minimalCurl,omitempty"`
	APIPath         string           `json:"apiPath,omitempty" yaml:"apiPath,omitempty"`
	APIMethod       HTTPMethod       `json:"apiMethod,omitempty" yaml:"apiMethod,omitempty"`
	Timestamp       time.Time        `json:"timestamp" yaml:"timestamp"`
}
