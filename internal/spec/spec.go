package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"api-fuzzer/internal/types"
	"api-fuzzer/pkg/utils"

	"gopkg.in/yaml.v3"
)

type ParseError struct {
	File     string
	Line     int
	Column   int
	Path     string
	Message  string
	InnerErr error
}

func (e *ParseError) Error() string {
	loc := ""
	if e.File != "" {
		loc += fmt.Sprintf("%s", e.File)
		if e.Line > 0 {
			loc += fmt.Sprintf(":%d", e.Line)
			if e.Column > 0 {
				loc += fmt.Sprintf(":%d", e.Column)
			}
		}
	}
	if e.Path != "" {
		if loc != "" {
			loc += " "
		}
		loc += fmt.Sprintf("[%s]", e.Path)
	}
	if loc != "" {
		loc += ": "
	}
	result := loc + e.Message
	if e.InnerErr != nil {
		result += ": " + e.InnerErr.Error()
	}
	return result
}

func (e *ParseError) Unwrap() error {
	return e.InnerErr
}

type OpenAPI struct {
	OpenAPI           string                 `yaml:"openapi" json:"openapi"`
	Info              *Info                  `yaml:"info" json:"info"`
	Servers           []*Server              `yaml:"servers,omitempty" json:"servers,omitempty"`
	Paths             map[string]*PathItem   `yaml:"paths" json:"paths"`
	Components        *Components            `yaml:"components,omitempty" json:"components,omitempty"`
	Security          []SecurityRequirement  `yaml:"security,omitempty" json:"security,omitempty"`
	Tags              []*Tag                 `yaml:"tags,omitempty" json:"tags,omitempty"`
	ExternalDocs      *ExternalDocs          `yaml:"externalDocs,omitempty" json:"externalDocs,omitempty"`
}

type Info struct {
	Title          string   `yaml:"title" json:"title"`
	Description    string   `yaml:"description,omitempty" json:"description,omitempty"`
	TermsOfService string   `yaml:"termsOfService,omitempty" json:"termsOfService,omitempty"`
	Contact        *Contact `yaml:"contact,omitempty" json:"contact,omitempty"`
	License        *License `yaml:"license,omitempty" json:"license,omitempty"`
	Version        string   `yaml:"version" json:"version"`
}

type Contact struct {
	Name  string `yaml:"name,omitempty" json:"name,omitempty"`
	URL   string `yaml:"url,omitempty" json:"url,omitempty"`
	Email string `yaml:"email,omitempty" json:"email,omitempty"`
}

type License struct {
	Name       string `yaml:"name" json:"name"`
	URL        string `yaml:"url,omitempty" json:"url,omitempty"`
	Identifier string `yaml:"identifier,omitempty" json:"identifier,omitempty"`
}

type Server struct {
	URL         string                    `yaml:"url" json:"url"`
	Description string                    `yaml:"description,omitempty" json:"description,omitempty"`
	Variables   map[string]*ServerVariable `yaml:"variables,omitempty" json:"variables,omitempty"`
}

type ServerVariable struct {
	Enum        []string `yaml:"enum,omitempty" json:"enum,omitempty"`
	Default     string   `yaml:"default" json:"default"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
}

type Components struct {
	Schemas         map[string]*Schema         `yaml:"schemas,omitempty" json:"schemas,omitempty"`
	Responses       map[string]*Response       `yaml:"responses,omitempty" json:"responses,omitempty"`
	Parameters      map[string]*Parameter      `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	Examples        map[string]*Example        `yaml:"examples,omitempty" json:"examples,omitempty"`
	RequestBodies   map[string]*RequestBody    `yaml:"requestBodies,omitempty" json:"requestBodies,omitempty"`
	Headers         map[string]*Header         `yaml:"headers,omitempty" json:"headers,omitempty"`
	SecuritySchemes map[string]*SecurityScheme `yaml:"securitySchemes,omitempty" json:"securitySchemes,omitempty"`
	Links           map[string]*Link           `yaml:"links,omitempty" json:"links,omitempty"`
	Callbacks       map[string]map[string]*PathItem `yaml:"callbacks,omitempty" json:"callbacks,omitempty"`
}

type PathItem struct {
	Ref         string       `yaml:"$ref,omitempty" json:"$ref,omitempty"`
	Summary     string       `yaml:"summary,omitempty" json:"summary,omitempty"`
	Description string       `yaml:"description,omitempty" json:"description,omitempty"`
	Get         *Operation   `yaml:"get,omitempty" json:"get,omitempty"`
	Put         *Operation   `yaml:"put,omitempty" json:"put,omitempty"`
	Post        *Operation   `yaml:"post,omitempty" json:"post,omitempty"`
	Delete      *Operation   `yaml:"delete,omitempty" json:"delete,omitempty"`
	Options     *Operation   `yaml:"options,omitempty" json:"options,omitempty"`
	Head        *Operation   `yaml:"head,omitempty" json:"head,omitempty"`
	Patch       *Operation   `yaml:"patch,omitempty" json:"patch,omitempty"`
	Trace       *Operation   `yaml:"trace,omitempty" json:"trace,omitempty"`
	Servers     []*Server    `yaml:"servers,omitempty" json:"servers,omitempty"`
	Parameters  []*Parameter `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

type Operation struct {
	Tags         []string              `yaml:"tags,omitempty" json:"tags,omitempty"`
	Summary      string                `yaml:"summary,omitempty" json:"summary,omitempty"`
	Description  string                `yaml:"description,omitempty" json:"description,omitempty"`
	ExternalDocs *ExternalDocs         `yaml:"externalDocs,omitempty" json:"externalDocs,omitempty"`
	OperationID  string                `yaml:"operationId,omitempty" json:"operationId,omitempty"`
	Parameters   []*Parameter          `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	RequestBody  *RequestBody          `yaml:"requestBody,omitempty" json:"requestBody,omitempty"`
	Responses    map[string]*Response  `yaml:"responses" json:"responses"`
	Callbacks    map[string]map[string]*PathItem `yaml:"callbacks,omitempty" json:"callbacks,omitempty"`
	Deprecated   bool                  `yaml:"deprecated,omitempty" json:"deprecated,omitempty"`
	Security     []SecurityRequirement `yaml:"security,omitempty" json:"security,omitempty"`
	Servers      []*Server             `yaml:"servers,omitempty" json:"servers,omitempty"`
}

type ExternalDocs struct {
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	URL         string `yaml:"url" json:"url"`
}

type Parameter struct {
	Ref             string              `yaml:"$ref,omitempty" json:"$ref,omitempty"`
	Name            string              `yaml:"name,omitempty" json:"name,omitempty"`
	In              string              `yaml:"in,omitempty" json:"in,omitempty"`
	Description     string              `yaml:"description,omitempty" json:"description,omitempty"`
	Required        bool                `yaml:"required,omitempty" json:"required,omitempty"`
	Deprecated      bool                `yaml:"deprecated,omitempty" json:"deprecated,omitempty"`
	AllowEmptyValue bool                `yaml:"allowEmptyValue,omitempty" json:"allowEmptyValue,omitempty"`
	Style           string              `yaml:"style,omitempty" json:"style,omitempty"`
	Explode         *bool               `yaml:"explode,omitempty" json:"explode,omitempty"`
	AllowReserved   bool                `yaml:"allowReserved,omitempty" json:"allowReserved,omitempty"`
	Schema          *Schema             `yaml:"schema,omitempty" json:"schema,omitempty"`
	Example         interface{}         `yaml:"example,omitempty" json:"example,omitempty"`
	Examples        map[string]*Example `yaml:"examples,omitempty" json:"examples,omitempty"`
	Content         map[string]*MediaType `yaml:"content,omitempty" json:"content,omitempty"`
}

type RequestBody struct {
	Ref         string                  `yaml:"$ref,omitempty" json:"$ref,omitempty"`
	Description string                  `yaml:"description,omitempty" json:"description,omitempty"`
	Content     map[string]*MediaType   `yaml:"content,omitempty" json:"content,omitempty"`
	Required    bool                    `yaml:"required,omitempty" json:"required,omitempty"`
}

type MediaType struct {
	Schema   *Schema                `yaml:"schema,omitempty" json:"schema,omitempty"`
	Example  interface{}            `yaml:"example,omitempty" json:"example,omitempty"`
	Examples map[string]*Example    `yaml:"examples,omitempty" json:"examples,omitempty"`
	Encoding map[string]*Encoding   `yaml:"encoding,omitempty" json:"encoding,omitempty"`
}

type Encoding struct {
	ContentType   string            `yaml:"contentType,omitempty" json:"contentType,omitempty"`
	Headers       map[string]*Header `yaml:"headers,omitempty" json:"headers,omitempty"`
	Style         string            `yaml:"style,omitempty" json:"style,omitempty"`
	Explode       *bool             `yaml:"explode,omitempty" json:"explode,omitempty"`
	AllowReserved bool              `yaml:"allowReserved,omitempty" json:"allowReserved,omitempty"`
}

type Schema struct {
	Ref                  string              `yaml:"$ref,omitempty" json:"$ref,omitempty"`
	Type                 string              `yaml:"type,omitempty" json:"type,omitempty"`
	Format               string              `yaml:"format,omitempty" json:"format,omitempty"`
	Title                string              `yaml:"title,omitempty" json:"title,omitempty"`
	Description          string              `yaml:"description,omitempty" json:"description,omitempty"`
	Default              interface{}         `yaml:"default,omitempty" json:"default,omitempty"`
	Example              interface{}         `yaml:"example,omitempty" json:"example,omitempty"`
	Examples             interface{}         `yaml:"examples,omitempty" json:"examples,omitempty"`
	Enum                 []interface{}       `yaml:"enum,omitempty" json:"enum,omitempty"`
	Const                interface{}         `yaml:"const,omitempty" json:"const,omitempty"`
	MultipleOf           *float64            `yaml:"multipleOf,omitempty" json:"multipleOf,omitempty"`
	Maximum              *float64            `yaml:"maximum,omitempty" json:"maximum,omitempty"`
	ExclusiveMaximum     interface{}         `yaml:"exclusiveMaximum,omitempty" json:"exclusiveMaximum,omitempty"`
	Minimum              *float64            `yaml:"minimum,omitempty" json:"minimum,omitempty"`
	ExclusiveMinimum     interface{}         `yaml:"exclusiveMinimum,omitempty" json:"exclusiveMinimum,omitempty"`
	MaxLength            *int64              `yaml:"maxLength,omitempty" json:"maxLength,omitempty"`
	MinLength            *int64              `yaml:"minLength,omitempty" json:"minLength,omitempty"`
	Pattern              string              `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	MaxItems             *int64              `yaml:"maxItems,omitempty" json:"maxItems,omitempty"`
	MinItems             *int64              `yaml:"minItems,omitempty" json:"minItems,omitempty"`
	UniqueItems          *bool               `yaml:"uniqueItems,omitempty" json:"uniqueItems,omitempty"`
	MaxContains          *int64              `yaml:"maxContains,omitempty" json:"maxContains,omitempty"`
	MinContains          *int64              `yaml:"minContains,omitempty" json:"minContains,omitempty"`
	MaxProperties        *int64              `yaml:"maxProperties,omitempty" json:"maxProperties,omitempty"`
	MinProperties        *int64              `yaml:"minProperties,omitempty" json:"minProperties,omitempty"`
	Required             []string            `yaml:"required,omitempty" json:"required,omitempty"`
	Items                *Schema             `yaml:"items,omitempty" json:"items,omitempty"`
	Contains             *Schema             `yaml:"contains,omitempty" json:"contains,omitempty"`
	Properties           map[string]*Schema  `yaml:"properties,omitempty" json:"properties,omitempty"`
	PatternProperties    map[string]*Schema  `yaml:"patternProperties,omitempty" json:"patternProperties,omitempty"`
	AdditionalProperties interface{}         `yaml:"additionalProperties,omitempty" json:"additionalProperties,omitempty"`
	PropertyNames        *Schema             `yaml:"propertyNames,omitempty" json:"propertyNames,omitempty"`
	AllOf                []*Schema           `yaml:"allOf,omitempty" json:"allOf,omitempty"`
	AnyOf                []*Schema           `yaml:"anyOf,omitempty" json:"anyOf,omitempty"`
	OneOf                []*Schema           `yaml:"oneOf,omitempty" json:"oneOf,omitempty"`
	Not                  *Schema             `yaml:"not,omitempty" json:"not,omitempty"`
	If                   *Schema             `yaml:"if,omitempty" json:"if,omitempty"`
	Then                 *Schema             `yaml:"then,omitempty" json:"then,omitempty"`
	Else                 *Schema             `yaml:"else,omitempty" json:"else,omitempty"`
	DependentRequired    map[string][]string `yaml:"dependentRequired,omitempty" json:"dependentRequired,omitempty"`
	DependentSchemas     map[string]*Schema  `yaml:"dependentSchemas,omitempty" json:"dependentSchemas,omitempty"`
	Nullable             bool                `yaml:"nullable,omitempty" json:"nullable,omitempty"`
	Discriminator        *Discriminator      `yaml:"discriminator,omitempty" json:"discriminator,omitempty"`
	ReadOnly             bool                `yaml:"readOnly,omitempty" json:"readOnly,omitempty"`
	WriteOnly            bool                `yaml:"writeOnly,omitempty" json:"writeOnly,omitempty"`
	XML                  *XML                `yaml:"xml,omitempty" json:"xml,omitempty"`
	ExternalDocs         *ExternalDocs       `yaml:"externalDocs,omitempty" json:"externalDocs,omitempty"`
	Deprecated           bool                `yaml:"deprecated,omitempty" json:"deprecated,omitempty"`
}

type Discriminator struct {
	PropertyName string            `yaml:"propertyName" json:"propertyName"`
	Mapping      map[string]string `yaml:"mapping,omitempty" json:"mapping,omitempty"`
}

type XML struct {
	Name      string `yaml:"name,omitempty" json:"name,omitempty"`
	Namespace string `yaml:"namespace,omitempty" json:"namespace,omitempty"`
	Prefix    string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Attribute bool   `yaml:"attribute,omitempty" json:"attribute,omitempty"`
	Wrapped   bool   `yaml:"wrapped,omitempty" json:"wrapped,omitempty"`
}

type Response struct {
	Ref         string                  `yaml:"$ref,omitempty" json:"$ref,omitempty"`
	Description string                  `yaml:"description" json:"description"`
	Headers     map[string]*Header      `yaml:"headers,omitempty" json:"headers,omitempty"`
	Content     map[string]*MediaType   `yaml:"content,omitempty" json:"content,omitempty"`
	Links       map[string]*Link        `yaml:"links,omitempty" json:"links,omitempty"`
}

type Header struct {
	Ref             string              `yaml:"$ref,omitempty" json:"$ref,omitempty"`
	Description     string              `yaml:"description,omitempty" json:"description,omitempty"`
	Required        bool                `yaml:"required,omitempty" json:"required,omitempty"`
	Deprecated      bool                `yaml:"deprecated,omitempty" json:"deprecated,omitempty"`
	AllowEmptyValue bool                `yaml:"allowEmptyValue,omitempty" json:"allowEmptyValue,omitempty"`
	Style           string              `yaml:"style,omitempty" json:"style,omitempty"`
	Explode         *bool               `yaml:"explode,omitempty" json:"explode,omitempty"`
	AllowReserved   bool                `yaml:"allowReserved,omitempty" json:"allowReserved,omitempty"`
	Schema          *Schema             `yaml:"schema,omitempty" json:"schema,omitempty"`
	Example         interface{}         `yaml:"example,omitempty" json:"example,omitempty"`
	Examples        map[string]*Example `yaml:"examples,omitempty" json:"examples,omitempty"`
	Content         map[string]*MediaType `yaml:"content,omitempty" json:"content,omitempty"`
}

type Example struct {
	Ref           string      `yaml:"$ref,omitempty" json:"$ref,omitempty"`
	Summary       string      `yaml:"summary,omitempty" json:"summary,omitempty"`
	Description   string      `yaml:"description,omitempty" json:"description,omitempty"`
	Value         interface{} `yaml:"value,omitempty" json:"value,omitempty"`
	ExternalValue string      `yaml:"externalValue,omitempty" json:"externalValue,omitempty"`
}

type Link struct {
	Ref          string                 `yaml:"$ref,omitempty" json:"$ref,omitempty"`
	OperationRef string                 `yaml:"operationRef,omitempty" json:"operationRef,omitempty"`
	OperationID  string                 `yaml:"operationId,omitempty" json:"operationId,omitempty"`
	Parameters   map[string]interface{} `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	RequestBody  interface{}            `yaml:"requestBody,omitempty" json:"requestBody,omitempty"`
	Description  string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Server       *Server                `yaml:"server,omitempty" json:"server,omitempty"`
}

type Tag struct {
	Name         string        `yaml:"name" json:"name"`
	Description  string        `yaml:"description,omitempty" json:"description,omitempty"`
	ExternalDocs *ExternalDocs `yaml:"externalDocs,omitempty" json:"externalDocs,omitempty"`
}

type SecurityScheme struct {
	Type             string       `yaml:"type" json:"type"`
	Description      string       `yaml:"description,omitempty" json:"description,omitempty"`
	Name             string       `yaml:"name,omitempty" json:"name,omitempty"`
	In               string       `yaml:"in,omitempty" json:"in,omitempty"`
	Scheme           string       `yaml:"scheme,omitempty" json:"scheme,omitempty"`
	BearerFormat     string       `yaml:"bearerFormat,omitempty" json:"bearerFormat,omitempty"`
	Flows            *OAuthFlows  `yaml:"flows,omitempty" json:"flows,omitempty"`
	OpenIDConnectURL string       `yaml:"openIdConnectUrl,omitempty" json:"openIdConnectUrl,omitempty"`
}

type OAuthFlows struct {
	Implicit          *OAuthFlow `yaml:"implicit,omitempty" json:"implicit,omitempty"`
	Password          *OAuthFlow `yaml:"password,omitempty" json:"password,omitempty"`
	ClientCredentials *OAuthFlow `yaml:"clientCredentials,omitempty" json:"clientCredentials,omitempty"`
	AuthorizationCode *OAuthFlow `yaml:"authorizationCode,omitempty" json:"authorizationCode,omitempty"`
}

type OAuthFlow struct {
	AuthorizationURL string            `yaml:"authorizationUrl,omitempty" json:"authorizationUrl,omitempty"`
	TokenURL         string            `yaml:"tokenUrl,omitempty" json:"tokenUrl,omitempty"`
	RefreshURL       string            `yaml:"refreshUrl,omitempty" json:"refreshUrl,omitempty"`
	Scopes           map[string]string `yaml:"scopes" json:"scopes"`
}

type SecurityRequirement map[string][]string

type resolverContext struct {
	currentFile  string
	loadedFiles  map[string]*OpenAPI
	loadedNodes  map[string]*yaml.Node
	visitedRefs  map[string]bool
	resolveDepth int
	maxDepth     int
}

func newResolverContext(filename string) *resolverContext {
	return &resolverContext{
		currentFile: filename,
		loadedFiles: make(map[string]*OpenAPI),
		loadedNodes: make(map[string]*yaml.Node),
		visitedRefs: make(map[string]bool),
		maxDepth:    100,
	}
}

func LoadOpenAPI(filename string) ([]*types.APISpec, error) {
	absPath, err := filepath.Abs(filename)
	if err != nil {
		return nil, &ParseError{
			File:    filename,
			Message: fmt.Sprintf("无法获取绝对路径: %v", err),
		}
	}

	ctx := newResolverContext(absPath)

	rootNode, err := loadFileAsNode(absPath)
	if err != nil {
		return nil, err
	}

	var doc OpenAPI
	if err := nodeToValue(rootNode, &doc, absPath, ""); err != nil {
		return nil, err
	}
	ctx.loadedFiles[absPath] = &doc

	if err := resolveAllRefs(ctx, absPath, rootNode); err != nil {
		return nil, err
	}

	if err := nodeToValue(rootNode, &doc, absPath, ""); err != nil {
		return nil, err
	}

	return convertToAPISpecs(ctx, absPath, &doc, rootNode)
}

func loadFileAsNode(filename string) (*yaml.Node, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, &ParseError{
			File:     filename,
			Message:  "读取文件失败",
			InnerErr: err,
		}
	}

	fileType := utils.DetectFileType(filename)
	if fileType == "" {
		fileType = utils.DetectFileTypeByContent(data)
	}

	var root yaml.Node
	switch fileType {
	case "json":
		var raw interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, &ParseError{
				File:     filename,
				Message:  "JSON 解析失败",
				InnerErr: err,
			}
		}
		yamlData, err := yaml.Marshal(raw)
		if err != nil {
			return nil, &ParseError{
				File:    filename,
				Message: "JSON 转 YAML 失败",
			}
		}
		if err := yaml.Unmarshal(yamlData, &root); err != nil {
			return nil, &ParseError{
				File:     filename,
				Message:  "解析失败",
				InnerErr: err,
			}
		}
	case "yaml", "":
		if err := yaml.Unmarshal(data, &root); err != nil {
			return nil, &ParseError{
				File:     filename,
				Message:  "YAML 解析失败",
				InnerErr: err,
			}
		}
	default:
		return nil, &ParseError{
			File:    filename,
			Message: fmt.Sprintf("不支持的文件格式: %s", fileType),
		}
	}

	actualRoot := &root
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		actualRoot = root.Content[0]
	}
	return actualRoot, nil
}

func nodeToValue(node *yaml.Node, out interface{}, file, path string) error {
	if node == nil {
		return nil
	}
	switch n := out.(type) {
	case **OpenAPI:
		var v OpenAPI
		if err := node.Decode(&v); err != nil {
			return newParseError(file, node, path, "解析 OpenAPI 失败", err)
		}
		*n = &v
	case *OpenAPI:
		if err := node.Decode(n); err != nil {
			return newParseError(file, node, path, "解析 OpenAPI 失败", err)
		}
	case **Schema:
		var v Schema
		if err := node.Decode(&v); err != nil {
			return newParseError(file, node, path, "解析 Schema 失败", err)
		}
		*n = &v
	case *Schema:
		if err := node.Decode(n); err != nil {
			return newParseError(file, node, path, "解析 Schema 失败", err)
		}
	case **Parameter:
		var v Parameter
		if err := node.Decode(&v); err != nil {
			return newParseError(file, node, path, "解析 Parameter 失败", err)
		}
		*n = &v
	case **RequestBody:
		var v RequestBody
		if err := node.Decode(&v); err != nil {
			return newParseError(file, node, path, "解析 RequestBody 失败", err)
		}
		*n = &v
	case **Response:
		var v Response
		if err := node.Decode(&v); err != nil {
			return newParseError(file, node, path, "解析 Response 失败", err)
		}
		*n = &v
	case **PathItem:
		var v PathItem
		if err := node.Decode(&v); err != nil {
			return newParseError(file, node, path, "解析 PathItem 失败", err)
		}
		*n = &v
	case **SecurityScheme:
		var v SecurityScheme
		if err := node.Decode(&v); err != nil {
			return newParseError(file, node, path, "解析 SecurityScheme 失败", err)
		}
		*n = &v
	case map[string]*Schema:
		return decodeMap(node, n, file, path, "Schema", func() *Schema { return &Schema{} })
	case map[string]*Parameter:
		return decodeMap(node, n, file, path, "Parameter", func() *Parameter { return &Parameter{} })
	case map[string]*Response:
		return decodeMap(node, n, file, path, "Response", func() *Response { return &Response{} })
	case map[string]*RequestBody:
		return decodeMap(node, n, file, path, "RequestBody", func() *RequestBody { return &RequestBody{} })
	case map[string]*SecurityScheme:
		return decodeMap(node, n, file, path, "SecurityScheme", func() *SecurityScheme { return &SecurityScheme{} })
	case map[string]*MediaType:
		return decodeMap(node, n, file, path, "MediaType", func() *MediaType { return &MediaType{} })
	default:
		if err := node.Decode(out); err != nil {
			return newParseError(file, node, path, "解析失败", err)
		}
	}
	return nil
}

func decodeMap[T any](node *yaml.Node, out map[string]T, file, path, typeName string, newFunc func() T) error {
	if node.Kind != yaml.MappingNode {
		return newParseError(file, node, path, fmt.Sprintf("期望映射类型作为 %s", typeName), nil)
	}
	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valNode := node.Content[i+1]
		var key string
		if err := keyNode.Decode(&key); err != nil {
			return newParseError(file, keyNode, fmt.Sprintf("%s.%s", path, key), "解析键失败", err)
		}
		val := newFunc()
		if err := nodeToValue(valNode, val, file, fmt.Sprintf("%s.%s", path, key)); err != nil {
			return err
		}
		out[key] = val
	}
	return nil
}

func newParseError(file string, node *yaml.Node, path string, message string, inner error) *ParseError {
	pe := &ParseError{
		File:     file,
		Message:  message,
		Path:     path,
		InnerErr: inner,
	}
	if node != nil {
		pe.Line = node.Line
		pe.Column = node.Column
	}
	return pe
}

func resolveAllRefs(ctx *resolverContext, filename string, node *yaml.Node) error {
	ctx.resolveDepth = 0
	return resolveNodeRefs(ctx, filename, node, "")
}

func resolveNodeRefs(ctx *resolverContext, filename string, node *yaml.Node, path string) error {
	if node == nil {
		return nil
	}

	if ctx.resolveDepth > ctx.maxDepth {
		return &ParseError{
			File:    filename,
			Line:    node.Line,
			Column:  node.Column,
			Path:    path,
			Message: "超过最大引用解析深度，可能存在循环引用",
		}
	}

	if node.Kind == yaml.MappingNode {
		hasRef := false
		var refValue string
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			var key string
			_ = keyNode.Decode(&key)
			if key == "$ref" && i+1 < len(node.Content) {
				_ = node.Content[i+1].Decode(&refValue)
				hasRef = true
				break
			}
		}

		if hasRef && refValue != "" {
			ctx.resolveDepth++
			defer func() { ctx.resolveDepth-- }()
			return resolveAndReplaceRef(ctx, filename, node, refValue, path)
		}

		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valNode := node.Content[i+1]
			var key string
			_ = keyNode.Decode(&key)
			if err := resolveNodeRefs(ctx, filename, valNode, fmt.Sprintf("%s.%s", path, key)); err != nil {
				return err
			}
		}
	} else if node.Kind == yaml.SequenceNode {
		for i, child := range node.Content {
			if err := resolveNodeRefs(ctx, filename, child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	} else if node.Kind == yaml.DocumentNode {
		for _, child := range node.Content {
			if err := resolveNodeRefs(ctx, filename, child, path); err != nil {
				return err
			}
		}
	}

	return nil
}

func resolveAndReplaceRef(ctx *resolverContext, filename string, node *yaml.Node, ref string, path string) error {
	refKey := fmt.Sprintf("%s::%s", filename, ref)
	if ctx.visitedRefs[refKey] {
		return &ParseError{
			File:    filename,
			Line:    node.Line,
			Column:  node.Column,
			Path:    path,
			Message: fmt.Sprintf("检测到循环引用: %s", ref),
		}
	}
	ctx.visitedRefs[refKey] = true
	defer delete(ctx.visitedRefs, refKey)

	targetFile, jsonPath := utils.SplitRef(ref)
	var targetNode *yaml.Node
	var targetFileAbs string

	if targetFile == "" {
		targetFileAbs = filename
		rootNode, err := loadFileAsNode(filename)
		if err != nil {
			return err
		}
		targetNode = rootNode
	} else {
		targetFileAbs = utils.ResolvePath(filename, targetFile)
		var err error
		targetNode, err = loadFileAsNode(targetFileAbs)
		if err != nil {
			return &ParseError{
				File:     filename,
				Line:     node.Line,
				Column:   node.Column,
				Path:     path,
				Message:  fmt.Sprintf("加载外部引用文件失败: %s", targetFile),
				InnerErr: err,
			}
		}
	}

	pathParts := utils.ParseJSONPath(jsonPath)
	resolvedNode, err := navigateNode(targetNode, pathParts, targetFileAbs, path, ref)
	if err != nil {
		return err
	}

	if resolvedNode == nil {
		return &ParseError{
			File:    targetFileAbs,
			Line:    node.Line,
			Column:  node.Column,
			Path:    path,
			Message: fmt.Sprintf("引用路径不存在: %s", ref),
		}
	}

	if err := resolveNodeRefs(ctx, targetFileAbs, resolvedNode, path); err != nil {
		return err
	}

	*node = *resolvedNode
	return nil
}

func navigateNode(node *yaml.Node, parts []string, file, path, ref string) (*yaml.Node, error) {
	current := node
	for i, part := range parts {
		if current == nil {
			return nil, &ParseError{
				File:    file,
				Path:    path,
				Message: fmt.Sprintf("引用路径为空，导航失败: %s (在 %s)", ref, strings.Join(parts[:i], "/")),
			}
		}
		switch current.Kind {
		case yaml.MappingNode:
			found := false
			for j := 0; j < len(current.Content); j += 2 {
				var key string
				_ = current.Content[j].Decode(&key)
				if key == part {
					current = current.Content[j+1]
					found = true
					break
				}
			}
			if !found {
				return nil, &ParseError{
					File:    file,
					Line:    current.Line,
					Column:  current.Column,
					Path:    path,
					Message: fmt.Sprintf("引用路径中找不到键: %s (完整路径: %s)", part, ref),
				}
			}
		case yaml.SequenceNode:
			idx := 0
			fmt.Sscanf(part, "%d", &idx)
			if idx < 0 || idx >= len(current.Content) {
				return nil, &ParseError{
					File:    file,
					Line:    current.Line,
					Column:  current.Column,
					Path:    path,
					Message: fmt.Sprintf("引用路径数组索引越界: %s (完整路径: %s)", part, ref),
				}
			}
			current = current.Content[idx]
		case yaml.DocumentNode:
			if len(current.Content) > 0 {
				current = current.Content[0]
				i--
			} else {
				return nil, &ParseError{
					File:    file,
					Path:    path,
					Message: fmt.Sprintf("引用路径中遇到空文档节点: %s", ref),
				}
			}
		default:
			return nil, &ParseError{
				File:    file,
				Line:    current.Line,
				Column:  current.Column,
				Path:    path,
				Message: fmt.Sprintf("引用路径中遇到不可导航节点类型，期望映射或序列，路径: %s (完整: %s)", strings.Join(parts[:i+1], "/"), ref),
			}
		}
	}
	return current, nil
}

func convertToAPISpecs(ctx *resolverContext, filename string, doc *OpenAPI, rootNode *yaml.Node) ([]*types.APISpec, error) {
	if doc == nil {
		return nil, &ParseError{
			File:    filename,
			Message: "OpenAPI 文档为空",
		}
	}

	if doc.OpenAPI == "" {
		return nil, &ParseError{
			File:    filename,
			Message: "缺少 'openapi' 字段，不是有效的 OpenAPI 3.0/3.1 文档",
		}
	}

	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		return nil, &ParseError{
			File:    filename,
			Message: fmt.Sprintf("不支持的 OpenAPI 版本: %s，仅支持 3.0.x 和 3.1.x", doc.OpenAPI),
		}
	}

	if doc.Paths == nil || len(doc.Paths) == 0 {
		return nil, &ParseError{
			File:    filename,
			Message: "缺少 'paths' 字段或为空",
		}
	}

	globalSecurity := doc.Security
	globalServers := convertServers(doc.Servers)
	securitySchemes := make(map[string]*types.AuthConfig)

	if doc.Components != nil && doc.Components.SecuritySchemes != nil {
		for name, scheme := range doc.Components.SecuritySchemes {
			auth := convertSecurityScheme(name, scheme)
			if auth != nil {
				securitySchemes[name] = auth
			}
		}
	}

	var specs []*types.APISpec

	for pathVal, pathItem := range doc.Paths {
		pathNode := findPathNode(rootNode, "paths", pathVal)
		if pathItem == nil {
			continue
		}

		pathParams := make([]*types.ParameterSpec, 0)
		if pathItem.Parameters != nil {
			for _, p := range pathItem.Parameters {
				pathParams = append(pathParams, convertParameter(p))
			}
		}

		methods := []struct {
			method    types.HTTPMethod
			operation *Operation
			key       string
		}{
			{types.MethodGet, pathItem.Get, "get"},
			{types.MethodPost, pathItem.Post, "post"},
			{types.MethodPut, pathItem.Put, "put"},
			{types.MethodDelete, pathItem.Delete, "delete"},
			{types.MethodPatch, pathItem.Patch, "patch"},
			{types.MethodHead, pathItem.Head, "head"},
			{types.MethodOptions, pathItem.Options, "options"},
			{types.HTTPMethod("TRACE"), pathItem.Trace, "trace"},
		}

		for _, m := range methods {
			if m.operation == nil {
				continue
			}

			opNode := findPathNode(pathNode, m.key)

			spec, err := convertOperation(ctx, filename, pathVal, m.method, m.operation, opNode,
				pathParams, globalServers, globalSecurity, securitySchemes)
			if err != nil {
				return nil, err
			}
			specs = append(specs, spec)
		}
	}

	return specs, nil
}

func findPathNode(node *yaml.Node, keys ...string) *yaml.Node {
	current := node
	for _, key := range keys {
		if current == nil {
			return nil
		}
		if current.Kind == yaml.DocumentNode && len(current.Content) > 0 {
			current = current.Content[0]
		}
		if current.Kind != yaml.MappingNode {
			return nil
		}
		found := false
		for j := 0; j < len(current.Content); j += 2 {
			var k string
			_ = current.Content[j].Decode(&k)
			if k == key {
				current = current.Content[j+1]
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	return current
}

func convertOperation(
	ctx *resolverContext,
	filename string,
	path string,
	method types.HTTPMethod,
	op *Operation,
	opNode *yaml.Node,
	pathParams []*types.ParameterSpec,
	globalServers []*types.ServerInfo,
	globalSecurity []SecurityRequirement,
	securitySchemes map[string]*types.AuthConfig,
) (*types.APISpec, error) {
	spec := &types.APISpec{
		Path:          path,
		Method:        method,
		Summary:       op.Summary,
		Description:   op.Description,
		Tags:          op.Tags,
		OperationID:   op.OperationID,
		Deprecated:    op.Deprecated,
		Parameters:    make([]*types.ParameterSpec, 0),
		Responses:     make(map[string]*types.ResponseSpec),
		ResponseSchema: make(map[string]*types.Schema),
	}

	paramSet := make(map[string]bool)
	for _, p := range pathParams {
		key := fmt.Sprintf("%s_%s", p.In, p.Name)
		paramSet[key] = true
		spec.Parameters = append(spec.Parameters, p)
	}
	if op.Parameters != nil {
		for _, p := range op.Parameters {
			converted := convertParameter(p)
			if converted != nil {
				key := fmt.Sprintf("%s_%s", converted.In, converted.Name)
				if !paramSet[key] {
					paramSet[key] = true
					spec.Parameters = append(spec.Parameters, converted)
				}
			}
		}
	}

	if op.RequestBody != nil {
		spec.RequestBody = convertRequestBody(op.RequestBody)
	}

	if op.Responses != nil {
		for status, resp := range op.Responses {
			convertedResp := convertResponse(resp)
			if convertedResp != nil {
				spec.Responses[status] = convertedResp
				spec.ResponseSchema[status] = extractResponseSchema(convertedResp)
			}
		}
	}

	if op.Servers != nil && len(op.Servers) > 0 {
		spec.Servers = convertServers(op.Servers)
	} else {
		spec.Servers = globalServers
	}

	security := op.Security
	if security == nil {
		security = globalSecurity
	}
	spec.Security = convertSecurityRequirements(security)
	spec.Auth = resolveAuthConfigs(security, securitySchemes)

	return spec, nil
}

func convertServers(servers []*Server) []*types.ServerInfo {
	if servers == nil {
		return nil
	}
	result := make([]*types.ServerInfo, 0, len(servers))
	for _, s := range servers {
		si := &types.ServerInfo{
			URL:         s.URL,
			Description: s.Description,
		}
		if s.Variables != nil {
			si.Variables = make(map[string]*types.ServerVariable)
			for k, v := range s.Variables {
				si.Variables[k] = &types.ServerVariable{
					Enum:        v.Enum,
					Default:     v.Default,
					Description: v.Description,
				}
			}
		}
		result = append(result, si)
	}
	return result
}

func convertParameter(p *Parameter) *types.ParameterSpec {
	if p == nil {
		return nil
	}
	return &types.ParameterSpec{
		Name:            p.Name,
		In:              types.ParameterLocation(p.In),
		Description:     p.Description,
		Required:        p.Required,
		Deprecated:      p.Deprecated,
		AllowEmptyValue: p.AllowEmptyValue,
		Style:           p.Style,
		Explode:         p.Explode,
		AllowReserved:   p.AllowReserved,
		Schema:          convertSchema(p.Schema),
		Example:         p.Example,
	}
}

func convertRequestBody(rb *RequestBody) *types.RequestBodySpec {
	if rb == nil {
		return nil
	}
	result := &types.RequestBodySpec{
		Description: rb.Description,
		Required:    rb.Required,
		Content:     make(map[string]*types.MediaTypeSpec),
	}
	for ct, mt := range rb.Content {
		result.Content[ct] = convertMediaType(mt)
	}
	return result
}

func convertResponse(r *Response) *types.ResponseSpec {
	if r == nil {
		return nil
	}
	result := &types.ResponseSpec{
		Description: r.Description,
		Content:     make(map[string]*types.MediaTypeSpec),
	}
	if r.Headers != nil {
		result.Headers = make(map[string]*types.Header)
		for k, h := range r.Headers {
			result.Headers[k] = &types.Header{
				Description:     h.Description,
				Required:        h.Required,
				Deprecated:      h.Deprecated,
				AllowEmptyValue: h.AllowEmptyValue,
				Schema:          convertSchema(h.Schema),
				Example:         h.Example,
			}
		}
	}
	for ct, mt := range r.Content {
		result.Content[ct] = convertMediaType(mt)
	}
	return result
}

func convertMediaType(mt *MediaType) *types.MediaTypeSpec {
	if mt == nil {
		return nil
	}
	return &types.MediaTypeSpec{
		Schema:  convertSchema(mt.Schema),
		Example: mt.Example,
	}
}

func convertSchema(s *Schema) *types.Schema {
	if s == nil {
		return nil
	}
	result := &types.Schema{
		Type:                 s.Type,
		Format:               s.Format,
		Title:                s.Title,
		Description:          s.Description,
		Default:              s.Default,
		Example:              s.Example,
		Enum:                 s.Enum,
		Const:                s.Const,
		MultipleOf:           s.MultipleOf,
		Maximum:              s.Maximum,
		Minimum:              s.Minimum,
		MaxLength:            s.MaxLength,
		MinLength:            s.MinLength,
		Pattern:              s.Pattern,
		MaxItems:             s.MaxItems,
		MinItems:             s.MinItems,
		UniqueItems:          s.UniqueItems,
		MaxProperties:        s.MaxProperties,
		MinProperties:        s.MinProperties,
		Required:             s.Required,
		Nullable:             s.Nullable,
		ReadOnly:             s.ReadOnly,
		WriteOnly:            s.WriteOnly,
		Ref:                  s.Ref,
	}

	if s.ExclusiveMaximum != nil {
		switch v := s.ExclusiveMaximum.(type) {
		case bool:
			if v && s.Maximum != nil {
				m := *s.Maximum
				result.ExclusiveMaximum = &m
			}
		case float64:
			result.ExclusiveMaximum = &v
		case int:
			f := float64(v)
			result.ExclusiveMaximum = &f
		}
	}
	if s.ExclusiveMinimum != nil {
		switch v := s.ExclusiveMinimum.(type) {
		case bool:
			if v && s.Minimum != nil {
				m := *s.Minimum
				result.ExclusiveMinimum = &m
			}
		case float64:
			result.ExclusiveMinimum = &v
		case int:
			f := float64(v)
			result.ExclusiveMinimum = &f
		}
	}

	if s.Items != nil {
		result.Items = convertSchema(s.Items)
	}
	if s.Properties != nil {
		result.Properties = make(map[string]*types.Schema)
		for k, v := range s.Properties {
			result.Properties[k] = convertSchema(v)
		}
	}
	if s.AdditionalProperties != nil {
		switch v := s.AdditionalProperties.(type) {
		case *Schema:
			result.AdditionalProperties = convertSchema(v)
		case bool:
			if v {
				result.AdditionalProperties = &types.Schema{}
			} else {
				result.AdditionalProperties = nil
			}
		}
	}
	if s.AllOf != nil {
		result.AllOf = make([]*types.Schema, 0, len(s.AllOf))
		for _, v := range s.AllOf {
			result.AllOf = append(result.AllOf, convertSchema(v))
		}
	}
	if s.AnyOf != nil {
		result.AnyOf = make([]*types.Schema, 0, len(s.AnyOf))
		for _, v := range s.AnyOf {
			result.AnyOf = append(result.AnyOf, convertSchema(v))
		}
	}
	if s.OneOf != nil {
		result.OneOf = make([]*types.Schema, 0, len(s.OneOf))
		for _, v := range s.OneOf {
			result.OneOf = append(result.OneOf, convertSchema(v))
		}
	}
	if s.Not != nil {
		result.Not = convertSchema(s.Not)
	}
	if s.Discriminator != nil {
		result.Discriminator = &types.Discriminator{
			PropertyName: s.Discriminator.PropertyName,
			Mapping:      s.Discriminator.Mapping,
		}
	}
	if s.XML != nil {
		result.XML = &types.XML{
			Name:      s.XML.Name,
			Namespace: s.XML.Namespace,
			Prefix:    s.XML.Prefix,
			Attribute: s.XML.Attribute,
			Wrapped:   s.XML.Wrapped,
		}
	}
	if s.ExternalDocs != nil {
		result.ExternalDocs = &types.ExternalDocs{
			Description: s.ExternalDocs.Description,
			URL:         s.ExternalDocs.URL,
		}
	}
	return result
}

func extractResponseSchema(resp *types.ResponseSpec) *types.Schema {
	if resp == nil || resp.Content == nil {
		return nil
	}
	for _, mt := range resp.Content {
		if mt != nil && mt.Schema != nil {
			return mt.Schema
		}
	}
	return nil
}

func convertSecurityScheme(name string, s *SecurityScheme) *types.AuthConfig {
	if s == nil {
		return nil
	}
	auth := &types.AuthConfig{
		Name:        name,
		Description: s.Description,
	}
	switch strings.ToLower(s.Type) {
	case "http":
		switch strings.ToLower(s.Scheme) {
		case "bearer":
			auth.Type = types.AuthTypeBearer
			auth.Scheme = "bearer"
			auth.BearerFormat = s.BearerFormat
		case "basic":
			auth.Type = types.AuthTypeBasic
			auth.Scheme = "basic"
		default:
			auth.Type = types.AuthTypeBearer
			auth.Scheme = s.Scheme
		}
	case "apikey":
		auth.Type = types.AuthTypeAPIKey
		auth.APIKeyName = s.Name
		auth.In = types.APIKeyLocation(s.In)
	case "oauth2":
		auth.Type = types.AuthTypeOAuth2
		if s.Flows != nil {
			auth.Flows = &types.OAuth2Flows{}
			if s.Flows.Implicit != nil {
				auth.Flows.Implicit = &types.OAuth2Flow{
					AuthorizationURL: s.Flows.Implicit.AuthorizationURL,
					RefreshURL:       s.Flows.Implicit.RefreshURL,
					Scopes:           s.Flows.Implicit.Scopes,
				}
			}
			if s.Flows.Password != nil {
				auth.Flows.Password = &types.OAuth2Flow{
					TokenURL:   s.Flows.Password.TokenURL,
					RefreshURL: s.Flows.Password.RefreshURL,
					Scopes:     s.Flows.Password.Scopes,
				}
			}
			if s.Flows.ClientCredentials != nil {
				auth.Flows.ClientCredentials = &types.OAuth2Flow{
					TokenURL:   s.Flows.ClientCredentials.TokenURL,
					RefreshURL: s.Flows.ClientCredentials.RefreshURL,
					Scopes:     s.Flows.ClientCredentials.Scopes,
				}
			}
			if s.Flows.AuthorizationCode != nil {
				auth.Flows.AuthorizationCode = &types.OAuth2Flow{
					AuthorizationURL: s.Flows.AuthorizationCode.AuthorizationURL,
					TokenURL:         s.Flows.AuthorizationCode.TokenURL,
					RefreshURL:       s.Flows.AuthorizationCode.RefreshURL,
					Scopes:           s.Flows.AuthorizationCode.Scopes,
				}
			}
		}
	case "openidconnect":
		auth.Type = types.AuthTypeOAuth2
	}
	return auth
}

func convertSecurityRequirements(security []SecurityRequirement) []types.SecurityRequirementSpec {
	if security == nil {
		return nil
	}
	result := make([]types.SecurityRequirementSpec, 0, len(security))
	for _, req := range security {
		spec := make(types.SecurityRequirementSpec)
		for k, v := range req {
			spec[k] = v
		}
		result = append(result, spec)
	}
	return result
}

func resolveAuthConfigs(security []SecurityRequirement, schemes map[string]*types.AuthConfig) []*types.AuthConfig {
	if len(security) == 0 {
		return nil
	}
	result := make([]*types.AuthConfig, 0)
	seen := make(map[string]bool)
	for _, req := range security {
		for name, scopes := range req {
			if scheme, ok := schemes[name]; ok {
				clone := cloneAuthConfig(scheme)
				if len(scopes) > 0 {
					clone.Scopes = scopes
				}
				key := authConfigKey(clone)
				if !seen[key] {
					seen[key] = true
					result = append(result, clone)
				}
			}
		}
	}
	return result
}

func cloneAuthConfig(a *types.AuthConfig) *types.AuthConfig {
	if a == nil {
		return nil
	}
	clone := *a
	if a.Scopes != nil {
		clone.Scopes = make([]string, len(a.Scopes))
		copy(clone.Scopes, a.Scopes)
	}
	if a.Flows != nil {
		clone.Flows = &types.OAuth2Flows{}
		if a.Flows.Implicit != nil {
			f := *a.Flows.Implicit
			clone.Flows.Implicit = &f
		}
		if a.Flows.Password != nil {
			f := *a.Flows.Password
			clone.Flows.Password = &f
		}
		if a.Flows.ClientCredentials != nil {
			f := *a.Flows.ClientCredentials
			clone.Flows.ClientCredentials = &f
		}
		if a.Flows.AuthorizationCode != nil {
			f := *a.Flows.AuthorizationCode
			clone.Flows.AuthorizationCode = &f
		}
	}
	return &clone
}

func authConfigKey(a *types.AuthConfig) string {
	return fmt.Sprintf("%s|%s|%s|%s", a.Type, a.Name, a.Scheme, strings.Join(a.Scopes, ","))
}
