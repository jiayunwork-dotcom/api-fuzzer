package plugin

type MutationSeverity string

const (
	SeverityInfo     MutationSeverity = "info"
	SeverityLow      MutationSeverity = "low"
	SeverityMedium   MutationSeverity = "medium"
	SeverityHigh     MutationSeverity = "high"
	SeverityCritical MutationSeverity = "critical"
)

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
}

type Discriminator struct {
	PropertyName string            `json:"propertyName" yaml:"propertyName"`
	Mapping      map[string]string `json:"mapping,omitempty" yaml:"mapping,omitempty"`
}

type MutationContext struct {
	ParamName    string
	ParamType    string
	Schema       *Schema
	CurrentValue interface{}
	Endpoint     string
	Method       string
}

type MutatedValue struct {
	Value      interface{}
	Label      string
	Severity   MutationSeverity
	Category   string
	PluginName string
}

type MutationPlugin interface {
	Name() string
	Priority() int
	SupportedTypes() []string
	Mutate(ctx MutationContext) []MutatedValue
	Validate() error
}

type PluginInfo struct {
	Name           string
	Priority       int
	SupportedTypes []string
	Valid          bool
	ValidateError  string
	SourceFile     string
	Instance       MutationPlugin
}

const (
	BuiltinPriority   = 50
	BuiltinPluginName = "builtin"
	DefaultPluginDir  = ".api-fuzzer-plugins"
)
