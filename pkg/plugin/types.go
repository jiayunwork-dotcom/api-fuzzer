package plugin

import "time"

type MutationSeverity string

const (
	SeverityInfo     MutationSeverity = "info"
	SeverityLow      MutationSeverity = "low"
	SeverityMedium   MutationSeverity = "medium"
	SeverityHigh     MutationSeverity = "high"
	SeverityCritical MutationSeverity = "critical"
)

type Schema struct {
	Type                 string              `json:"type,omitempty"`
	Format               string              `json:"format,omitempty"`
	Title                string              `json:"title,omitempty"`
	Description          string              `json:"description,omitempty"`
	Default              interface{}         `json:"default,omitempty"`
	Example              interface{}         `json:"example,omitempty"`
	Enum                 []interface{}       `json:"enum,omitempty"`
	Const                interface{}         `json:"const,omitempty"`
	MultipleOf           *float64            `json:"multipleOf,omitempty"`
	Maximum              *float64            `json:"maximum,omitempty"`
	ExclusiveMaximum     *float64            `json:"exclusiveMaximum,omitempty"`
	Minimum              *float64            `json:"minimum,omitempty"`
	ExclusiveMinimum     *float64            `json:"exclusiveMinimum,omitempty"`
	MaxLength            *int64              `json:"maxLength,omitempty"`
	MinLength            *int64              `json:"minLength,omitempty"`
	Pattern              string              `json:"pattern,omitempty"`
	MaxItems             *int64              `json:"maxItems,omitempty"`
	MinItems             *int64              `json:"minItems,omitempty"`
	UniqueItems          *bool               `json:"uniqueItems,omitempty"`
	MaxProperties        *int64              `json:"maxProperties,omitempty"`
	MinProperties        *int64              `json:"minProperties,omitempty"`
	Required             []string            `json:"required,omitempty"`
	Items                *Schema             `json:"items,omitempty"`
	Properties           map[string]*Schema  `json:"properties,omitempty"`
	AdditionalProperties *Schema             `json:"additionalProperties,omitempty"`
	AllOf                []*Schema           `json:"allOf,omitempty"`
	AnyOf                []*Schema           `json:"anyOf,omitempty"`
	OneOf                []*Schema           `json:"oneOf,omitempty"`
	Not                  *Schema             `json:"not,omitempty"`
	Ref                  string              `json:"$ref,omitempty"`
	Nullable             bool                `json:"nullable,omitempty"`
	ReadOnly             bool                `json:"readOnly,omitempty"`
	WriteOnly            bool                `json:"writeOnly,omitempty"`
	Discriminator        *Discriminator      `json:"discriminator,omitempty"`
}

type Discriminator struct {
	PropertyName string            `json:"propertyName"`
	Mapping      map[string]string `json:"mapping,omitempty"`
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
	SourceFile     string
	ModTime        time.Time
	Instance       MutationPlugin
	Valid          bool
	ValidateError  string
}

type PluginStats struct {
	CallCount     int64
	SuccessCount  int64
	FailureCount  int64
	TotalTimeMs   int64
	OutputCount   int64
	HitCount      int64
	CategoryHits  map[string]int64
	CategoryOutputs map[string]int64
	SeverityHits  map[MutationSeverity]int64
	SeverityOutputs map[MutationSeverity]int64
}

func NewPluginStats() *PluginStats {
	return &PluginStats{
		CategoryHits:    make(map[string]int64),
		CategoryOutputs: make(map[string]int64),
		SeverityHits:    make(map[MutationSeverity]int64),
		SeverityOutputs: make(map[MutationSeverity]int64),
	}
}

func (s *PluginStats) HitRate() float64 {
	if s.OutputCount == 0 {
		return 0
	}
	return float64(s.HitCount) / float64(s.OutputCount)
}

func (s *PluginStats) HitRatePercent() float64 {
	return s.HitRate() * 100
}

func (s *PluginStats) SuccessRate() float64 {
	if s.CallCount == 0 {
		return 0
	}
	return float64(s.SuccessCount) / float64(s.CallCount)
}

func (s *PluginStats) SuccessRatePercent() float64 {
	return s.SuccessRate() * 100
}

func (s *PluginStats) AvgTimeMs() float64 {
	if s.CallCount == 0 {
		return 0
	}
	return float64(s.TotalTimeMs) / float64(s.CallCount)
}

func (s *PluginStats) AvgTimeMsInt() int64 {
	if s.CallCount == 0 {
		return 0
	}
	return s.TotalTimeMs / s.CallCount
}

func (s *PluginStats) SuggestDisable() bool {
	return s.HitCount == 0 && s.CallCount > 10
}

func (s *PluginStats) Merge(other *PluginStats) {
	if other == nil {
		return
	}
	s.CallCount += other.CallCount
	s.SuccessCount += other.SuccessCount
	s.FailureCount += other.FailureCount
	s.TotalTimeMs += other.TotalTimeMs
	s.OutputCount += other.OutputCount
	s.HitCount += other.HitCount
	for k, v := range other.CategoryHits {
		s.CategoryHits[k] += v
	}
	for k, v := range other.CategoryOutputs {
		s.CategoryOutputs[k] += v
	}
	for k, v := range other.SeverityHits {
		s.SeverityHits[k] += v
	}
	for k, v := range other.SeverityOutputs {
		s.SeverityOutputs[k] += v
	}
}

const (
	BuiltinPriority   = 100
	BuiltinPluginName = "builtin"
	DefaultPluginDir  = ".api-fuzzer-plugins"
)
