package plugin

import "api-fuzzer/internal/types"

type MutationSeverity string

const (
	SeverityInfo     MutationSeverity = "info"
	SeverityLow      MutationSeverity = "low"
	SeverityMedium   MutationSeverity = "medium"
	SeverityHigh     MutationSeverity = "high"
	SeverityCritical MutationSeverity = "critical"
)

type MutationContext struct {
	ParamName    string
	ParamType    string
	Schema       *types.Schema
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
