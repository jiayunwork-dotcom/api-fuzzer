package plugin

import (
	public "api-fuzzer/pkg/plugin"
)

type MutationSeverity = public.MutationSeverity

const (
	SeverityInfo     = public.SeverityInfo
	SeverityLow      = public.SeverityLow
	SeverityMedium   = public.SeverityMedium
	SeverityHigh     = public.SeverityHigh
	SeverityCritical = public.SeverityCritical
)

type Schema = public.Schema
type Discriminator = public.Discriminator
type MutationContext = public.MutationContext
type MutatedValue = public.MutatedValue
type MutationPlugin = public.MutationPlugin
type PluginInfo = public.PluginInfo

const (
	BuiltinPriority   = public.BuiltinPriority
	BuiltinPluginName = public.BuiltinPluginName
	DefaultPluginDir  = public.DefaultPluginDir
)
