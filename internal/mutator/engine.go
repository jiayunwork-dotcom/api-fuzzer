package mutator

import (
	"os"
	"sort"
	"time"

	"api-fuzzer/internal/plugin"
	"api-fuzzer/internal/types"
)

type builtinMutatorPlugin struct {
	name        string
	priority    int
	types       []string
	mutateFn    func(schema *types.Schema, value interface{}) ([]MutationResult, error)
}

func (b *builtinMutatorPlugin) Name() string {
	return b.name
}

func (b *builtinMutatorPlugin) Priority() int {
	return b.priority
}

func (b *builtinMutatorPlugin) SupportedTypes() []string {
	return b.types
}

func (b *builtinMutatorPlugin) Mutate(ctx plugin.MutationContext) []plugin.MutatedValue {
	results, err := b.mutateFn(ctx.Schema, ctx.CurrentValue)
	if err != nil {
		return nil
	}

	mutated := make([]plugin.MutatedValue, 0, len(results))
	for _, r := range results {
		severity := plugin.SeverityMedium
		category := "boundary"

		targetLower := r.Target
		if len(targetLower) >= 7 {
			switch targetLower[7:] {
			case "SQLInjection", "XSS", "PathTraversal", "FormatString", "JSONInjection":
				severity = plugin.SeverityHigh
				category = "injection"
			case "Overlong1MB", "Repeat100K", "Huge10K", "Nested10Levels", "Extra100Fields", "LongKey1000Chars":
				severity = plugin.SeverityHigh
				category = "overflow"
			case "WrongElementType", "AllWrongTypes", "FloatZero", "NegativeZeroFloat", "NaN", "Infinity", "NegativeInfinity":
				severity = plugin.SeverityMedium
				category = "type-confusion"
			}
		}

		mutated = append(mutated, plugin.MutatedValue{
			Value:      r.Value,
			Label:      r.Target,
			Severity:   severity,
			Category:   category,
			PluginName: plugin.BuiltinPluginName,
		})
	}
	return mutated
}

func (b *builtinMutatorPlugin) Validate() error {
	return nil
}

func getBuiltinPlugins() []*plugin.PluginInfo {
	builtins := []struct {
		name        string
		types       []string
		mutator     Mutator
	}{
		{"builtin-string", []string{types.TypeString}, NewStringMutator()},
		{"builtin-number", []string{types.TypeInteger, types.TypeNumber}, NewNumberMutator()},
		{"builtin-bool", []string{types.TypeBoolean}, NewBoolMutator()},
		{"builtin-array", []string{types.TypeArray}, NewArrayMutator()},
		{"builtin-object", []string{types.TypeObject}, NewObjectMutator()},
		{"builtin-null", []string{types.TypeString, types.TypeInteger, types.TypeNumber, types.TypeBoolean, types.TypeArray, types.TypeObject, types.TypeNull}, NewNullInjector()},
	}

	result := make([]*plugin.PluginInfo, 0, len(builtins))
	for _, b := range builtins {
		m := b.mutator
		bp := &builtinMutatorPlugin{
			name:     b.name,
			priority: plugin.BuiltinPriority,
			types:    b.types,
			mutateFn: m.Mutate,
		}
		result = append(result, &plugin.PluginInfo{
			Name:           bp.Name(),
			Priority:       bp.Priority(),
			SupportedTypes: bp.SupportedTypes(),
			Valid:          true,
			SourceFile:     "builtin",
			Instance:       bp,
		})
	}
	return result
}

type MutationEngine struct {
	loader          *plugin.Loader
	allPlugins      []*plugin.PluginInfo
	timeoutPerCall  time.Duration
}

func NewMutationEngine(loader *plugin.Loader) *MutationEngine {
	me := &MutationEngine{
		loader:         loader,
		timeoutPerCall: 5 * time.Second,
	}
	me.rebuildPluginList()
	return me
}

func (me *MutationEngine) rebuildPluginList() {
	me.allPlugins = make([]*plugin.PluginInfo, 0)

	me.allPlugins = append(me.allPlugins, getBuiltinPlugins()...)

	if me.loader != nil {
		external := me.loader.GetValidPlugins()
		me.allPlugins = append(me.allPlugins, external...)
	}

	sort.Slice(me.allPlugins, func(i, j int) bool {
		if me.allPlugins[i].Priority != me.allPlugins[j].Priority {
			return me.allPlugins[i].Priority > me.allPlugins[j].Priority
		}
		return me.allPlugins[i].Name < me.allPlugins[j].Name
	})
}

func (me *MutationEngine) ReloadExternalPlugins() error {
	if me.loader == nil {
		return nil
	}
	_, err := me.loader.Load()
	if err != nil {
		return err
	}
	me.rebuildPluginList()
	return nil
}

func (me *MutationEngine) findMatchingPlugins(paramType string) []*plugin.PluginInfo {
	matched := make([]*plugin.PluginInfo, 0)
	for _, p := range me.allPlugins {
		if !p.Valid {
			continue
		}
		if len(p.SupportedTypes) == 0 {
			matched = append(matched, p)
			continue
		}
		for _, t := range p.SupportedTypes {
			if t == paramType {
				matched = append(matched, p)
				break
			}
		}
	}
	return matched
}

type ExtendedMutationResult struct {
	MutationResult
	PluginName string
	Severity   plugin.MutationSeverity
	Category   string
}

func (me *MutationEngine) GetMutationsExtended(schema *types.Schema, originalValue interface{}, paramName, endpoint, method string) ([]ExtendedMutationResult, error) {
	var allResults []ExtendedMutationResult

	paramType := ""
	if schema != nil {
		paramType = schema.Type
	}
	if paramType == "" {
		paramType = types.TypeString
	}

	ctx := plugin.MutationContext{
		ParamName:    paramName,
		ParamType:    paramType,
		Schema:       schema,
		CurrentValue: originalValue,
		Endpoint:     endpoint,
		Method:       method,
	}

	plugins := me.findMatchingPlugins(paramType)

	for _, p := range plugins {
		var values []plugin.MutatedValue
		var err error
		var timedOut bool

		if p.SourceFile == "builtin" {
			func() {
				defer func() {
					if r := recover(); r != nil {
						err = r.(error)
					}
				}()
				values = p.Instance.Mutate(ctx)
			}()
		} else {
			if me.loader != nil {
				values, timedOut, err = me.loader.RunMutateWithTimeout(p, ctx, me.timeoutPerCall)
			} else {
				func() {
					defer func() {
						if r := recover(); r != nil {
							err = r.(error)
						}
					}()
					values = p.Instance.Mutate(ctx)
				}()
			}
		}

		if err != nil {
			if timedOut {
				os.Stderr.WriteString([]byte("警告: 插件 " + p.Name + " 执行超时，已跳过\n"))
			} else {
				os.Stderr.WriteString([]byte("警告: 插件 " + p.Name + " 执行失败: " + err.Error() + "\n"))
			}
			continue
		}

		for _, v := range values {
			allResults = append(allResults, ExtendedMutationResult{
				MutationResult: MutationResult{
					Value:       v.Value,
					Target:      v.Label,
					Description: "[" + v.PluginName + "] " + v.Label + " (" + v.Category + ")",
				},
				PluginName: v.PluginName,
				Severity:   v.Severity,
				Category:   v.Category,
			})
		}
	}

	return allResults, nil
}

func (me *MutationEngine) GetMutations(schema *types.Schema, originalValue interface{}) ([]MutationResult, error) {
	ext, err := me.GetMutationsExtended(schema, originalValue, "", "", "")
	if err != nil {
		return nil, err
	}
	results := make([]MutationResult, 0, len(ext))
	for _, e := range ext {
		results = append(results, e.MutationResult)
	}
	return results, nil
}

func GetMutationsWithEngine(engine *MutationEngine, schema *types.Schema, originalValue interface{}) ([]MutationResult, error) {
	if engine != nil {
		return engine.GetMutations(schema, originalValue)
	}
	return GetMutations(schema, originalValue)
}
