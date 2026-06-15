package generator

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"time"

	"api-fuzzer/internal/mutator"
	"api-fuzzer/internal/types"
	"api-fuzzer/pkg/utils"
)

const (
	defaultMaxCombinationPairs = 50
	defaultMaxMutationPerPath  = 5
	priorityRequiredPath       = 10
	priorityBodyTopLevel       = 8
	priorityOptional           = 5
	priorityMin                = 1
)

type GeneratorOptions struct {
	IncludePaths []string
	ExcludePaths []string
}

type paramContext struct {
	Name     string
	Location types.ParameterLocation
	Schema   *types.Schema
	Required bool
	Value    interface{}
	Path     string
	Priority int
	Depth    int
}

type bodyFieldContext struct {
	Path     string
	Schema   *types.Schema
	Value    interface{}
	Priority int
	Depth    int
	Required bool
}

func GenerateValidValue(schema *types.Schema) interface{} {
	if schema == nil {
		return "valid_value"
	}

	if schema.Example != nil {
		return schema.Example
	}
	if schema.Default != nil {
		return schema.Default
	}
	if schema.Const != nil {
		return schema.Const
	}
	if len(schema.Enum) > 0 {
		return schema.Enum[0]
	}

	if len(schema.AllOf) > 0 {
		merged := mergeAllOfSchemas(schema.AllOf)
		return GenerateValidValue(merged)
	}
	if len(schema.OneOf) > 0 {
		return GenerateValidValue(schema.OneOf[0])
	}
	if len(schema.AnyOf) > 0 {
		return GenerateValidValue(schema.AnyOf[0])
	}

	switch schema.Type {
	case types.TypeString:
		return generateValidString(schema)
	case types.TypeInteger:
		return generateValidInteger(schema)
	case types.TypeNumber:
		return generateValidNumber(schema)
	case types.TypeBoolean:
		return true
	case types.TypeArray:
		return generateValidArray(schema)
	case types.TypeObject:
		return generateValidObject(schema)
	case types.TypeNull:
		return nil
	default:
		return "valid_value"
	}
}

func mergeAllOfSchemas(schemas []*types.Schema) *types.Schema {
	result := &types.Schema{}
	for _, s := range schemas {
		if s.Type != "" {
			result.Type = s.Type
		}
		if s.Properties != nil {
			if result.Properties == nil {
				result.Properties = make(map[string]*types.Schema)
			}
			for k, v := range s.Properties {
				result.Properties[k] = v
			}
		}
		if len(s.Required) > 0 {
			result.Required = append(result.Required, s.Required...)
		}
		if s.Items != nil {
			result.Items = s.Items
		}
		if s.Format != "" {
			result.Format = s.Format
		}
		if s.Minimum != nil {
			result.Minimum = s.Minimum
		}
		if s.Maximum != nil {
			result.Maximum = s.Maximum
		}
		if s.MinLength != nil {
			result.MinLength = s.MinLength
		}
		if s.MaxLength != nil {
			result.MaxLength = s.MaxLength
		}
		if s.MinItems != nil {
			result.MinItems = s.MinItems
		}
		if s.MaxItems != nil {
			result.MaxItems = s.MaxItems
		}
	}
	return result
}

func generateValidString(schema *types.Schema) string {
	minLen := int64(1)
	if schema.MinLength != nil {
		minLen = *schema.MinLength
	}
	maxLen := int64(10)
	if schema.MaxLength != nil && *schema.MaxLength > 0 {
		maxLen = *schema.MaxLength
		if maxLen < minLen {
			maxLen = minLen
		}
	}
	if minLen > maxLen {
		minLen = maxLen
	}
	targetLen := minLen
	if targetLen < 1 {
		targetLen = 1
	}

	switch schema.Format {
	case "email":
		return "user@example.com"
	case "uuid":
		return "550e8400-e29b-41d4-a716-446655440000"
	case "date":
		return "2024-01-15"
	case "date-time":
		return "2024-01-15T10:30:00Z"
	case "time":
		return "10:30:00"
	case "uri", "url":
		return "https://example.com/path"
	case "hostname":
		return "example.com"
	case "ipv4":
		return "192.168.1.1"
	case "ipv6":
		return "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	case "byte", "base64":
		return "SGVsbG8gV29ybGQ="
	case "password":
		return utils.BuildString(int(targetLen), 'p')
	default:
		return utils.BuildString(int(targetLen), 'a')
	}
}

func generateValidInteger(schema *types.Schema) int64 {
	var min int64 = 1
	var max int64 = 100

	if schema.Minimum != nil {
		min = int64(*schema.Minimum)
		if schema.ExclusiveMinimum != nil {
			min = int64(*schema.ExclusiveMinimum) + 1
		}
	}
	if schema.Maximum != nil {
		max = int64(*schema.Maximum)
		if schema.ExclusiveMaximum != nil {
			max = int64(*schema.ExclusiveMaximum) - 1
		}
	}
	if schema.MultipleOf != nil {
		m := int64(*schema.MultipleOf)
		if m > 0 {
			quotient := min / m
			if min%m != 0 {
				quotient++
			}
			return quotient * m
		}
	}
	if min > max {
		return min
	}
	return (min + max) / 2
}

func generateValidNumber(schema *types.Schema) float64 {
	var min float64 = 1.0
	var max float64 = 100.0

	if schema.Minimum != nil {
		min = *schema.Minimum
		if schema.ExclusiveMinimum != nil {
			min = *schema.ExclusiveMinimum + 0.0001
		}
	}
	if schema.Maximum != nil {
		max = *schema.Maximum
		if schema.ExclusiveMaximum != nil {
			max = *schema.ExclusiveMaximum - 0.0001
		}
	}
	if schema.MultipleOf != nil && *schema.MultipleOf > 0 {
		m := *schema.MultipleOf
		quotient := min / m
		return quotient * m
	}
	return (min + max) / 2
}

func generateValidArray(schema *types.Schema) []interface{} {
	minItems := int64(1)
	if schema.MinItems != nil {
		minItems = *schema.MinItems
	}
	maxItems := int64(3)
	if schema.MaxItems != nil && *schema.MaxItems > 0 {
		maxItems = *schema.MaxItems
		if maxItems < minItems {
			maxItems = minItems
		}
	}
	targetLen := int(minItems)
	if targetLen < 1 {
		targetLen = 1
	}

	arr := make([]interface{}, targetLen)
	for i := 0; i < targetLen; i++ {
		arr[i] = GenerateValidValue(schema.Items)
	}
	return arr
}

func generateValidObject(schema *types.Schema) map[string]interface{} {
	obj := make(map[string]interface{})
	if schema.Properties == nil {
		return obj
	}

	requiredFields := make(map[string]bool)
	for _, f := range schema.Required {
		requiredFields[f] = true
	}

	for name, fieldSchema := range schema.Properties {
		if requiredFields[name] || rand.Intn(2) == 0 {
			obj[name] = GenerateValidValue(fieldSchema)
		}
	}

	if schema.AdditionalProperties != nil {
		obj["ext_field_1"] = GenerateValidValue(schema.AdditionalProperties)
	}

	return obj
}

func toStringMap(m map[string]interface{}) map[string]string {
	if m == nil {
		return make(map[string]string)
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = fmt.Sprintf("%v", v)
	}
	return result
}

func toJSONBody(v interface{}) (string, interface{}) {
	if v == nil {
		return "", nil
	}
	switch val := v.(type) {
	case string:
		return val, val
	case []byte:
		return string(val), val
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "", v
		}
		return string(b), v
	}
}

func GenerateTestCases(api *types.APISpec, maxCasesPerEndpoint int, baseURL string) ([]*types.TestCase, error) {
	return GenerateTestCasesWithOptions(api, maxCasesPerEndpoint, baseURL, GeneratorOptions{})
}

func GenerateTestCasesWithOptions(api *types.APISpec, maxCasesPerEndpoint int, baseURL string, opts GeneratorOptions) ([]*types.TestCase, error) {
	if api == nil {
		return nil, fmt.Errorf("api spec is nil")
	}

	if !matchesPathFilters(api.Path, opts.IncludePaths, opts.ExcludePaths) {
		return []*types.TestCase{}, nil
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	_ = r

	pathParams, queryParams, headerParams, cookieParams := categorizeParameters(api.Parameters)

	pathParamValues := make(map[string]interface{})
	pathParamContexts := make([]*paramContext, 0, len(pathParams))
	for _, p := range pathParams {
		val := GenerateValidValue(p.Schema)
		pathParamValues[p.Name] = val
		pathParamContexts = append(pathParamContexts, &paramContext{
			Name:     p.Name,
			Location: types.ParamInPath,
			Schema:   p.Schema,
			Required: true,
			Value:    val,
			Path:     fmt.Sprintf(".path.%s", p.Name),
			Priority: priorityRequiredPath,
			Depth:    0,
		})
	}

	queryParamValues := make(map[string]interface{})
	queryParamContexts := make([]*paramContext, 0, len(queryParams))
	for _, p := range queryParams {
		val := GenerateValidValue(p.Schema)
		queryParamValues[p.Name] = val
		priority := priorityOptional
		if p.Required {
			priority = priorityRequiredPath
		}
		queryParamContexts = append(queryParamContexts, &paramContext{
			Name:     p.Name,
			Location: types.ParamInQuery,
			Schema:   p.Schema,
			Required: p.Required,
			Value:    val,
			Path:     fmt.Sprintf(".query.%s", p.Name),
			Priority: priority,
			Depth:    0,
		})
	}

	headerParamValues := make(map[string]interface{})
	headerParamContexts := make([]*paramContext, 0, len(headerParams))
	for _, p := range headerParams {
		val := GenerateValidValue(p.Schema)
		headerParamValues[p.Name] = val
		priority := priorityOptional
		if p.Required {
			priority = priorityRequiredPath
		}
		headerParamContexts = append(headerParamContexts, &paramContext{
			Name:     p.Name,
			Location: types.ParamInHeader,
			Schema:   p.Schema,
			Required: p.Required,
			Value:    val,
			Path:     fmt.Sprintf(".header.%s", p.Name),
			Priority: priority,
			Depth:    0,
		})
	}

	_ = cookieParams

	var bodySchema *types.Schema
	var bodyValue interface{}
	var bodyContentType string
	var bodyFieldContexts []*bodyFieldContext

	if api.RequestBody != nil && api.RequestBody.Content != nil {
		for ct, mt := range api.RequestBody.Content {
			if mt.Schema != nil {
				bodySchema = mt.Schema
				bodyContentType = ct
				bodyValue = GenerateValidValue(mt.Schema)
				bodyFieldContexts = collectBodyFieldContexts(mt.Schema, bodyValue, ".body", 0)
				break
			}
		}
	}

	happyPathID := fmt.Sprintf("%s_%s_happy", api.Method, sanitizePath(api.Path))
	happyURL := buildFullURL(baseURL, api.Path, pathParamValues)
	happyBodyStr, happyBodyObj := toJSONBody(bodyValue)
	happyCase := &types.TestCase{
		ID:        happyPathID,
		APISpec:   api,
		APIPath:   api.Path,
		APIMethod: api.Method,
		Name:      fmt.Sprintf("Happy Path: %s %s", api.Method, api.Path),
		Auth:      api.Auth,
		Request: &types.HTTPRequest{
			URL:     happyURL,
			Method:  api.Method,
			Headers: buildHeaders(headerParamValues, bodyContentType),
			Query:   toStringMap(queryParamValues),
			Body:    happyBodyStr,
			BodyObj: happyBodyObj,
		},
		Priority: priorityRequiredPath + 1,
		Tags:     api.Tags,
	}

	testCases := []*types.TestCase{happyCase}

	allParamContexts := make([]*paramContext, 0)
	allParamContexts = append(allParamContexts, pathParamContexts...)
	allParamContexts = append(allParamContexts, queryParamContexts...)
	allParamContexts = append(allParamContexts, headerParamContexts...)

	for _, pc := range allParamContexts {
		mutations, err := mutator.GetMutations(pc.Schema, pc.Value)
		if err != nil {
			continue
		}
		mutations = limitMutations(mutations, defaultMaxMutationPerPath)
		for mi, mr := range mutations {
			newPathVals := copyMapInterface(pathParamValues)
			newQueryVals := copyMapInterface(queryParamValues)
			newHeaderVals := copyMapInterface(headerParamValues)

			switch pc.Location {
			case types.ParamInPath:
				newPathVals[pc.Name] = mr.Value
			case types.ParamInQuery:
				newQueryVals[pc.Name] = mr.Value
			case types.ParamInHeader:
				newHeaderVals[pc.Name] = mr.Value
			}

			tcID := fmt.Sprintf("%s_%s_mut_s_%s_%d", api.Method, sanitizePath(api.Path), sanitizeName(pc.Path), mi)
			paramBodyStr, paramBodyObj := toJSONBody(bodyValue)
			tc := &types.TestCase{
				ID:        tcID,
				APISpec:   api,
				APIPath:   api.Path,
				APIMethod: api.Method,
				Name:      fmt.Sprintf("Single Mut: %s [%s]", pc.Path, mr.Target),
				Description: mr.Description,
				Auth:      api.Auth,
				Request: &types.HTTPRequest{
					URL:     buildFullURL(baseURL, api.Path, newPathVals),
					Method:  api.Method,
					Headers: buildHeaders(newHeaderVals, bodyContentType),
					Query:   toStringMap(newQueryVals),
					Body:    paramBodyStr,
					BodyObj: paramBodyObj,
				},
				Priority:    pc.Priority,
				MutatedPath: []string{pc.Path},
				MutatedDesc: []string{fmt.Sprintf("%s: %s", mr.Target, mr.Description)},
				Tags:        api.Tags,
			}
			testCases = append(testCases, tc)
		}
	}

	for _, bc := range bodyFieldContexts {
		mutations, err := mutator.GetMutations(bc.Schema, bc.Value)
		if err != nil {
			continue
		}
		mutations = limitMutations(mutations, defaultMaxMutationPerPath)
		for mi, mr := range mutations {
			newBody, applyErr := applyValueAtPath(bodyValue, bc.Path, mr.Value)
			if applyErr != nil {
				continue
			}
			tcID := fmt.Sprintf("%s_%s_mut_b_%s_%d", api.Method, sanitizePath(api.Path), sanitizeName(bc.Path), mi)
			bodyStr, bodyObj := toJSONBody(newBody)
			tc := &types.TestCase{
				ID:        tcID,
				APISpec:   api,
				APIPath:   api.Path,
				APIMethod: api.Method,
				Name:      fmt.Sprintf("Single Mut: %s [%s]", bc.Path, mr.Target),
				Description: mr.Description,
				Auth:      api.Auth,
				Request: &types.HTTPRequest{
					URL:     buildFullURL(baseURL, api.Path, pathParamValues),
					Method:  api.Method,
					Headers: buildHeaders(headerParamValues, bodyContentType),
					Query:   toStringMap(queryParamValues),
					Body:    bodyStr,
					BodyObj: bodyObj,
				},
				Priority:    bc.Priority,
				MutatedPath: []string{bc.Path},
				MutatedDesc: []string{fmt.Sprintf("%s: %s", mr.Target, mr.Description)},
				Tags:        api.Tags,
			}
			testCases = append(testCases, tc)
		}
	}

	type mutTarget struct {
		IsBody  bool
		PCtx    *paramContext
		BCtx    *bodyFieldContext
		MutIdx  int
		MutRes  mutator.MutationResult
		Priority int
	}

	var allMutTargets []mutTarget

	for _, pc := range allParamContexts {
		mutations, err := mutator.GetMutations(pc.Schema, pc.Value)
		if err != nil {
			continue
		}
		mutations = limitMutations(mutations, defaultMaxMutationPerPath)
		for mi, mr := range mutations {
			allMutTargets = append(allMutTargets, mutTarget{
				IsBody:   false,
				PCtx:     pc,
				MutIdx:   mi,
				MutRes:   mr,
				Priority: pc.Priority,
			})
		}
	}

	for _, bc := range bodyFieldContexts {
		mutations, err := mutator.GetMutations(bc.Schema, bc.Value)
		if err != nil {
			continue
		}
		mutations = limitMutations(mutations, defaultMaxMutationPerPath)
		for mi, mr := range mutations {
			allMutTargets = append(allMutTargets, mutTarget{
				IsBody:   true,
				BCtx:     bc,
				MutIdx:   mi,
				MutRes:   mr,
				Priority: bc.Priority,
			})
		}
	}

	sort.Slice(allMutTargets, func(i, j int) bool {
		return allMutTargets[i].Priority > allMutTargets[j].Priority
	})

	pairCombinations := generatePairCombinations(allMutTargets, defaultMaxCombinationPairs)

	for _, pair := range pairCombinations {
		t1 := pair[0]
		t2 := pair[1]

		newPathVals := copyMapInterface(pathParamValues)
		newQueryVals := copyMapInterface(queryParamValues)
		newHeaderVals := copyMapInterface(headerParamValues)
		newBody := deepCopy(bodyValue)

		mutatedPaths := make([]string, 0, 2)
		mutatedDescs := make([]string, 0, 2)
		minPriority := priorityRequiredPath

		for _, t := range []mutTarget{t1, t2} {
			if t.Priority < minPriority {
				minPriority = t.Priority
			}
			if t.IsBody {
				mutatedPaths = append(mutatedPaths, t.BCtx.Path)
				mutatedDescs = append(mutatedDescs, fmt.Sprintf("%s: %s", t.MutRes.Target, t.MutRes.Description))
				newBody, _ = applyValueAtPath(newBody, t.BCtx.Path, t.MutRes.Value)
			} else {
				mutatedPaths = append(mutatedPaths, t.PCtx.Path)
				mutatedDescs = append(mutatedDescs, fmt.Sprintf("%s: %s", t.MutRes.Target, t.MutRes.Description))
				switch t.PCtx.Location {
				case types.ParamInPath:
					newPathVals[t.PCtx.Name] = t.MutRes.Value
				case types.ParamInQuery:
					newQueryVals[t.PCtx.Name] = t.MutRes.Value
				case types.ParamInHeader:
					newHeaderVals[t.PCtx.Name] = t.MutRes.Value
				}
			}
		}

		combinedPriority := minPriority - 1
		if combinedPriority < priorityMin {
			combinedPriority = priorityMin
		}

		tcID := fmt.Sprintf("%s_%s_mut_p_%s_%s", api.Method, sanitizePath(api.Path),
			sanitizeName(mutatedPaths[0]), sanitizeName(mutatedPaths[1]))
		pairBodyStr, pairBodyObj := toJSONBody(newBody)
		tc := &types.TestCase{
			ID:        tcID,
			APISpec:   api,
			APIPath:   api.Path,
			APIMethod: api.Method,
			Name:      fmt.Sprintf("Pair Mut: %s + %s", mutatedPaths[0], mutatedPaths[1]),
			Auth:      api.Auth,
			Request: &types.HTTPRequest{
				URL:     buildFullURL(baseURL, api.Path, newPathVals),
				Method:  api.Method,
				Headers: buildHeaders(newHeaderVals, bodyContentType),
				Query:   toStringMap(newQueryVals),
				Body:    pairBodyStr,
				BodyObj: pairBodyObj,
			},
			Priority:    combinedPriority,
			MutatedPath: mutatedPaths,
			MutatedDesc: mutatedDescs,
			Tags:        api.Tags,
		}
		testCases = append(testCases, tc)
	}

	sort.Slice(testCases, func(i, j int) bool {
		if testCases[i].Priority != testCases[j].Priority {
			return testCases[i].Priority > testCases[j].Priority
		}
		return testCases[i].ID < testCases[j].ID
	})

	if maxCasesPerEndpoint > 0 && len(testCases) > maxCasesPerEndpoint {
		testCases = sampleTestCases(testCases, maxCasesPerEndpoint)
	}

	return testCases, nil
}

func categorizeParameters(params []*types.ParameterSpec) (path, query, header, cookie []*types.ParameterSpec) {
	for _, p := range params {
		if p == nil {
			continue
		}
		switch p.In {
		case types.ParamInPath:
			path = append(path, p)
		case types.ParamInQuery:
			query = append(query, p)
		case types.ParamInHeader:
			header = append(header, p)
		case types.ParamInCookie:
			cookie = append(cookie, p)
		}
	}
	return
}

func collectBodyFieldContexts(schema *types.Schema, value interface{}, basePath string, depth int) []*bodyFieldContext {
	var contexts []*bodyFieldContext

	if schema == nil {
		return contexts
	}

	priority := priorityBodyTopLevel - depth
	if priority < priorityMin {
		priority = priorityMin
	}
	if depth > 0 {
		priority = priorityOptional - (depth - 1)
		if priority < priorityMin {
			priority = priorityMin
		}
	}

	switch schema.Type {
	case types.TypeObject:
		if schema.Properties != nil {
			requiredMap := make(map[string]bool)
			for _, r := range schema.Required {
				requiredMap[r] = true
			}
			objVal, _ := value.(map[string]interface{})
			for name, propSchema := range schema.Properties {
				fieldPath := fmt.Sprintf("%s.%s", basePath, name)
				var fieldValue interface{}
				if objVal != nil {
					fieldValue = objVal[name]
				}
				if fieldValue == nil {
					fieldValue = GenerateValidValue(propSchema)
				}

				isRequired := requiredMap[name]
				fieldPriority := priorityBodyTopLevel - depth
				if !isRequired && depth == 0 {
					fieldPriority = priorityOptional
				} else if depth > 0 {
					fieldPriority = priorityOptional - depth
				}
				if fieldPriority < priorityMin {
					fieldPriority = priorityMin
				}

				isScalar := propSchema.Type != types.TypeObject && propSchema.Type != types.TypeArray
				if isScalar || (propSchema.Type == "" && len(propSchema.Properties) == 0) {
					contexts = append(contexts, &bodyFieldContext{
						Path:     fieldPath,
						Schema:   propSchema,
						Value:    fieldValue,
						Priority: fieldPriority,
						Depth:    depth + 1,
						Required: isRequired,
					})
				}

				if propSchema.Type == types.TypeObject || propSchema.Type == types.TypeArray ||
					len(propSchema.Properties) > 0 || propSchema.Items != nil {
					subContexts := collectBodyFieldContexts(propSchema, fieldValue, fieldPath, depth+1)
					contexts = append(contexts, subContexts...)
				}
			}
		}

	case types.TypeArray:
		if schema.Items != nil {
			arrVal, _ := value.([]interface{})
			if len(arrVal) > 0 {
				for idx := 0; idx < len(arrVal) && idx < 2; idx++ {
					itemPath := fmt.Sprintf("%s[%d]", basePath, idx)
					var itemValue interface{}
					if idx < len(arrVal) {
						itemValue = arrVal[idx]
					}
					if itemValue == nil {
						itemValue = GenerateValidValue(schema.Items)
					}

					itemPriority := priorityOptional - depth
					if itemPriority < priorityMin {
						itemPriority = priorityMin
					}

					isScalar := schema.Items.Type != types.TypeObject && schema.Items.Type != types.TypeArray
					if isScalar {
						contexts = append(contexts, &bodyFieldContext{
							Path:     itemPath,
							Schema:   schema.Items,
							Value:    itemValue,
							Priority: itemPriority,
							Depth:    depth + 1,
						})
					}

					if schema.Items.Type == types.TypeObject || schema.Items.Type == types.TypeArray ||
						len(schema.Items.Properties) > 0 || schema.Items.Items != nil {
						subContexts := collectBodyFieldContexts(schema.Items, itemValue, itemPath, depth+1)
						contexts = append(contexts, subContexts...)
					}
				}
			}
		}
	}

	return contexts
}

func applyValueAtPath(root interface{}, path string, newValue interface{}) (interface{}, error) {
	if root == nil {
		return newValue, nil
	}

	rootCopy := deepCopy(root)

	if path == ".body" || path == "" {
		return newValue, nil
	}

	relativePath := path
	if strings.HasPrefix(relativePath, ".body") {
		relativePath = strings.TrimPrefix(relativePath, ".body")
	}

	parts := parsePath(relativePath)
	if len(parts) == 0 {
		return newValue, nil
	}

	err := setValueByPath(rootCopy, parts, newValue)
	if err != nil {
		return rootCopy, err
	}
	return rootCopy, nil
}

type pathPart struct {
	IsIndex bool
	Key     string
	Index   int
}

func parsePath(path string) []pathPart {
	var parts []pathPart
	path = strings.TrimPrefix(path, ".")
	if path == "" {
		return parts
	}

	segments := strings.Split(path, ".")
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		bracketStart := strings.Index(seg, "[")
		if bracketStart >= 0 {
			key := seg[:bracketStart]
			if key != "" {
				parts = append(parts, pathPart{IsIndex: false, Key: key})
			}
			remainder := seg[bracketStart:]
			for len(remainder) > 0 && remainder[0] == '[' {
				end := strings.Index(remainder, "]")
				if end < 0 {
					break
				}
				idxStr := remainder[1:end]
				idx := 0
				fmt.Sscanf(idxStr, "%d", &idx)
				parts = append(parts, pathPart{IsIndex: true, Index: idx})
				if end+1 < len(remainder) {
					remainder = remainder[end+1:]
				} else {
					remainder = ""
				}
			}
		} else {
			parts = append(parts, pathPart{IsIndex: false, Key: seg})
		}
	}
	return parts
}

func setValueByPath(root interface{}, parts []pathPart, newValue interface{}) error {
	if len(parts) == 0 {
		return fmt.Errorf("empty path")
	}

	current := root
	for i, part := range parts {
		isLast := i == len(parts)-1

		if part.IsIndex {
			arr, ok := current.([]interface{})
			if !ok {
				return fmt.Errorf("expected array at index part %d", i)
			}
			if part.Index < 0 || part.Index >= len(arr) {
				part.Index = 0
				if part.Index >= len(arr) {
					return fmt.Errorf("array index out of bounds: %d", part.Index)
				}
			}
			if isLast {
				arr[part.Index] = newValue
				return nil
			}
			current = arr[part.Index]
		} else {
			obj, ok := current.(map[string]interface{})
			if !ok {
				return fmt.Errorf("expected object at key part %d: %s", i, part.Key)
			}
			if isLast {
				obj[part.Key] = newValue
				return nil
			}
			next, exists := obj[part.Key]
			if !exists {
				obj[part.Key] = make(map[string]interface{})
				next = obj[part.Key]
			}
			current = next
		}
	}
	return nil
}

func deepCopy(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case map[string]interface{}:
		cp := make(map[string]interface{}, len(val))
		for k, vv := range val {
			cp[k] = deepCopy(vv)
		}
		return cp
	case []interface{}:
		cp := make([]interface{}, len(val))
		for i, vv := range val {
			cp[i] = deepCopy(vv)
		}
		return cp
	default:
		return v
	}
}

func copyMapInterface(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return make(map[string]interface{})
	}
	cp := make(map[string]interface{}, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func buildFullURL(baseURL, apiPath string, pathParams map[string]interface{}) string {
	fullPath := apiPath
	for name, val := range pathParams {
		placeholder := fmt.Sprintf("{%s}", name)
		strVal := fmt.Sprintf("%v", val)
		fullPath = strings.ReplaceAll(fullPath, placeholder, strVal)
	}

	base := strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(fullPath, "/") {
		fullPath = "/" + fullPath
	}
	return base + fullPath
}

func buildHeaders(headerParams map[string]interface{}, contentType string) map[string]string {
	headers := make(map[string]string)
	for k, v := range headerParams {
		headers[k] = fmt.Sprintf("%v", v)
	}
	if contentType != "" {
		if _, exists := headers["Content-Type"]; !exists {
			headers["Content-Type"] = contentType
		}
	}
	if _, exists := headers["Accept"]; !exists {
		headers["Accept"] = "application/json"
	}
	return headers
}

func sanitizePath(p string) string {
	r := strings.NewReplacer("/", "_", "{", "", "}", "", "-", "_")
	return r.Replace(strings.Trim(p, "/"))
}

func sanitizeName(s string) string {
	r := strings.NewReplacer(".", "_", "[", "_", "]", "_", "{", "", "}", "", "-", "_", " ", "")
	result := r.Replace(s)
	result = strings.Trim(result, "_")
	if len(result) > 60 {
		result = result[:60]
	}
	return result
}

func limitMutations(mutations []mutator.MutationResult, max int) []mutator.MutationResult {
	if len(mutations) <= max {
		return mutations
	}
	return mutations[:max]
}

func generatePairCombinations(targets []mutTarget, maxPairs int) [][2]mutTarget {
	var pairs [][2]mutTarget
	n := len(targets)
	if n < 2 {
		return pairs
	}

	totalPossible := n * (n - 1) / 2
	if totalPossible <= maxPairs {
		for i := 0; i < n; i++ {
			for j := i + 1; j < n; j++ {
				pairs = append(pairs, [2]mutTarget{targets[i], targets[j]})
			}
		}
		return pairs
	}

	used := make(map[[2]int]bool)
	attempts := 0
	maxAttempts := maxPairs * 10

	for len(pairs) < maxPairs && attempts < maxAttempts {
		attempts++
		i := rand.Intn(n)
		j := rand.Intn(n)
		if i == j {
			continue
		}
		if i > j {
			i, j = j, i
		}
		key := [2]int{i, j}
		if used[key] {
			continue
		}
		used[key] = true
		pairs = append(pairs, [2]mutTarget{targets[i], targets[j]})
	}

	return pairs
}

func sampleTestCases(cases []*types.TestCase, max int) []*types.TestCase {
	if len(cases) <= max {
		return cases
	}

	priorityGroups := make(map[int][]*types.TestCase)
	for _, tc := range cases {
		priorityGroups[tc.Priority] = append(priorityGroups[tc.Priority], tc)
	}

	var priorities []int
	for p := range priorityGroups {
		priorities = append(priorities, p)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(priorities)))

	total := len(cases)
	result := make([]*types.TestCase, 0, max)
	remaining := max

	for pi, p := range priorities {
		group := priorityGroups[p]
		groupSize := len(group)

		var take int
		if pi == len(priorities)-1 {
			take = remaining
		} else {
			ratio := float64(groupSize) / float64(total)
			take = int(ratio * float64(max))
			if take < 1 && remaining > 0 {
				take = 1
			}
			if take > remaining {
				take = remaining
			}
			if take > groupSize {
				take = groupSize
			}
		}

		result = append(result, group[:take]...)
		remaining -= take
		if remaining <= 0 {
			break
		}
	}

	return result
}

func matchesPathFilters(apiPath string, includePatterns, excludePatterns []string) bool {
	for _, pattern := range excludePatterns {
		if pattern == "" {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err == nil && re.MatchString(apiPath) {
			return false
		}
	}

	if len(includePatterns) > 0 {
		matched := false
		for _, pattern := range includePatterns {
			if pattern == "" {
				matched = true
				break
			}
			re, err := regexp.Compile(pattern)
			if err == nil && re.MatchString(apiPath) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}
