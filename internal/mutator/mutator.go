package mutator

import (
	"math"
	"strings"

	"api-fuzzer/internal/types"
	"api-fuzzer/pkg/utils"
)

type MutationResult struct {
	Value       interface{}
	Target      string
	Description string
}

type Mutator interface {
	Mutate(schema *types.Schema, value interface{}) ([]MutationResult, error)
}

type StringMutator struct{}
type NumberMutator struct{}
type ArrayMutator struct{}
type ObjectMutator struct{}
type BoolMutator struct{}
type NullInjector struct{}

func NewStringMutator() *StringMutator {
	return &StringMutator{}
}

func NewNumberMutator() *NumberMutator {
	return &NumberMutator{}
}

func NewArrayMutator() *ArrayMutator {
	return &ArrayMutator{}
}

func NewObjectMutator() *ObjectMutator {
	return &ObjectMutator{}
}

func NewBoolMutator() *BoolMutator {
	return &BoolMutator{}
}

func NewNullInjector() *NullInjector {
	return &NullInjector{}
}

func (m *StringMutator) Mutate(schema *types.Schema, value interface{}) ([]MutationResult, error) {
	var results []MutationResult

	results = append(results, MutationResult{
		Value:       "",
		Target:      "String.Emtpy",
		Description: "空字符串探测边界条件",
	})

	results = append(results, MutationResult{
		Value:       utils.BuildString(1024*1024, 'A'),
		Target:      "String.Overlong1MB",
		Description: "1MB超长字符串缓冲区溢出探测",
	})

	results = append(results, MutationResult{
		Value:       utils.GenerateUnicodeControls(),
		Target:      "String.UnicodeControls",
		Description: "Unicode控制字符\\x00-\\x1f过滤绕过探测",
	})

	results = append(results, MutationResult{
		Value:       utils.ZeroWidthChars(),
		Target:      "String.ZeroWidth",
		Description: "零宽字符过滤绕过探测",
	})

	results = append(results, MutationResult{
		Value:       "normal" + utils.RTLMark() + "text",
		Target:      "String.RTLMark",
		Description: "RTL双向文本书写方向标记注入",
	})

	results = append(results, MutationResult{
		Value:       "' OR 1=1--",
		Target:      "String.SQLInjection",
		Description: "SQL注入经典载荷' OR 1=1--",
	})

	results = append(results, MutationResult{
		Value:       "<script>alert(1)</script>",
		Target:      "String.XSS",
		Description: "XSS跨站脚本经典载荷<script>alert(1)</script>",
	})

	results = append(results, MutationResult{
		Value:       "../../etc/passwd",
		Target:      "String.PathTraversal",
		Description: "路径遍历探测../../etc/passwd",
	})

	results = append(results, MutationResult{
		Value:       "%s%s%s%n",
		Target:      "String.FormatString",
		Description: "格式化字符串漏洞探测%s%s%s%n",
	})

	results = append(results, MutationResult{
		Value:       `{"key":"value"}`,
		Target:      "String.JSONInjection",
		Description: "JSON注入载荷{\"key\":\"value\"}",
	})

	results = append(results, MutationResult{
		Value:       strings.Repeat("A", 100000),
		Target:      "String.Repeat100K",
		Description: "字符'A'重复100000次超长重复串",
	})

	return results, nil
}

func (m *NumberMutator) Mutate(schema *types.Schema, value interface{}) ([]MutationResult, error) {
	var results []MutationResult

	isInteger := schema != nil && schema.Type == types.TypeInteger

	if isInteger {
		results = append(results, MutationResult{
			Value:       int64(0),
			Target:      "Number.Zero",
			Description: "零值边界探测",
		})

		results = append(results, MutationResult{
			Value:       int64(-1),
			Target:      "Number.NegativeOne",
			Description: "-1边界值探测",
		})

		results = append(results, MutationResult{
			Value:       int64(utils.MaxInt),
			Target:      "Number.MaxInt",
			Description: "MAX_INT最大值边界溢出探测",
		})

		results = append(results, MutationResult{
			Value:       int64(utils.MinInt),
			Target:      "Number.MinInt",
			Description: "MIN_INT最小值边界溢出探测",
		})

		results = append(results, MutationResult{
			Value:       0.0,
			Target:      "Number.FloatZero",
			Description: "浮点0.0整数类型传浮点探测",
		})

		results = append(results, MutationResult{
			Value:       -0.0,
			Target:      "Number.NegativeZeroFloat",
			Description: "负零浮点-0.0整数类型传浮点探测",
		})

		results = append(results, MutationResult{
			Value:       math.NaN(),
			Target:      "Number.NaN",
			Description: "NaN非数值整数类型传NaN探测",
		})

		results = append(results, MutationResult{
			Value:       math.Inf(1),
			Target:      "Number.Infinity",
			Description: "正无穷Infinity整数类型传Inf探测",
		})

		results = append(results, MutationResult{
			Value:       math.Inf(-1),
			Target:      "Number.NegativeInfinity",
			Description: "负无穷-Infinity整数类型传-Inf探测",
		})
	} else {
		results = append(results, MutationResult{
			Value:       float64(0),
			Target:      "Number.Zero",
			Description: "浮点零值边界探测",
		})

		results = append(results, MutationResult{
			Value:       float64(-1),
			Target:      "Number.NegativeOne",
			Description: "浮点-1边界值探测",
		})

		results = append(results, MutationResult{
			Value:       float64(utils.MaxInt),
			Target:      "Number.MaxIntAsFloat",
			Description: "MAX_INT作为浮点数边界探测",
		})

		results = append(results, MutationResult{
			Value:       float64(utils.MinInt),
			Target:      "Number.MinIntAsFloat",
			Description: "MIN_INT作为浮点数边界探测",
		})

		results = append(results, MutationResult{
			Value:       math.NaN(),
			Target:      "Number.NaN",
			Description: "NaN非数值边界探测",
		})

		results = append(results, MutationResult{
			Value:       math.Inf(1),
			Target:      "Number.Infinity",
			Description: "正无穷Infinity边界探测",
		})

		results = append(results, MutationResult{
			Value:       math.Inf(-1),
			Target:      "Number.NegativeInfinity",
			Description: "负无穷-Infinity边界探测",
		})

		results = append(results, MutationResult{
			Value:       1e-300,
			Target:      "Number.TinyFloat",
			Description: "极小浮点1e-300下溢探测",
		})

		results = append(results, MutationResult{
			Value:       1e300,
			Target:      "Number.HugeFloat",
			Description: "极大浮点1e300上溢探测",
		})

		results = append(results, MutationResult{
			Value:       -0.0,
			Target:      "Number.NegativeZero",
			Description: "负零-0.0特殊浮点值探测",
		})
	}

	return results, nil
}

func buildNestedArray(depth int, element interface{}) interface{} {
	if depth <= 0 {
		return element
	}
	return []interface{}{buildNestedArray(depth-1, element)}
}

func (m *ArrayMutator) Mutate(schema *types.Schema, value interface{}) ([]MutationResult, error) {
	var results []MutationResult

	results = append(results, MutationResult{
		Value:       []interface{}{},
		Target:      "Array.Empty",
		Description: "空数组边界探测",
	})

	var sampleElement interface{}
	if schema != nil && schema.Items != nil {
		switch schema.Items.Type {
		case types.TypeString:
			sampleElement = "test"
		case types.TypeInteger:
			sampleElement = int64(1)
		case types.TypeNumber:
			sampleElement = 1.0
		case types.TypeBoolean:
			sampleElement = true
		case types.TypeObject:
			sampleElement = map[string]interface{}{"key": "value"}
		case types.TypeArray:
			sampleElement = []interface{}{}
		default:
			sampleElement = "test"
		}
	} else {
		sampleElement = "test"
	}

	results = append(results, MutationResult{
		Value:       []interface{}{sampleElement},
		Target:      "Array.SingleElement",
		Description: "单元素数组最小有效长度探测",
	})

	largeArray := make([]interface{}, 10000)
	for i := range largeArray {
		largeArray[i] = sampleElement
	}
	results = append(results, MutationResult{
		Value:       largeArray,
		Target:      "Array.Huge10K",
		Description: "10000元素超大数组内存/性能探测",
	})

	nested10 := buildNestedArray(10, sampleElement)
	results = append(results, MutationResult{
		Value:       nested10,
		Target:      "Array.Nested10Levels",
		Description: "10层嵌套数组递归深度探测",
	})

	var wrongTypeElement interface{}
	itemType := ""
	if schema.Items != nil {
		itemType = schema.Items.Type
	}
	switch itemType {
	case types.TypeString:
		wrongTypeElement = int64(123)
	case types.TypeInteger, types.TypeNumber:
		wrongTypeElement = "not_a_number"
	case types.TypeBoolean:
		wrongTypeElement = "not_a_bool"
	case types.TypeObject:
		wrongTypeElement = "not_an_object"
	case types.TypeArray:
		wrongTypeElement = "not_an_array"
	default:
		wrongTypeElement = int64(999)
	}

	if schema.Items == nil {
		wrongTypeElement = int64(999)
	}

	wrongTypeArray := []interface{}{wrongTypeElement}
	results = append(results, MutationResult{
		Value:       wrongTypeArray,
		Target:      "Array.WrongElementType",
		Description: "元素类型错误数组类型校验探测",
	})

	return results, nil
}

func buildNestedObject(depth int, key string, value interface{}) interface{} {
	if depth <= 0 {
		return map[string]interface{}{key: value}
	}
	return map[string]interface{}{key: buildNestedObject(depth-1, key, value)}
}

func (m *ObjectMutator) Mutate(schema *types.Schema, value interface{}) ([]MutationResult, error) {
	var results []MutationResult

	results = append(results, MutationResult{
		Value:       map[string]interface{}{},
		Target:      "Object.Empty",
		Description: "空对象所有字段缺失探测",
	})

	if schema != nil && len(schema.Required) > 0 {
		partialObj := make(map[string]interface{})
		if schema.Properties != nil {
			for k, v := range schema.Properties {
				if !utils.Contains(schema.Required, k) {
					switch v.Type {
					case types.TypeString:
						partialObj[k] = "value"
					case types.TypeInteger:
						partialObj[k] = int64(1)
					case types.TypeNumber:
						partialObj[k] = 1.0
					case types.TypeBoolean:
						partialObj[k] = true
					default:
						partialObj[k] = "value"
					}
				}
			}
		}
		results = append(results, MutationResult{
			Value:       partialObj,
			Target:      "Object.MissingAllRequired",
			Description: "缺失所有必填字段必填校验探测",
		})
	}

	extraFieldsObj := make(map[string]interface{})
	if schema != nil && schema.Properties != nil {
		for k, v := range schema.Properties {
			switch v.Type {
			case types.TypeString:
				extraFieldsObj[k] = "value"
			case types.TypeInteger:
				extraFieldsObj[k] = int64(1)
			case types.TypeNumber:
				extraFieldsObj[k] = 1.0
			case types.TypeBoolean:
				extraFieldsObj[k] = true
			default:
				extraFieldsObj[k] = "value"
			}
		}
	}
	for i := 0; i < 100; i++ {
		extraFieldsObj["extra_field_"+utils.IntToString(int64(i))] = "fuzz_value_" + utils.IntToString(int64(i))
	}
	results = append(results, MutationResult{
		Value:       extraFieldsObj,
		Target:      "Object.Extra100Fields",
		Description: "100个额外未声明字段未知字段处理探测",
	})

	wrongTypeObj := make(map[string]interface{})
	if schema != nil && schema.Properties != nil {
		for k, v := range schema.Properties {
			switch v.Type {
			case types.TypeString:
				wrongTypeObj[k] = int64(999)
			case types.TypeInteger, types.TypeNumber:
				wrongTypeObj[k] = "not_a_number"
			case types.TypeBoolean:
				wrongTypeObj[k] = "not_a_bool"
			case types.TypeArray:
				wrongTypeObj[k] = "not_an_array"
			case types.TypeObject:
				wrongTypeObj[k] = "not_an_object"
			default:
				wrongTypeObj[k] = int64(42)
			}
		}
	} else {
		wrongTypeObj["field1"] = int64(1)
		wrongTypeObj["field2"] = "wrong"
	}
	results = append(results, MutationResult{
		Value:       wrongTypeObj,
		Target:      "Object.AllWrongTypes",
		Description: "所有字段类型错误类型校验探测",
	})

	nestedObj := buildNestedObject(10, "nested", "deep_value")
	results = append(results, MutationResult{
		Value:       nestedObj,
		Target:      "Object.Nested10Levels",
		Description: "10层嵌套对象递归深度探测",
	})

	longKeyObj := make(map[string]interface{})
	longKey := utils.BuildString(1000, 'K')
	longKeyObj[longKey] = "long_key_value"
	if schema != nil && schema.Properties != nil {
		for k, v := range schema.Properties {
			switch v.Type {
			case types.TypeString:
				longKeyObj[k] = "value"
			case types.TypeInteger:
				longKeyObj[k] = int64(1)
			case types.TypeNumber:
				longKeyObj[k] = 1.0
			case types.TypeBoolean:
				longKeyObj[k] = true
			default:
				longKeyObj[k] = "value"
			}
		}
	}
	results = append(results, MutationResult{
		Value:       longKeyObj,
		Target:      "Object.LongKey1000Chars",
		Description: "超长1000字符key字段名长度探测",
	})

	return results, nil
}

func (m *BoolMutator) Mutate(schema *types.Schema, value interface{}) ([]MutationResult, error) {
	var results []MutationResult

	results = append(results, MutationResult{
		Value:       nil,
		Target:      "Bool.Null",
		Description: "null代替布尔空值处理探测",
	})

	results = append(results, MutationResult{
		Value:       int64(0),
		Target:      "Bool.Int0",
		Description: "整数0代替false类型混淆探测",
	})

	results = append(results, MutationResult{
		Value:       int64(1),
		Target:      "Bool.Int1",
		Description: "整数1代替true类型混淆探测",
	})

	results = append(results, MutationResult{
		Value:       "true",
		Target:      "Bool.StringTrue",
		Description: "字符串\"true\"代替true类型混淆探测",
	})

	results = append(results, MutationResult{
		Value:       "false",
		Target:      "Bool.StringFalse",
		Description: "字符串\"false\"代替false类型混淆探测",
	})

	results = append(results, MutationResult{
		Value:       "",
		Target:      "Bool.EmptyString",
		Description: "空字符串代替布尔空串处理探测",
	})

	return results, nil
}

func (m *NullInjector) Mutate(schema *types.Schema, value interface{}) ([]MutationResult, error) {
	var results []MutationResult

	if schema == nil {
		results = append(results, MutationResult{
			Value:       nil,
			Target:      "NullInjector.RootNull",
			Description: "根值设为null空指针探测",
		})
		return results, nil
	}

	switch schema.Type {
	case types.TypeObject:
		if schema.Properties != nil && len(schema.Properties) > 0 {
			for fieldName := range schema.Properties {
				newObj := make(map[string]interface{})
				for k, v := range schema.Properties {
					if k == fieldName {
						newObj[k] = nil
					} else {
						switch v.Type {
						case types.TypeString:
							newObj[k] = "value"
						case types.TypeInteger:
							newObj[k] = int64(1)
						case types.TypeNumber:
							newObj[k] = 1.0
						case types.TypeBoolean:
							newObj[k] = true
						case types.TypeArray:
							newObj[k] = []interface{}{}
						case types.TypeObject:
							newObj[k] = map[string]interface{}{}
						default:
							newObj[k] = "value"
						}
					}
				}
				results = append(results, MutationResult{
					Value:       newObj,
					Target:      "NullInjector.Field_" + fieldName,
					Description: "字段 '" + fieldName + "' 设为null单字段null注入探测",
				})
			}

			allNullObj := make(map[string]interface{})
			for k := range schema.Properties {
				allNullObj[k] = nil
			}
			results = append(results, MutationResult{
				Value:       allNullObj,
				Target:      "NullInjector.AllFieldsNull",
				Description: "所有字段设为null全字段null注入探测",
			})
		} else {
			results = append(results, MutationResult{
				Value:       nil,
				Target:      "NullInjector.RootNull",
				Description: "对象根值设为null空对象探测",
			})
		}

	case types.TypeArray:
		if schema.Items != nil {
			nullArray := []interface{}{nil}
			results = append(results, MutationResult{
				Value:       nullArray,
				Target:      "NullInjector.ArrayElementNull",
				Description: "数组元素设为null数组元素null注入",
			})
		}
		results = append(results, MutationResult{
			Value:       nil,
			Target:      "NullInjector.ArrayRootNull",
			Description: "数组根值设为null数组整体null注入",
		})

	default:
		results = append(results, MutationResult{
			Value:       nil,
			Target:      "NullInjector.ValueNull",
			Description: "标量值设为null基础类型null注入",
		})
	}

	return results, nil
}

func GetMutations(schema *types.Schema, originalValue interface{}) ([]MutationResult, error) {
	var allResults []MutationResult

	if schema == nil {
		nullInj := NewNullInjector()
		results, err := nullInj.Mutate(nil, originalValue)
		if err != nil {
			return nil, err
		}
		allResults = append(allResults, results...)
		return allResults, nil
	}

	switch schema.Type {
	case types.TypeString:
		stringMut := NewStringMutator()
		results, err := stringMut.Mutate(schema, originalValue)
		if err != nil {
			return nil, err
		}
		allResults = append(allResults, results...)

	case types.TypeNumber, types.TypeInteger:
		numberMut := NewNumberMutator()
		results, err := numberMut.Mutate(schema, originalValue)
		if err != nil {
			return nil, err
		}
		allResults = append(allResults, results...)

	case types.TypeBoolean:
		boolMut := NewBoolMutator()
		results, err := boolMut.Mutate(schema, originalValue)
		if err != nil {
			return nil, err
		}
		allResults = append(allResults, results...)

	case types.TypeArray:
		arrayMut := NewArrayMutator()
		results, err := arrayMut.Mutate(schema, originalValue)
		if err != nil {
			return nil, err
		}
		allResults = append(allResults, results...)

	case types.TypeObject:
		objectMut := NewObjectMutator()
		results, err := objectMut.Mutate(schema, originalValue)
		if err != nil {
			return nil, err
		}
		allResults = append(allResults, results...)

	case types.TypeNull, "":
		nullInj := NewNullInjector()
		results, err := nullInj.Mutate(schema, originalValue)
		if err != nil {
			return nil, err
		}
		allResults = append(allResults, results...)
	}

	nullInj := NewNullInjector()
	nullResults, err := nullInj.Mutate(schema, originalValue)
	if err != nil {
		return nil, err
	}
	allResults = append(allResults, nullResults...)

	return allResults, nil
}
