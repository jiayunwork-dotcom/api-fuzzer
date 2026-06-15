package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"text/template"
)

const pluginTemplate = `package main

import (
	"api-fuzzer/internal/plugin"
)

type {{.StructName}} struct{}

func (p *{{.StructName}}) Name() string {
	return "{{.PluginName}}"
}

func (p *{{.StructName}}) Priority() int {
	return 80
}

func (p *{{.StructName}}) SupportedTypes() []string {
	return []string{"string"}
}

func (p *{{.StructName}}) Mutate(ctx plugin.MutationContext) []plugin.MutatedValue {
	var results []plugin.MutatedValue

	results = append(results, plugin.MutatedValue{
		Value:      "{{.PluginName}}-test-value",
		Label:      "{{.PluginName}}-sample-mutation",
		Severity:   plugin.SeverityMedium,
		Category:   "injection",
		PluginName: p.Name(),
	})

	return results
}

func (p *{{.StructName}}) Validate() error {
	return nil
}

func NewPlugin() plugin.MutationPlugin {
	return &{{.StructName}}{}
}
`

const buildInstructions = `
# 编译插件说明
# 1. 将此文件保存为 <name>.go
# 2. 使用以下命令编译为 .so 插件:
#    go build -buildmode=plugin -o <name>.so <name>.go
# 3. 将生成的 <name>.so 放入插件目录 (默认为 .api-fuzzer-plugins/)
`

type templateData struct {
	PluginName string
	StructName string
}

func sanitizeStructName(name string) string {
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ".", "_")
	name = strings.ReplaceAll(name, " ", "_")
	if name == "" {
		name = "Custom"
	}
	runes := []rune(name)
	if len(runes) > 0 && runes[0] >= 'a' && runes[0] <= 'z' {
		runes[0] = runes[0] - 32
	}
	return string(runes)
}

func CreatePluginTemplate(pluginDir, name string) error {
	if name == "" {
		return fmt.Errorf("插件名称不能为空")
	}

	if pluginDir == "" {
		pluginDir = DefaultPluginDir
	}

	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return fmt.Errorf("创建插件目录失败: %w", err)
	}

	structName := sanitizeStructName(name)
	data := templateData{
		PluginName: name,
		StructName: structName + "Plugin",
	}

	tmpl, err := template.New("plugin").Parse(pluginTemplate)
	if err != nil {
		return fmt.Errorf("解析模板失败: %w", err)
	}

	fileName := fmt.Sprintf("%s.go", name)
	filePath := filepath.Join(pluginDir, fileName)

	if _, err := os.Stat(filePath); err == nil {
		return fmt.Errorf("文件 %s 已存在", filePath)
	}

	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("写入模板失败: %w", err)
	}

	readmePath := filepath.Join(pluginDir, "BUILD.md")
	if _, err := os.Stat(readmePath); os.IsNotExist(err) {
		if err := os.WriteFile(readmePath, []byte(buildInstructions), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "警告: 创建构建说明失败: %v\n", err)
		}
	}

	fmt.Printf("插件模板已生成: %s\n", filePath)
	fmt.Println("编译命令:")
	fmt.Printf("  cd %s\n", pluginDir)
	fmt.Printf("  go build -buildmode=plugin -o %s.so %s\n", name, fileName)
	return nil
}

func ListPlugins(pluginDir string) error {
	loader := NewLoader(pluginDir)
	plugins, err := loader.Load()
	if err != nil {
		return err
	}

	fmt.Printf("插件目录: %s\n", loader.PluginDir())
	fmt.Printf("发现插件: %d 个\n\n", len(plugins))

	if len(plugins) == 0 {
		fmt.Println("(暂无插件)")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "名称\t优先级\t支持类型\t状态\t文件")
	fmt.Fprintln(w, strings.Repeat("-", 80))

	for _, p := range plugins {
		status := "✓ 可用"
		if !p.Valid {
			status = "✗ 自检失败"
		}
		typesStr := "全部"
		if len(p.SupportedTypes) > 0 {
			typesStr = strings.Join(p.SupportedTypes, ",")
			if len(typesStr) > 20 {
				typesStr = typesStr[:20] + "..."
			}
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n",
			p.Name, p.Priority, typesStr, status, filepath.Base(p.SourceFile))
	}

	return w.Flush()
}

func ValidatePlugins(pluginDir string) error {
	loader := NewLoader(pluginDir)
	plugins, err := loader.Load()
	if err != nil {
		return err
	}

	fmt.Printf("插件目录: %s\n", loader.PluginDir())
	fmt.Printf("发现插件: %d 个\n\n", len(plugins))

	if len(plugins) == 0 {
		fmt.Println("(暂无插件)")
		return nil
	}

	validCount := 0
	invalidCount := 0

	for _, p := range plugins {
		if p.Valid {
			validCount++
			fmt.Printf("[✓] %s (优先级: %d)\n", p.Name, p.Priority)
			if len(p.SupportedTypes) > 0 {
				fmt.Printf("    支持类型: %s\n", strings.Join(p.SupportedTypes, ", "))
			} else {
				fmt.Println("    支持类型: 全部")
			}
		} else {
			invalidCount++
			fmt.Printf("[✗] %s (优先级: %d)\n", p.Name, p.Priority)
			fmt.Printf("    错误: %s\n", p.ValidateError)
		}
		fmt.Println()
	}

	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("结果: %d 个可用, %d 个有问题\n", validCount, invalidCount)

	if invalidCount > 0 {
		return fmt.Errorf("有 %d 个插件未通过验证", invalidCount)
	}
	return nil
}
