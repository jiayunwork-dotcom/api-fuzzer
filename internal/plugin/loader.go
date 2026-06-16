package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"sort"
	"strings"
	"sync"
	"time"
)

type Loader struct {
	pluginDir string
	plugins   []*PluginInfo
	mu        sync.RWMutex
}

func NewLoader(pluginDir string) *Loader {
	if pluginDir == "" {
		pluginDir = DefaultPluginDir
	}
	return &Loader{
		pluginDir: pluginDir,
		plugins:   make([]*PluginInfo, 0),
	}
}

func (l *Loader) PluginDir() string {
	return l.pluginDir
}

func (l *Loader) Load() ([]*PluginInfo, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.plugins = make([]*PluginInfo, 0)

	if _, err := os.Stat(l.pluginDir); os.IsNotExist(err) {
		return l.plugins, nil
	}

	files, err := filepath.Glob(filepath.Join(l.pluginDir, "*.so"))
	if err != nil {
		return nil, fmt.Errorf("扫描插件目录失败: %w", err)
	}

	if len(files) == 0 {
		return l.plugins, nil
	}

	pluginMap := make(map[string]*PluginInfo)

	for _, file := range files {
		info, loadErr := l.loadPluginFile(file)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "警告: 加载插件 %s 失败: %v\n", filepath.Base(file), loadErr)
			continue
		}

		existing, exists := pluginMap[info.Name]
		if exists {
			if info.Priority > existing.Priority {
				fmt.Fprintf(os.Stderr, "警告: 插件名称冲突 '%s'，保留优先级更高的 %s (%d > %d)\n",
					info.Name, filepath.Base(info.SourceFile), info.Priority, existing.Priority)
				pluginMap[info.Name] = info
			} else {
				fmt.Fprintf(os.Stderr, "警告: 插件名称冲突 '%s'，跳过 %s (优先级 %d <= %d)\n",
					info.Name, filepath.Base(info.SourceFile), info.Priority, existing.Priority)
			}
			continue
		}
		pluginMap[info.Name] = info
	}

	for _, p := range pluginMap {
		l.plugins = append(l.plugins, p)
	}

	l.sortPlugins()

	return l.plugins, nil
}

func (l *Loader) loadPluginFile(filePath string) (*PluginInfo, error) {
	fileInfo, statErr := os.Stat(filePath)
	if statErr != nil {
		return nil, fmt.Errorf("获取插件文件信息失败: %w", statErr)
	}

	p, err := plugin.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开插件文件失败: %w", err)
	}

	sym, err := p.Lookup("NewPlugin")
	if err != nil {
		return nil, fmt.Errorf("查找导出符号 'NewPlugin' 失败: %w", err)
	}

	newPluginFn, ok := sym.(func() MutationPlugin)
	if !ok {
		return nil, fmt.Errorf("'NewPlugin' 签名不匹配，期望 func() MutationPlugin")
	}

	instance := newPluginFn()
	if instance == nil {
		return nil, fmt.Errorf("NewPlugin 返回 nil")
	}

	info := &PluginInfo{
		Name:           instance.Name(),
		Priority:       instance.Priority(),
		SupportedTypes: instance.SupportedTypes(),
		SourceFile:     filePath,
		ModTime:        fileInfo.ModTime(),
		Instance:       instance,
	}

	if info.Name == "" {
		return nil, fmt.Errorf("插件名称为空")
	}
	if info.Priority < 1 || info.Priority > 100 {
		return nil, fmt.Errorf("优先级 %d 超出范围 (1-100)", info.Priority)
	}

	validateErr := instance.Validate()
	if validateErr != nil {
		info.Valid = false
		info.ValidateError = validateErr.Error()
		fmt.Fprintf(os.Stderr, "警告: 插件 '%s' 自检失败: %v\n", info.Name, validateErr)
	} else {
		info.Valid = true
	}

	return info, nil
}

func (l *Loader) sortPlugins() {
	sort.Slice(l.plugins, func(i, j int) bool {
		if l.plugins[i].Priority != l.plugins[j].Priority {
			return l.plugins[i].Priority > l.plugins[j].Priority
		}
		return l.plugins[i].Name < l.plugins[j].Name
	})
}

func (l *Loader) GetPlugins() []*PluginInfo {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]*PluginInfo, len(l.plugins))
	copy(result, l.plugins)
	return result
}

func (l *Loader) GetValidPlugins() []*PluginInfo {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]*PluginInfo, 0)
	for _, p := range l.plugins {
		if p.Valid {
			result = append(result, p)
		}
	}
	return result
}

func (l *Loader) FindMatchingPlugins(paramType string) []*PluginInfo {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]*PluginInfo, 0)
	for _, p := range l.plugins {
		if !p.Valid {
			continue
		}
		if len(p.SupportedTypes) == 0 {
			result = append(result, p)
			continue
		}
		for _, t := range p.SupportedTypes {
			if strings.EqualFold(t, paramType) {
				result = append(result, p)
				break
			}
		}
	}
	return result
}

func (l *Loader) RunMutateWithTimeout(p *PluginInfo, ctx MutationContext, timeout time.Duration) (values []MutatedValue, timedOut bool, err error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	done := make(chan struct{})
	var panicVal interface{}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicVal = r
			}
			close(done)
		}()

		values = p.Instance.Mutate(ctx)
	}()

	select {
	case <-done:
		if panicVal != nil {
			return nil, false, fmt.Errorf("插件 %s Mutate 方法 panic: %v", p.Name, panicVal)
		}
		for i := range values {
			values[i].PluginName = p.Name
		}
		return values, false, nil
	case <-time.After(timeout):
		return nil, true, fmt.Errorf("插件 %s Mutate 方法超时 (%v)", p.Name, timeout)
	}
}

type ReloadResult struct {
	Added   []string
	Updated []string
	Removed []string
	Failed  []string
}

func (l *Loader) Reload() (*ReloadResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	result := &ReloadResult{
		Added:   make([]string, 0),
		Updated: make([]string, 0),
		Removed: make([]string, 0),
		Failed:  make([]string, 0),
	}

	oldPluginMap := make(map[string]*PluginInfo)
	for _, p := range l.plugins {
		oldPluginMap[p.Name] = p
	}

	if _, err := os.Stat(l.pluginDir); os.IsNotExist(err) {
		for name := range oldPluginMap {
			result.Removed = append(result.Removed, name)
		}
		l.plugins = make([]*PluginInfo, 0)
		return result, nil
	}

	files, err := filepath.Glob(filepath.Join(l.pluginDir, "*.so"))
	if err != nil {
		return nil, fmt.Errorf("扫描插件目录失败: %w", err)
	}

	newPluginMap := make(map[string]*PluginInfo)
	loadedNames := make(map[string]bool)

	for _, file := range files {
		fileInfo, statErr := os.Stat(file)
		if statErr != nil {
			continue
		}

		tempInfo, loadErr := l.loadPluginFile(file)
		if loadErr != nil {
			result.Failed = append(result.Failed, filepath.Base(file))
			fmt.Fprintf(os.Stderr, "警告: 加载插件 %s 失败: %v\n", filepath.Base(file), loadErr)
			continue
		}

		if loadedNames[tempInfo.Name] {
			continue
		}

		oldInfo, exists := oldPluginMap[tempInfo.Name]
		if exists {
			if oldInfo.SourceFile == file && oldInfo.ModTime.Equal(fileInfo.ModTime()) {
				newPluginMap[tempInfo.Name] = oldInfo
				loadedNames[tempInfo.Name] = true
				continue
			}

			if !tempInfo.Valid {
				fmt.Fprintf(os.Stderr, "警告: 插件 '%s' 新版本验证失败，保留旧版本继续运行\n", tempInfo.Name)
				newPluginMap[tempInfo.Name] = oldInfo
				result.Failed = append(result.Failed, tempInfo.Name)
				loadedNames[tempInfo.Name] = true
				continue
			}

			newPluginMap[tempInfo.Name] = tempInfo
			result.Updated = append(result.Updated, tempInfo.Name)
			loadedNames[tempInfo.Name] = true
		} else {
			if !tempInfo.Valid {
				fmt.Fprintf(os.Stderr, "警告: 新插件 '%s' 验证失败，跳过\n", tempInfo.Name)
				result.Failed = append(result.Failed, tempInfo.Name)
				continue
			}
			newPluginMap[tempInfo.Name] = tempInfo
			result.Added = append(result.Added, tempInfo.Name)
			loadedNames[tempInfo.Name] = true
		}
	}

	for name := range oldPluginMap {
		if _, exists := newPluginMap[name]; !exists {
			result.Removed = append(result.Removed, name)
		}
	}

	l.plugins = make([]*PluginInfo, 0, len(newPluginMap))
	for _, p := range newPluginMap {
		l.plugins = append(l.plugins, p)
	}

	l.sortPlugins()

	return result, nil
}
