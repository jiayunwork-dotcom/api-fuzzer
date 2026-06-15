package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"api-fuzzer/internal/auth"
	"api-fuzzer/internal/detector"
	"api-fuzzer/internal/differ"
	"api-fuzzer/internal/executor"
	"api-fuzzer/internal/generator"
	"api-fuzzer/internal/minimizer"
	"api-fuzzer/internal/progress"
	"api-fuzzer/internal/spec"
	"api-fuzzer/internal/types"
)

const (
	Version              = "1.0.0"
	defaultConcurrency   = 10
	maxConcurrency       = 100
	defaultTimeout       = 10 * time.Second
	defaultDiffThreshold = 2 * time.Second
)

type GlobalConfig struct {
	LogLevel string
	Config   string
}

type RunConfig struct {
	Spec                string
	BaseURL             string
	Concurrency         int
	RateLimit           int
	Timeout             time.Duration
	AuthTokens          []string
	BearerToken         string
	APIKey              []string
	BasicAuth           string
	Output              string
	Format              []string
	MaxCasesPerEndpoint int
	SeverityThreshold   string
	IncludePaths        []string
	ExcludePaths        []string
	DryRun              bool
	StateFile           string
	DiffURL             string
	DiffTimeThreshold   time.Duration
	RegressionOut       string
}

type ReportConfig struct {
	Input    string
	Output   string
	Severity string
	Format   string
}

type RegressionConfig struct {
	Cases      string
	BaseURL    string
	Timeout    time.Duration
	AuthTokens []string
	Output     string
	Format     []string
}

type ReportData struct {
	Version     string           `json:"version"`
	GeneratedAt time.Time        `json:"generatedAt"`
	Summary     ReportSummary    `json:"summary"`
	Anomalies   []*types.Anomaly `json:"anomalies"`
	TestCases   int              `json:"testCases"`
	Config      interface{}      `json:"config,omitempty"`
}

type ReportSummary struct {
	Total     int            `json:"total"`
	Critical  int            `json:"critical"`
	High      int            `json:"high"`
	Medium    int            `json:"medium"`
	Low       int            `json:"low"`
	Info      int            `json:"info"`
	ByType    map[string]int `json:"byType"`
	ByPath    map[string]int `json:"byPath"`
	Duration  string         `json:"duration"`
	StartTime time.Time      `json:"startTime"`
	EndTime   time.Time      `json:"endTime"`
}

var (
	globalCfg GlobalConfig
	runCfg    RunConfig
	reportCfg ReportConfig
	regCfg    RegressionConfig
	startTime time.Time
)

func main() {
	if err := Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

func Execute() error {
	rootCmd := &cobra.Command{
		Use:   "api-fuzzer",
		Short: "REST API模糊测试与异常输入发现工具",
		Long: `API Fuzzer 是一款基于 OpenAPI 规范的自动化 REST API 模糊测试工具。
它能够自动生成测试用例，发现 API 在异常输入下的潜在问题，
包括服务器错误、超时、敏感信息泄露、认证绕过等。`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			printBanner()
		},
	}

	rootCmd.PersistentFlags().StringVar(&globalCfg.LogLevel, "log-level", "info", "日志级别 (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&globalCfg.Config, "config", "", "配置文件路径")

	rootCmd.AddCommand(newRunCmd())
	rootCmd.AddCommand(newReportCmd())
	rootCmd.AddCommand(newRegressionCmd())
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd.Execute()
}

func printBanner() {
	banner := `
   ___    ____  ______   _______ ____________ 
  /   |  / __ \/  _/ /  / ____(_) ____/__  __/
 / /| | / /_/ // // /  / /_  / / /_    / /   
/ ___ |/ ____// // /__/ __/ / / __/   / /    
/_/  |_/_/   /___/_____/_/   /_/     /_/     
                                              
`
	fmt.Println(banner)
	fmt.Printf("API Fuzzer v%s - REST API模糊测试与异常输入发现工具\n", Version)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "显示版本信息",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("api-fuzzer version %s\n", Version)
		},
	}
}

func newRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "运行API模糊测试",
		Long: `基于 OpenAPI 规范文件运行 API 模糊测试，自动生成测试用例并执行，
收集异常结果并生成报告。`,
		RunE: runFuzz,
	}

	cmd.Flags().StringVar(&runCfg.Spec, "spec", "", "OpenAPI规范文件路径 (必填)")
	cmd.Flags().StringVar(&runCfg.BaseURL, "base-url", "", "覆盖Server地址")
	cmd.Flags().IntVar(&runCfg.Concurrency, "concurrency", defaultConcurrency, "并发数 (默认10, 最大100)")
	cmd.Flags().IntVar(&runCfg.RateLimit, "rate-limit", 0, "每秒请求速率限制 (0=无限)")
	cmd.Flags().DurationVar(&runCfg.Timeout, "timeout", defaultTimeout, "单个请求超时时间 (默认10s)")
	cmd.Flags().StringSliceVar(&runCfg.AuthTokens, "auth-token", nil, "认证令牌，格式name:value (可多次)")
	cmd.Flags().StringVar(&runCfg.BearerToken, "bearer-token", "", "便捷设置Bearer Token")
	cmd.Flags().StringSliceVar(&runCfg.APIKey, "api-key", nil, "便捷设置API Key，格式name:value (可多次)")
	cmd.Flags().StringVar(&runCfg.BasicAuth, "basic-auth", "", "便捷设置Basic认证，格式user:pass")
	cmd.Flags().StringVar(&runCfg.Output, "output", "", "报告输出路径 (默认./report-时间戳)")
	cmd.Flags().StringSliceVar(&runCfg.Format, "format", []string{"json", "html"}, "报告格式: json, html (默认两者)")
	cmd.Flags().IntVar(&runCfg.MaxCasesPerEndpoint, "max-cases-per-endpoint", 0, "每个端点最大用例数 (0=不限制)")
	cmd.Flags().StringVar(&runCfg.SeverityThreshold, "severity-threshold", "low", "严重程度阈值: info/low/medium/high/critical")
	cmd.Flags().StringSliceVar(&runCfg.IncludePaths, "include-paths", nil, "包含路径正则 (可多次)")
	cmd.Flags().StringSliceVar(&runCfg.ExcludePaths, "exclude-paths", nil, "排除路径正则 (可多次)")
	cmd.Flags().BoolVar(&runCfg.DryRun, "dry-run", false, "只生成用例不发送请求")
	cmd.Flags().StringVar(&runCfg.StateFile, "state-file", "", "断点续跑状态文件路径")
	cmd.Flags().StringVar(&runCfg.DiffURL, "diff-url", "", "差分测试的第二服务器地址")
	cmd.Flags().DurationVar(&runCfg.DiffTimeThreshold, "diff-time-threshold", defaultDiffThreshold, "差分测试响应时间阈值 (默认2s)")
	cmd.Flags().StringVar(&runCfg.RegressionOut, "regression-out", "", "运行结束后保存回归用例到此文件")

	_ = cmd.MarkFlagRequired("spec")

	return cmd
}

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "报告格式转换与查看",
		Long:  "将已生成的JSON报告转换为HTML格式，或按严重程度筛选显示。",
		RunE:  runReport,
	}

	cmd.Flags().StringVar(&reportCfg.Input, "input", "", "报告JSON文件路径 (必填)")
	cmd.Flags().StringVar(&reportCfg.Output, "output", "", "输出报告路径")
	cmd.Flags().StringVar(&reportCfg.Severity, "severity", "info", "只显示该等级以上: info/low/medium/high/critical")
	cmd.Flags().StringVar(&reportCfg.Format, "format", "html", "转换目标格式: json, html")

	_ = cmd.MarkFlagRequired("input")

	return cmd
}

func newRegressionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "regression",
		Short: "运行回归测试",
		Long:  "从回归用例文件加载测试用例并重新运行，验证修复情况。",
		RunE:  runRegression,
	}

	cmd.Flags().StringVar(&regCfg.Cases, "cases", "", "回归用例JSON文件路径 (必填)")
	cmd.Flags().StringVar(&regCfg.BaseURL, "base-url", "", "目标服务器地址")
	cmd.Flags().DurationVar(&regCfg.Timeout, "timeout", defaultTimeout, "单个请求超时时间 (默认10s)")
	cmd.Flags().StringSliceVar(&regCfg.AuthTokens, "auth-token", nil, "认证令牌，格式name:value (可多次)")
	cmd.Flags().StringVar(&regCfg.Output, "output", "", "报告输出路径")
	cmd.Flags().StringSliceVar(&regCfg.Format, "format", []string{"json", "html"}, "报告格式: json, html")

	_ = cmd.MarkFlagRequired("cases")

	return cmd
}

func runFuzz(cmd *cobra.Command, args []string) error {
	startTime = time.Now()

	if runCfg.Concurrency > maxConcurrency {
		fmt.Printf("警告: 并发数 %d 超过最大限制 %d，已自动限制为 %d\n", runCfg.Concurrency, maxConcurrency, maxConcurrency)
		runCfg.Concurrency = maxConcurrency
	}
	if runCfg.Concurrency <= 0 {
		runCfg.Concurrency = defaultConcurrency
	}

	severityThreshold := parseSeverity(runCfg.SeverityThreshold)

	authTokens, err := buildAuthTokens(runCfg.AuthTokens, runCfg.BearerToken, runCfg.APIKey, runCfg.BasicAuth)
	if err != nil {
		return fmt.Errorf("解析认证配置失败: %w", err)
	}

	fmt.Printf("[1/6] 加载 OpenAPI 规范: %s\n", runCfg.Spec)
	apiSpecs, err := spec.LoadOpenAPI(runCfg.Spec)
	if err != nil {
		return fmt.Errorf("加载 OpenAPI 规范失败: %w", err)
	}
	fmt.Printf("  加载完成，共发现 %d 个 API 端点\n", len(apiSpecs))

	fmt.Printf("[2/6] 过滤 API 端点\n")
	filteredSpecs := filterAPISpecs(apiSpecs, runCfg.IncludePaths, runCfg.ExcludePaths)
	if len(filteredSpecs) == 0 {
		return fmt.Errorf("过滤后没有可用的API端点，请检查include/exclude配置")
	}
	fmt.Printf("  过滤完成，剩余 %d 个 API 端点\n", len(filteredSpecs))

	baseURL := runCfg.BaseURL
	if baseURL == "" && len(apiSpecs) > 0 {
		for _, s := range apiSpecs {
			if s.Servers != nil && len(s.Servers) > 0 {
				baseURL = s.Servers[0].URL
				break
			}
		}
	}
	if baseURL == "" {
		return fmt.Errorf("未指定base-url且OpenAPI规范中无server地址")
	}

	fmt.Printf("[3/6] 生成测试用例\n")
	var allTestCases []*types.TestCase
	for _, api := range filteredSpecs {
		cases, genErr := generator.GenerateTestCasesWithOptions(api, runCfg.MaxCasesPerEndpoint, baseURL, generator.GeneratorOptions{
			IncludePaths: runCfg.IncludePaths,
			ExcludePaths: runCfg.ExcludePaths,
		})
		if genErr != nil {
			fmt.Printf("  警告: 生成 %s %s 用例失败: %v\n", api.Method, api.Path, genErr)
			continue
		}
		allTestCases = append(allTestCases, cases...)
	}

	sort.Slice(allTestCases, func(i, j int) bool {
		if allTestCases[i].Priority != allTestCases[j].Priority {
			return allTestCases[i].Priority > allTestCases[j].Priority
		}
		return allTestCases[i].ID < allTestCases[j].ID
	})

	fmt.Printf("  共生成 %d 个测试用例\n", len(allTestCases))

	if runCfg.DryRun {
		estimatedSeconds := float64(len(allTestCases)) / float64(runCfg.Concurrency) * 0.5
		estimatedDuration := time.Duration(estimatedSeconds * float64(time.Second))
		fmt.Println()
		fmt.Println("=== Dry Run 模式 ===")
		fmt.Printf("计划测试用例数: %d\n", len(allTestCases))
		fmt.Printf("并发数: %d\n", runCfg.Concurrency)
		fmt.Printf("预计耗时(估算): %v\n", estimatedDuration.Round(time.Second))
		fmt.Println("未实际发送请求")
		return nil
	}

	fmt.Printf("[4/6] 执行测试用例\n")
	execConfig := &executor.ExecutorConfig{
		Concurrency: runCfg.Concurrency,
		RateLimit:   runCfg.RateLimit,
		Timeout:     runCfg.Timeout,
		BaseURL:     baseURL,
		AuthTokens:  authTokens,
	}
	exec, err := executor.NewExecutor(execConfig)
	if err != nil {
		return fmt.Errorf("创建执行器失败: %w", err)
	}

	if runCfg.StateFile != "" {
		exec.SetStateFile(runCfg.StateFile)
	}

	pb := progress.NewProgressBar(len(allTestCases))
	pb.Start()
	exec.SetProgressBar(pb)

	det := detector.NewDetector(severityThreshold)
	exec.SetDetector(det)

	ctx := context.Background()
	allAnomalies, execErr := exec.Run(ctx, allTestCases, func(tc *types.TestCase, resp *types.HTTPResponse, anomalies []*types.Anomaly) {
		if tc != nil && tc.APISpec != nil {
			for _, a := range anomalies {
				if a != nil && a.APIPath == "" {
					a.APIPath = tc.APIPath
					a.APIMethod = tc.APIMethod
				}
			}
		}
	})
	pb.Stop()

	if execErr != nil && execErr != context.Canceled {
		fmt.Printf("  执行过程出现错误: %v\n", execErr)
	}
	fmt.Printf("  执行完成，发现 %d 个异常\n", len(allAnomalies))

	var diffAnomalies []*types.Anomaly
	if runCfg.DiffURL != "" {
		fmt.Printf("[4.5/6] 执行差分测试\n")
		diff := differ.NewDiffer(baseURL, runCfg.DiffURL, runCfg.DiffTimeThreshold, true, runCfg.Timeout)
		var err error
		diffAnomalies, err = diff.RunDiff(allTestCases)
		if err != nil {
			fmt.Printf("  差分测试错误: %v\n", err)
		} else {
			fmt.Printf("  差分测试完成，发现 %d 个差异\n", len(diffAnomalies))
			allAnomalies = append(allAnomalies, diffAnomalies...)
		}
	}

	fmt.Printf("[5/6] 最小化异常请求\n")
	validAnomalies := make([]*types.Anomaly, 0, len(allAnomalies))
	for _, a := range allAnomalies {
		if a == nil || a.Severity.Compare(severityThreshold) < 0 {
			continue
		}
		validAnomalies = append(validAnomalies, a)
	}

	for i, anomaly := range validAnomalies {
		if anomaly == nil || anomaly.Request == nil {
			continue
		}
		verifyFn := func(req *types.HTTPRequest) (bool, error) {
			return true, nil
		}
		min := minimizer.NewMinimizer(verifyFn, 5*time.Second)
		_, curl, minErr := min.Minimize(anomaly.Request, anomaly.Type)
		if minErr == nil && curl != "" {
			validAnomalies[i].MinimalCurl = curl
		} else {
			validAnomalies[i].MinimalCurl = minimizer.BuildCurl(anomaly.Request)
		}
	}
	fmt.Printf("  最小化完成，保留 %d 个有效异常\n", len(validAnomalies))

	fmt.Printf("[6/6] 生成报告\n")
	outputPath := runCfg.Output
	if outputPath == "" {
		timestamp := time.Now().Format("20060102-150405")
		outputPath = fmt.Sprintf("./report-%s", timestamp)
	}

	reportData := buildReportData(validAnomalies, len(allTestCases), runCfg)

	formats := runCfg.Format
	if len(formats) == 0 {
		formats = []string{"json", "html"}
	}

	for _, fmtType := range formats {
		switch strings.ToLower(fmtType) {
		case "json":
			path := ensureExt(outputPath, ".json")
			if err := saveJSONReport(path, reportData); err != nil {
				fmt.Printf("  保存JSON报告失败: %v\n", err)
			} else {
				fmt.Printf("  JSON报告已保存: %s\n", path)
			}
		case "html":
			path := ensureExt(outputPath, ".html")
			if err := saveHTMLReport(path, reportData); err != nil {
				fmt.Printf("  保存HTML报告失败: %v\n", err)
			} else {
				fmt.Printf("  HTML报告已保存: %s\n", path)
			}
		}
	}

	if runCfg.RegressionOut != "" && len(validAnomalies) > 0 {
		if err := saveRegressionCases(runCfg.RegressionOut, validAnomalies); err != nil {
			fmt.Printf("  保存回归用例失败: %v\n", err)
		} else {
			fmt.Printf("  回归用例已保存: %s\n", runCfg.RegressionOut)
		}
	}

	printSummary(validAnomalies)
	return nil
}

func runReport(cmd *cobra.Command, args []string) error {
	fmt.Printf("读取报告: %s\n", reportCfg.Input)
	data, err := os.ReadFile(reportCfg.Input)
	if err != nil {
		return fmt.Errorf("读取报告文件失败: %w", err)
	}

	var report ReportData
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("解析报告JSON失败: %w", err)
	}

	threshold := parseSeverity(reportCfg.Severity)
	filtered := make([]*types.Anomaly, 0)
	for _, a := range report.Anomalies {
		if a != nil && a.Severity.Compare(threshold) >= 0 {
			filtered = append(filtered, a)
		}
	}
	report.Anomalies = filtered
	report.Summary = buildSummary(filtered)

	outputPath := reportCfg.Output
	if outputPath == "" {
		base := strings.TrimSuffix(reportCfg.Input, filepath.Ext(reportCfg.Input))
		outputPath = base + "-converted"
	}

	switch strings.ToLower(reportCfg.Format) {
	case "json":
		path := ensureExt(outputPath, ".json")
		if err := saveJSONReport(path, &report); err != nil {
			return fmt.Errorf("保存JSON报告失败: %w", err)
		}
		fmt.Printf("JSON报告已保存: %s\n", path)
	case "html":
		path := ensureExt(outputPath, ".html")
		if err := saveHTMLReport(path, &report); err != nil {
			return fmt.Errorf("保存HTML报告失败: %w", err)
		}
		fmt.Printf("HTML报告已保存: %s\n", path)
	default:
		return fmt.Errorf("不支持的格式: %s", reportCfg.Format)
	}

	printSummary(report.Anomalies)
	return nil
}

func runRegression(cmd *cobra.Command, args []string) error {
	startTime = time.Now()

	fmt.Printf("加载回归用例: %s\n", regCfg.Cases)
	data, err := os.ReadFile(regCfg.Cases)
	if err != nil {
		return fmt.Errorf("读取回归用例文件失败: %w", err)
	}

	var testCases []*types.TestCase
	if err := json.Unmarshal(data, &testCases); err != nil {
		return fmt.Errorf("解析回归用例JSON失败: %w", err)
	}
	fmt.Printf("加载完成，共 %d 个回归用例\n", len(testCases))

	if regCfg.BaseURL != "" {
		for _, tc := range testCases {
			if tc != nil && tc.Request != nil {
				tc.Request.URL = replaceBaseURL(tc.Request.URL, regCfg.BaseURL)
			}
		}
	}

	authTokens := make(map[string]string)
	for _, at := range regCfg.AuthTokens {
		parts := strings.SplitN(at, ":", 2)
		if len(parts) == 2 {
			authTokens[parts[0]] = parts[1]
		}
	}

	execConfig := &executor.ExecutorConfig{
		Concurrency: defaultConcurrency,
		Timeout:     regCfg.Timeout,
		BaseURL:     regCfg.BaseURL,
		AuthTokens:  authTokens,
	}
	exec, err := executor.NewExecutor(execConfig)
	if err != nil {
		return fmt.Errorf("创建执行器失败: %w", err)
	}

	pb := progress.NewProgressBar(len(testCases))
	pb.Start()
	exec.SetProgressBar(pb)

	ctx := context.Background()
	anomalies, execErr := exec.Run(ctx, testCases, nil)
	pb.Stop()

	if execErr != nil && execErr != context.Canceled {
		fmt.Printf("执行过程出现错误: %v\n", execErr)
	}
	fmt.Printf("执行完成，发现 %d 个问题\n", len(anomalies))

	regressionAnomalies := make([]*types.Anomaly, 0, len(anomalies))
	anomalyIDs := make(map[string]bool)
	for _, a := range anomalies {
		if a == nil {
			continue
		}
		anomalyIDs[a.TestCaseID] = true
		ra := *a
		ra.Type = types.AnomalyRegressionUnfixed
		regressionAnomalies = append(regressionAnomalies, &ra)
	}

	for _, tc := range testCases {
		if tc == nil {
			continue
		}
		if !anomalyIDs[tc.ID] {
			regressionAnomalies = append(regressionAnomalies, &types.Anomaly{
				ID:         fmt.Sprintf("fixed-%s", tc.ID),
				TestCaseID: tc.ID,
				Type:       types.AnomalyRegressionFixed,
				Severity:   types.SeverityInfo,
				Message:    fmt.Sprintf("回归用例已修复: %s", tc.Name),
				APIPath:    tc.APIPath,
				APIMethod:  tc.APIMethod,
				Timestamp:  time.Now(),
			})
		}
	}

	outputPath := regCfg.Output
	if outputPath == "" {
		timestamp := time.Now().Format("20060102-150405")
		outputPath = fmt.Sprintf("./regression-report-%s", timestamp)
	}

	reportData := buildReportData(regressionAnomalies, len(testCases), regCfg)
	formats := regCfg.Format
	if len(formats) == 0 {
		formats = []string{"json", "html"}
	}

	for _, fmtType := range formats {
		switch strings.ToLower(fmtType) {
		case "json":
			path := ensureExt(outputPath, ".json")
			if err := saveJSONReport(path, reportData); err != nil {
				fmt.Printf("保存JSON报告失败: %v\n", err)
			} else {
				fmt.Printf("JSON报告已保存: %s\n", path)
			}
		case "html":
			path := ensureExt(outputPath, ".html")
			if err := saveHTMLReport(path, reportData); err != nil {
				fmt.Printf("保存HTML报告失败: %v\n", err)
			} else {
				fmt.Printf("HTML报告已保存: %s\n", path)
			}
		}
	}

	printSummary(regressionAnomalies)
	return nil
}

func parseSeverity(s string) types.AnomalySeverity {
	switch strings.ToLower(s) {
	case "info":
		return types.SeverityInfo
	case "low":
		return types.SeverityLow
	case "medium":
		return types.SeverityMedium
	case "high":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	default:
		return types.SeverityLow
	}
}

func buildAuthTokens(authTokens []string, bearerToken string, apiKeys []string, basicAuth string) (map[string]string, error) {
	tokens := make(map[string]string)

	for _, at := range authTokens {
		parts := strings.SplitN(at, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("auth-token格式错误，应为name:value: %s", at)
		}
		tokens[parts[0]] = parts[1]
	}

	if bearerToken != "" {
		tokens["Bearer"] = bearerToken
	}

	for _, ak := range apiKeys {
		parts := strings.SplitN(ak, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("api-key格式错误，应为name:value: %s", ak)
		}
		tokens[parts[0]] = parts[1]
	}

	if basicAuth != "" {
		parts := strings.SplitN(basicAuth, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("basic-auth格式错误，应为user:pass: %s", basicAuth)
		}
		tokens["BasicAuth"] = auth.EncodeBasicAuth(parts[0], parts[1])
	}

	return tokens, nil
}

func filterAPISpecs(specs []*types.APISpec, includePatterns, excludePatterns []string) []*types.APISpec {
	var result []*types.APISpec
	for _, s := range specs {
		if s == nil {
			continue
		}
		excluded := false
		for _, pattern := range excludePatterns {
			if pattern == "" {
				continue
			}
			re, err := regexp.Compile(pattern)
			if err == nil && re.MatchString(s.Path) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		if len(includePatterns) > 0 {
			included := false
			for _, pattern := range includePatterns {
				if pattern == "" {
					included = true
					break
				}
				re, err := regexp.Compile(pattern)
				if err == nil && re.MatchString(s.Path) {
					included = true
					break
				}
			}
			if !included {
				continue
			}
		}

		result = append(result, s)
	}
	return result
}

func buildReportData(anomalies []*types.Anomaly, testCases int, cfg interface{}) *ReportData {
	return &ReportData{
		Version:     Version,
		GeneratedAt: time.Now(),
		Summary:     buildSummary(anomalies),
		Anomalies:   anomalies,
		TestCases:   testCases,
		Config:      cfg,
	}
}

func buildSummary(anomalies []*types.Anomaly) ReportSummary {
	summary := ReportSummary{
		ByType:  make(map[string]int),
		ByPath:  make(map[string]int),
		Total:   len(anomalies),
		StartTime: startTime,
		EndTime:   time.Now(),
	}
	summary.Duration = summary.EndTime.Sub(summary.StartTime).Round(time.Second).String()

	for _, a := range anomalies {
		if a == nil {
			continue
		}
		switch a.Severity {
		case types.SeverityCritical:
			summary.Critical++
		case types.SeverityHigh:
			summary.High++
		case types.SeverityMedium:
			summary.Medium++
		case types.SeverityLow:
			summary.Low++
		case types.SeverityInfo:
			summary.Info++
		}
		summary.ByType[string(a.Type)]++
		if a.APIPath != "" {
			summary.ByPath[a.APIPath]++
		}
	}
	return summary
}

func ensureExt(path, ext string) string {
	if filepath.Ext(path) == "" {
		return path + ext
	}
	return path
}

func saveJSONReport(path string, data *ReportData) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录失败: %w", err)
		}
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化JSON失败: %w", err)
	}
	return os.WriteFile(path, b, 0644)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Fuzzer 测试报告</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
.header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 12px; margin-bottom: 24px; }
.header h1 { font-size: 28px; margin-bottom: 8px; }
.header .meta { opacity: 0.9; font-size: 14px; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 24px; }
.stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }
.stat-card .label { font-size: 12px; color: #888; text-transform: uppercase; margin-bottom: 8px; }
.stat-card .value { font-size: 32px; font-weight: bold; }
.critical .value { color: #dc2626; }
.high .value { color: #ea580c; }
.medium .value { color: #d97706; }
.low .value { color: #2563eb; }
.info .value { color: #6b7280; }
.section { background: white; border-radius: 8px; padding: 24px; margin-bottom: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
.section h2 { font-size: 20px; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 2px solid #eee; }
.anomaly { border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; margin-bottom: 12px; }
.anomaly-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.badge { padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; }
.badge-critical { background: #fee2e2; color: #dc2626; }
.badge-high { background: #ffedd5; color: #ea580c; }
.badge-medium { background: #fef3c7; color: #d97706; }
.badge-low { background: #dbeafe; color: #2563eb; }
.badge-info { background: #f3f4f6; color: #6b7280; }
.anomaly-title { font-weight: 600; font-size: 16px; }
.anomaly-meta { font-size: 13px; color: #666; margin-bottom: 8px; }
.anomaly-message { background: #f9fafb; padding: 12px; border-radius: 6px; margin-bottom: 8px; font-family: monospace; font-size: 13px; }
.anomaly-curl { background: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 6px; font-family: 'Courier New', monospace; font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
.details { margin-top: 8px; font-size: 13px; color: #555; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #eee; }
th { background: #f9fafb; font-weight: 600; }
.empty { text-align: center; padding: 40px; color: #888; }
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>API Fuzzer 测试报告</h1>
<div class="meta">生成时间: {{.GeneratedAt.Format "2006-01-02 15:04:05"}} | 版本: {{.Version}} | 测试用例: {{.TestCases}}</div>
</div>
<div class="stats">
<div class="stat-card"><div class="label">总计</div><div class="value">{{.Summary.Total}}</div></div>
<div class="stat-card critical"><div class="label">Critical</div><div class="value">{{.Summary.Critical}}</div></div>
<div class="stat-card high"><div class="label">High</div><div class="value">{{.Summary.High}}</div></div>
<div class="stat-card medium"><div class="label">Medium</div><div class="value">{{.Summary.Medium}}</div></div>
<div class="stat-card low"><div class="label">Low</div><div class="value">{{.Summary.Low}}</div></div>
<div class="stat-card info"><div class="label">Info</div><div class="value">{{.Summary.Info}}</div></div>
</div>
{{if .Summary.ByType}}
<div class="section">
<h2>按类型统计</h2>
<table><tr><th>类型</th><th>数量</th></tr>
{{range $k, $v := .Summary.ByType}}<tr><td>{{$k}}</td><td>{{$v}}</td></tr>{{end}}
</table>
</div>
{{end}}
{{if .Summary.ByPath}}
<div class="section">
<h2>按路径统计</h2>
<table><tr><th>路径</th><th>数量</th></tr>
{{range $k, $v := .Summary.ByPath}}<tr><td>{{$k}}</td><td>{{$v}}</td></tr>{{end}}
</table>
</div>
{{end}}
<div class="section">
<h2>异常详情 ({{len .Anomalies}})</h2>
{{if .Anomalies}}
{{range .Anomalies}}
<div class="anomaly">
<div class="anomaly-header">
<span class="anomaly-title">{{.Message}}</span>
<span class="badge badge-{{severityClass .Severity}}">{{.Severity}}</span>
</div>
<div class="anomaly-meta">
<strong>{{.APIMethod}}</strong> {{.APIPath}} | 类型: {{.Type}} | 时间: {{.Timestamp.Format "15:04:05"}}
</div>
{{if .Description}}<div class="anomaly-message">{{.Description}}</div>{{end}}
{{if .MinimalCurl}}<div class="anomaly-curl">{{.MinimalCurl}}</div>{{end}}
{{if .Response}}
<div class="details">
响应状态: {{.Response.StatusCode}} | 耗时: {{.Response.Duration}}
{{if .Response.Error}}<br>错误: {{.Response.Error}}{{end}}
</div>
{{end}}
</div>
{{end}}
{{else}}
<div class="empty">没有发现异常</div>
{{end}}
</div>
</div>
</body>
</html>`

func saveHTMLReport(path string, data *ReportData) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录失败: %w", err)
		}
	}

	funcMap := template.FuncMap{
		"severityClass": func(s types.AnomalySeverity) string {
			switch s {
			case types.SeverityCritical:
				return "critical"
			case types.SeverityHigh:
				return "high"
			case types.SeverityMedium:
				return "medium"
			case types.SeverityLow:
				return "low"
			default:
				return "info"
			}
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("解析模板失败: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func saveRegressionCases(path string, anomalies []*types.Anomaly) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录失败: %w", err)
		}
	}

	var cases []*types.TestCase
	seenIDs := make(map[string]bool)
	for _, a := range anomalies {
		if a == nil || seenIDs[a.TestCaseID] {
			continue
		}
		seenIDs[a.TestCaseID] = true
		tc := &types.TestCase{
			ID:        a.TestCaseID,
			APIPath:   a.APIPath,
			APIMethod: a.APIMethod,
			Name:      fmt.Sprintf("Regression: %s", a.Message),
			Request:   a.Request,
			CreatedAt: time.Now(),
		}
		cases = append(cases, tc)
	}

	b, err := json.MarshalIndent(cases, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化JSON失败: %w", err)
	}
	return os.WriteFile(path, b, 0644)
}

func replaceBaseURL(url, newBase string) string {
	if url == "" || newBase == "" {
		return url
	}
	for _, prefix := range []string{"http://", "https://"} {
		if strings.HasPrefix(url, prefix) {
			rest := strings.TrimPrefix(url, prefix)
			slashIdx := strings.Index(rest, "/")
			if slashIdx >= 0 {
				return strings.TrimRight(newBase, "/") + rest[slashIdx:]
			}
		}
	}
	return strings.TrimRight(newBase, "/") + url
}

func printSummary(anomalies []*types.Anomaly) {
	fmt.Println()
	fmt.Println("=== 执行摘要 ===")
	s := buildSummary(anomalies)
	fmt.Printf("总异常数: %d\n", s.Total)
	fmt.Printf("  Critical: %d\n", s.Critical)
	fmt.Printf("  High:     %d\n", s.High)
	fmt.Printf("  Medium:   %d\n", s.Medium)
	fmt.Printf("  Low:      %d\n", s.Low)
	fmt.Printf("  Info:     %d\n", s.Info)
	if s.Duration != "" {
		fmt.Printf("总耗时: %s\n", s.Duration)
	}

}
