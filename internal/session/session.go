package session

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"api-fuzzer/internal/types"
)

type SessionStatus string

const (
	StatusCreated    SessionStatus = "created"
	StatusRunning    SessionStatus = "running"
	StatusCompleted  SessionStatus = "completed"
	StatusInterrupted SessionStatus = "interrupted"
)

type SessionConfig struct {
	SpecPath            string        `json:"specPath"`
	SpecFileName        string        `json:"specFileName"`
	BaseURL             string        `json:"baseURL"`
	Concurrency         int           `json:"concurrency"`
	RateLimit           int           `json:"rateLimit"`
	Timeout             time.Duration `json:"timeout"`
	AuthTokens          map[string]string `json:"authTokens,omitempty"`
	IncludePaths        []string      `json:"includePaths,omitempty"`
	ExcludePaths        []string      `json:"excludePaths,omitempty"`
	MaxCasesPerEndpoint int           `json:"maxCasesPerEndpoint"`
	SeverityThreshold   string        `json:"severityThreshold"`
	DiffURL             string        `json:"diffURL,omitempty"`
	DiffTimeThreshold   time.Duration `json:"diffTimeThreshold"`
	DryRun              bool          `json:"dryRun"`
	CreatedAt           time.Time     `json:"createdAt"`
}

type SessionProgress struct {
	Status         SessionStatus `json:"status"`
	TotalCases     int           `json:"totalCases"`
	CompletedCases int           `json:"completedCases"`
	AnomalyCount   int           `json:"anomalyCount"`
	CurrentCaseID  string        `json:"currentCaseId,omitempty"`
	StartTime      time.Time     `json:"startTime"`
	LastUpdateTime time.Time     `json:"lastUpdateTime"`
}

type CaseManifestEntry struct {
	CaseID    string            `json:"caseId"`
	APIPath   string            `json:"apiPath"`
	APIMethod types.HTTPMethod  `json:"apiMethod"`
	Name      string            `json:"name"`
	Priority  int               `json:"priority"`
}

type CasesManifest struct {
	Total int                 `json:"total"`
	Cases []CaseManifestEntry `json:"cases"`
}

type Session struct {
	DirPath       string
	SessionName   string
	Config        *SessionConfig
	Progress      *SessionProgress
	Manifest      *CasesManifest

	mu               sync.Mutex
	anomalyFile      *os.File
	anomalyWriter    *bufio.Writer
	completedIDsFile *os.File
	progressFile     string
	configFile       string
	anomaliesFile    string
	manifestFile     string
	completedIDsPath string
}

func DefaultSessionRoot() string {
	return ".api-fuzzer-sessions"
}

func generateSessionName(specPath string) string {
	timestamp := time.Now().Format("20060102-150405")
	specName := filepath.Base(specPath)
	specName = strings.TrimSuffix(specName, filepath.Ext(specName))
	specName = sanitizeFileName(specName)
	return fmt.Sprintf("%s-%s", timestamp, specName)
}

func sanitizeFileName(name string) string {
	replacer := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		":", "-",
		"*", "-",
		"?", "-",
		"\"", "-",
		"<", "-",
		">", "-",
		"|", "-",
		" ", "-",
	)
	return replacer.Replace(name)
}

func New(specPath string, sessionRoot string) (*Session, error) {
	if sessionRoot == "" {
		sessionRoot = DefaultSessionRoot()
	}

	sessionName := generateSessionName(specPath)
	dirPath := filepath.Join(sessionRoot, sessionName)

	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return nil, fmt.Errorf("create session directory: %w", err)
	}

	s := &Session{
		DirPath:          dirPath,
		SessionName:      sessionName,
		configFile:       filepath.Join(dirPath, "config.json"),
		progressFile:     filepath.Join(dirPath, "progress.json"),
		anomaliesFile:    filepath.Join(dirPath, "anomalies.jsonl"),
		manifestFile:     filepath.Join(dirPath, "cases-manifest.json"),
		completedIDsPath: filepath.Join(dirPath, "completed-ids.jsonl"),
		Config: &SessionConfig{
			SpecPath:     specPath,
			SpecFileName: filepath.Base(specPath),
			CreatedAt:    time.Now(),
		},
		Progress: &SessionProgress{
			Status:         StatusCreated,
			TotalCases:     0,
			CompletedCases: 0,
			AnomalyCount:   0,
			StartTime:      time.Now(),
			LastUpdateTime: time.Now(),
		},
		Manifest: &CasesManifest{
			Total: 0,
			Cases: make([]CaseManifestEntry, 0),
		},
	}

	return s, nil
}

func Load(sessionDir string) (*Session, error) {
	absPath, err := filepath.Abs(sessionDir)
	if err != nil {
		return nil, fmt.Errorf("resolve session path: %w", err)
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("session directory does not exist: %s", absPath)
	}

	s := &Session{
		DirPath:          absPath,
		SessionName:      filepath.Base(absPath),
		configFile:       filepath.Join(absPath, "config.json"),
		progressFile:     filepath.Join(absPath, "progress.json"),
		anomaliesFile:    filepath.Join(absPath, "anomalies.jsonl"),
		manifestFile:     filepath.Join(absPath, "cases-manifest.json"),
		completedIDsPath: filepath.Join(absPath, "completed-ids.jsonl"),
	}

	if err := s.loadConfig(); err != nil {
		return nil, err
	}
	if err := s.loadProgress(); err != nil {
		return nil, err
	}
	if err := s.loadManifest(); err != nil {
		return nil, err
	}

	return s, nil
}

func FindLatestInterrupted(sessionRoot string) (*Session, error) {
	if sessionRoot == "" {
		sessionRoot = DefaultSessionRoot()
	}

	sessions, err := ListSessions(sessionRoot)
	if err != nil {
		return nil, err
	}

	for _, info := range sessions {
		if info.Status == StatusInterrupted || info.Status == StatusCreated {
			return Load(filepath.Join(sessionRoot, info.Name))
		}
	}

	return nil, fmt.Errorf("no interrupted or created session found")
}

type SessionInfo struct {
	Name           string        `json:"name"`
	Status         SessionStatus `json:"status"`
	SpecFileName   string        `json:"specFileName"`
	StartTime      time.Time     `json:"startTime"`
	CompletedCases int           `json:"completedCases"`
	TotalCases     int           `json:"totalCases"`
	AnomalyCount   int           `json:"anomalyCount"`
}

func ListSessions(sessionRoot string) ([]SessionInfo, error) {
	if sessionRoot == "" {
		sessionRoot = DefaultSessionRoot()
	}

	entries, err := os.ReadDir(sessionRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return []SessionInfo{}, nil
		}
		return nil, fmt.Errorf("read session root: %w", err)
	}

	var infos []SessionInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sessionPath := filepath.Join(sessionRoot, entry.Name())
		info, err := readSessionInfo(sessionPath, entry.Name())
		if err != nil {
			continue
		}
		infos = append(infos, info)
	}

	sort.Slice(infos, func(i, j int) bool {
		return infos[i].StartTime.After(infos[j].StartTime)
	})

	return infos, nil
}

func readSessionInfo(dirPath, name string) (SessionInfo, error) {
	info := SessionInfo{Name: name}

	progressPath := filepath.Join(dirPath, "progress.json")
	progressData, err := os.ReadFile(progressPath)
	if err != nil {
		return info, err
	}
	var progress SessionProgress
	if err := json.Unmarshal(progressData, &progress); err != nil {
		return info, err
	}
	info.Status = progress.Status
	info.StartTime = progress.StartTime
	info.CompletedCases = progress.CompletedCases
	info.TotalCases = progress.TotalCases
	info.AnomalyCount = progress.AnomalyCount

	configPath := filepath.Join(dirPath, "config.json")
	configData, err := os.ReadFile(configPath)
	if err == nil {
		var config SessionConfig
		if json.Unmarshal(configData, &config) == nil {
			info.SpecFileName = config.SpecFileName
		}
	}

	return info, nil
}

func (s *Session) SaveConfig() error {
	data, err := json.MarshalIndent(s.Config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(s.configFile, data, 0644)
}

func (s *Session) loadConfig() error {
	data, err := os.ReadFile(s.configFile)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var cfg SessionConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	s.Config = &cfg
	return nil
}

func (s *Session) SaveProgress() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Progress.LastUpdateTime = time.Now()
	data, err := json.MarshalIndent(s.Progress, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal progress: %w", err)
	}
	return os.WriteFile(s.progressFile, data, 0644)
}

func (s *Session) loadProgress() error {
	data, err := os.ReadFile(s.progressFile)
	if err != nil {
		return fmt.Errorf("read progress: %w", err)
	}
	var progress SessionProgress
	if err := json.Unmarshal(data, &progress); err != nil {
		return fmt.Errorf("parse progress: %w", err)
	}
	s.Progress = &progress
	return nil
}

func (s *Session) SaveManifest() error {
	data, err := json.MarshalIndent(s.Manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	return os.WriteFile(s.manifestFile, data, 0644)
}

func (s *Session) loadManifest() error {
	data, err := os.ReadFile(s.manifestFile)
	if err != nil {
		if os.IsNotExist(err) {
			s.Manifest = &CasesManifest{Cases: make([]CaseManifestEntry, 0)}
			return nil
		}
		return fmt.Errorf("read manifest: %w", err)
	}
	var manifest CasesManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}
	s.Manifest = &manifest
	return nil
}

func (s *Session) SetStatus(status SessionStatus) error {
	s.mu.Lock()
	s.Progress.Status = status
	s.mu.Unlock()
	return s.SaveProgress()
}

func (s *Session) OpenAnomalyWriter(appendMode bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	flag := os.O_CREATE | os.O_WRONLY
	if appendMode {
		flag |= os.O_APPEND
	} else {
		flag |= os.O_TRUNC
	}

	f, err := os.OpenFile(s.anomaliesFile, flag, 0644)
	if err != nil {
		return fmt.Errorf("open anomalies file: %w", err)
	}
	s.anomalyFile = f
	s.anomalyWriter = bufio.NewWriter(f)
	return nil
}

func (s *Session) CloseAnomalyWriter() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.anomalyWriter != nil {
		if err := s.anomalyWriter.Flush(); err != nil {
			return err
		}
		s.anomalyWriter = nil
	}
	if s.anomalyFile != nil {
		err := s.anomalyFile.Close()
		s.anomalyFile = nil
		return err
	}
	return nil
}

func (s *Session) AppendAnomaly(a *types.Anomaly) error {
	if a == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.anomalyWriter == nil {
		return fmt.Errorf("anomaly writer not opened")
	}

	data, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("marshal anomaly: %w", err)
	}

	if _, err := s.anomalyWriter.Write(data); err != nil {
		return fmt.Errorf("write anomaly: %w", err)
	}
	if err := s.anomalyWriter.WriteByte('\n'); err != nil {
		return fmt.Errorf("write newline: %w", err)
	}
	if err := s.anomalyWriter.Flush(); err != nil {
		return fmt.Errorf("flush anomaly: %w", err)
	}
	if err := s.anomalyFile.Sync(); err != nil {
		return fmt.Errorf("sync anomaly file: %w", err)
	}

	s.Progress.AnomalyCount++
	return nil
}

func (s *Session) UpdateProgress(completed int, currentCaseID string) error {
	s.mu.Lock()
	s.Progress.CompletedCases = completed
	if currentCaseID != "" {
		s.Progress.CurrentCaseID = currentCaseID
	}
	s.mu.Unlock()
	return s.SaveProgress()
}

func (s *Session) IncrementProgress(currentCaseID string) error {
	if currentCaseID != "" {
		if err := s.appendCompletedID(currentCaseID); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.Progress.CompletedCases++
	if currentCaseID != "" {
		s.Progress.CurrentCaseID = currentCaseID
	}
	s.mu.Unlock()
	return s.SaveProgress()
}

func (s *Session) appendCompletedID(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.completedIDsFile == nil {
		f, err := os.OpenFile(s.completedIDsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("open completed-ids file: %w", err)
		}
		s.completedIDsFile = f
	}

	line := id + "\n"
	if _, err := s.completedIDsFile.WriteString(line); err != nil {
		return fmt.Errorf("write completed-id: %w", err)
	}
	return s.completedIDsFile.Sync()
}

func (s *Session) CloseCompletedIDsFile() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completedIDsFile != nil {
		err := s.completedIDsFile.Close()
		s.completedIDsFile = nil
		return err
	}
	return nil
}

func (s *Session) GetCompletedCaseIDs() map[string]struct{} {
	result := make(map[string]struct{})
	f, err := os.Open(s.completedIDsPath)
	if err != nil {
		return result
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			result[line] = struct{}{}
		}
	}
	return result
}

func (s *Session) AddCaseToManifest(tc *types.TestCase) {
	if tc == nil {
		return
	}
	entry := CaseManifestEntry{
		CaseID:    tc.ID,
		APIPath:   tc.APIPath,
		APIMethod: tc.APIMethod,
		Name:      tc.Name,
		Priority:  tc.Priority,
	}
	s.Manifest.Cases = append(s.Manifest.Cases, entry)
	s.Manifest.Total = len(s.Manifest.Cases)
}

func (s *Session) CanResume() bool {
	return s.Progress.Status == StatusInterrupted || s.Progress.Status == StatusCreated
}

func (s *Session) ReadAnomalies() ([]*types.Anomaly, error) {
	f, err := os.Open(s.anomaliesFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []*types.Anomaly{}, nil
		}
		return nil, fmt.Errorf("open anomalies file: %w", err)
	}
	defer f.Close()

	var anomalies []*types.Anomaly
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var a types.Anomaly
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			fmt.Fprintf(os.Stderr, "警告: 跳过解析失败的异常行 %d: %v\n", lineNum, err)
			continue
		}
		anomalies = append(anomalies, &a)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan anomalies: %w", err)
	}
	return anomalies, nil
}
