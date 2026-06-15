package progress

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type ProgressBar struct {
	Total     int
	Current   int
	Anomalies int
	StartTime time.Time
	mutex     sync.Mutex

	stopChan    chan struct{}
	signalChan  chan os.Signal
	stopped     bool
	printTicker *time.Ticker
}

func NewProgressBar(total int) *ProgressBar {
	return &ProgressBar{
		Total:     total,
		Current:   0,
		Anomalies: 0,
		StartTime: time.Now(),
	}
}

func (pb *ProgressBar) Start() {
	pb.mutex.Lock()
	if pb.stopped {
		pb.mutex.Unlock()
		return
	}
	pb.stopChan = make(chan struct{})
	pb.signalChan = make(chan os.Signal, 1)
	pb.printTicker = time.NewTicker(200 * time.Millisecond)
	pb.mutex.Unlock()

	signal.Notify(pb.signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		for {
			select {
			case <-pb.stopChan:
				pb.printTicker.Stop()
				signal.Stop(pb.signalChan)
				return
			case <-pb.signalChan:
				pb.Stop()
				os.Exit(0)
			case <-pb.printTicker.C:
				pb.Print()
			}
		}
	}()
}

func (pb *ProgressBar) Increment(n int) {
	pb.mutex.Lock()
	defer pb.mutex.Unlock()
	pb.Current += n
	if pb.Current > pb.Total {
		pb.Current = pb.Total
	}
}

func (pb *ProgressBar) AddAnomaly() {
	pb.mutex.Lock()
	defer pb.mutex.Unlock()
	pb.Anomalies++
}

func (pb *ProgressBar) Stop() {
	pb.mutex.Lock()
	if pb.stopped {
		pb.mutex.Unlock()
		return
	}
	pb.stopped = true
	close(pb.stopChan)
	pb.mutex.Unlock()

	pb.Print()
	fmt.Println()
}

func (pb *ProgressBar) Print() {
	pb.mutex.Lock()
	defer pb.mutex.Unlock()

	total := pb.Total
	current := pb.Current
	anomalies := pb.Anomalies
	elapsed := time.Since(pb.StartTime)

	var percent float64
	if total > 0 {
		percent = float64(current) / float64(total) * 100
		if percent > 100 {
			percent = 100
		}
	}

	barWidth := 10
	filled := 0
	if total > 0 {
		filled = int(float64(barWidth) * float64(current) / float64(total))
	}
	if filled > barWidth {
		filled = barWidth
	}
	empty := barWidth - filled

	bar := "["
	for i := 0; i < filled; i++ {
		bar += "="
	}
	for i := 0; i < empty; i++ {
		bar += "-"
	}
	bar += "]"

	elapsedStr := formatDuration(elapsed)

	var remainingStr string
	if current > 0 && total > 0 && current < total {
		remaining := time.Duration(float64(elapsed) * float64(total-current) / float64(current))
		remainingStr = formatDuration(remaining)
	} else {
		remainingStr = "--:--"
	}

	fmt.Printf("\r%s %5.1f%% (%d/%d) 异常: %d 耗时: %s 剩余: %s",
		bar, percent, current, total, anomalies, elapsedStr, remainingStr)
}

func formatDuration(d time.Duration) string {
	seconds := int(d.Seconds())
	minutes := seconds / 60
	seconds = seconds % 60
	return fmt.Sprintf("%02d:%02d", minutes, seconds)
}
