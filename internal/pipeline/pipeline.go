// Package pipeline runs explicitly ordered transformation stages.
//
// A pipeline stops at the first failure and never writes output on its own.
// The caller validates, renders, and writes only after every stage succeeds.
package pipeline

import (
	"errors"
	"time"

	"github.com/zoro/byteforge/internal/bferrors"
)

// Stage is one named transformation.
type Stage struct {
	Name string
	Fn   func([]byte) ([]byte, error)
}

// Timing records how long a stage took.
type Timing struct {
	Name     string
	Duration time.Duration
}

// Run executes stages in order.
func Run(input []byte, stages []Stage) ([]byte, []Timing, error) {
	data := input
	timings := make([]Timing, 0, len(stages))
	for _, stage := range stages {
		if stage.Fn == nil {
			return nil, timings, bferrors.New(bferrors.Processing, "pipeline stage %q has no function", stage.Name)
		}
		start := time.Now()
		out, err := stage.Fn(data)
		timings = append(timings, Timing{Name: stage.Name, Duration: time.Since(start)})
		if err != nil {
			return nil, timings, contextualize(stage.Name, err)
		}
		data = out
	}
	return data, timings, nil
}

func contextualize(stage string, err error) error {
	var classified *bferrors.Error
	if errors.As(err, &classified) {
		return err
	}
	return bferrors.Wrap(bferrors.Processing, err, "stage %s failed", stage)
}
