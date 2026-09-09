package cloudflareprotocol

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"strings"
)

const (
	defaultMaxSSELineBytes  = 64 << 10
	defaultMaxSSEEventBytes = 1 << 20
	defaultMaxSSEEvents     = 10000
	maxConfiguredSSEBytes   = 16 << 20
	maxConfiguredSSEEvents  = 1000000
)

type SSELimits struct{ MaxLineBytes, MaxEventBytes, MaxEvents int }

func normalizeSSELimits(l SSELimits) (SSELimits, error) {
	if l.MaxLineBytes < 0 || l.MaxEventBytes < 0 || l.MaxEvents < 0 {
		return SSELimits{}, fail(ErrValidation, "sse.limits", "limits cannot be negative", nil)
	}
	if l.MaxLineBytes == 0 {
		l.MaxLineBytes = defaultMaxSSELineBytes
	}
	if l.MaxEventBytes == 0 {
		l.MaxEventBytes = defaultMaxSSEEventBytes
	}
	if l.MaxEvents == 0 {
		l.MaxEvents = defaultMaxSSEEvents
	}
	if l.MaxLineBytes > maxConfiguredSSEBytes || l.MaxEventBytes > maxConfiguredSSEBytes || l.MaxEvents > maxConfiguredSSEEvents {
		return SSELimits{}, fail(ErrValidation, "sse.limits", "configured limit exceeds hard maximum", nil)
	}
	return l, nil
}

type SSEFrame struct {
	Event, ID, Retry string
	Data             []byte
}

// ParseSSE dispatches only events containing data. The final unterminated line
// is processed before EOF, and inserted newlines count toward the body limit.
func ParseSSE(ctx context.Context, r io.Reader, limits SSELimits, emit func(SSEFrame) error) error {
	if r == nil || emit == nil {
		return fail(ErrValidation, "sse", "reader and callback are required", nil)
	}
	l, err := normalizeSSELimits(limits)
	if err != nil {
		return err
	}
	br := bufio.NewReaderSize(r, minInt(l.MaxLineBytes+2, 64<<10))
	var event, lastID, lastRetry string
	var data []string
	dataBytes, events := 0, 0
	flush := func() error {
		if len(data) == 0 {
			event = ""
			dataBytes = 0
			return nil
		}
		events++
		if events > l.MaxEvents {
			return fail(ErrLimit, "sse.events", "event count exceeds limit", nil)
		}
		if err := ctx.Err(); err != nil {
			return fail(ErrCancelled, "sse", "context cancelled", err)
		}
		frame := SSEFrame{
			Event: event,
			ID:    lastID,
			Retry: lastRetry,
			Data:  []byte(strings.Join(data, "\n")),
		}
		event = ""
		data = nil
		dataBytes = 0
		return emit(frame)
	}
	for {
		if err := ctx.Err(); err != nil {
			return fail(ErrCancelled, "sse", "context cancelled", err)
		}
		line, eof, err := readSSELine(br, l.MaxLineBytes)
		if err != nil {
			return err
		}
		if line == "" {
			if err := flush(); err != nil {
				return err
			}
		} else if line[0] != ':' {
			field, value, _ := strings.Cut(line, ":")
			value = strings.TrimPrefix(value, " ")
			switch field {
			case "event":
				event = value
			case "id":
				if !strings.ContainsRune(value, '\x00') {
					lastID = value
				}
			case "retry":
				if validSSERetry(value) {
					lastRetry = value
				}
			case "data":
				extra := len(value)
				if len(data) > 0 {
					extra++
				}
				if dataBytes+extra > l.MaxEventBytes {
					return fail(ErrLimit, "sse.event", "event body exceeds limit", nil)
				}
				dataBytes += extra
				data = append(data, value)
			}
		}
		if eof {
			return flush()
		}
	}
}

func readSSELine(br *bufio.Reader, max int) (string, bool, error) {
	var line []byte
	for {
		fragment, err := br.ReadSlice('\n')
		if len(line)+len(fragment) > max+2 {
			return "", false, fail(ErrLimit, "sse.line", "line exceeds limit", nil)
		}
		line = append(line, fragment...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil && err != io.EOF {
			return "", false, fail(ErrMalformed, "sse", "read stream", err)
		}
		eof := err == io.EOF
		line = bytes.TrimSuffix(line, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) > max {
			return "", false, fail(ErrLimit, "sse.line", "line exceeds limit", nil)
		}
		return string(line), eof, nil
	}
}

func validSSERetry(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
