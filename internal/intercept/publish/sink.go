// Package publish carries decrypted message events from the `intercept` proxy to the
// `console` viewer, over a live unix socket and/or a rotating log file, the output(s) chosen
// at launch. A message's content is already decoded + Redact-masked by the proxy before it
// reaches any sink here.
package publish

import "counterspy/internal/model"

// Sink receives published per-message events. Publish must be non-blocking-safe (a slow/absent
// reader must not stall the proxy) and Close releases resources. Implementations: the unix socket
// and the log file.
type Sink interface {
	Publish(model.InterceptedMessage) error
	Close() error
}

// Fanout publishes to several sinks; a single sink's error doesn't stop the others (best-effort
// delivery), and Close closes them all. Nil sinks are skipped so the caller can pass optional outputs.
type Fanout []Sink

func (f Fanout) Publish(msg model.InterceptedMessage) error {
	var firstErr error
	for _, s := range f {
		if s == nil {
			continue
		}
		if err := s.Publish(msg); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (f Fanout) Close() error {
	var firstErr error
	for _, s := range f {
		if s == nil {
			continue
		}
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
