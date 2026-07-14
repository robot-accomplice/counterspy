package inspect

import "io"

// PacketSource yields IP-layer packets (link header already stripped) from a capture. The live
// implementation reads /dev/bpf on darwin (openLiveCapture); tests inject a fixtureSource. Next
// blocks until a packet is available or the source ends; Close stops the capture.
type PacketSource interface {
	Next() ([]byte, error)
	Close() error
}

// fixtureSource replays a fixed list of IP packets then returns io.EOF, so the tier orchestration
// and flow correlation can be tested without a live BPF capture.
type fixtureSource struct {
	packets [][]byte
	i       int
}

func (f *fixtureSource) Next() ([]byte, error) {
	if f.i >= len(f.packets) {
		return nil, io.EOF
	}
	p := f.packets[f.i]
	f.i++
	return p, nil
}

func (f *fixtureSource) Close() error { return nil }
