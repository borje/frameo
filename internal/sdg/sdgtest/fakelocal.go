// SPDX-License-Identifier: GPL-3.0-or-later

package sdgtest

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"syscall"
)

// LocalDevice is a device listening for direct connections the way a frame on
// the local network does: no grid, no relay, just the tunnel handshake and
// then the service behind it.
type LocalDevice struct {
	Long KeyPair

	// Protocols are the service names this device answers on. A caller that
	// names anything else gets a tunnel and silence, which is what a real
	// frame does.
	Protocols []string

	ln      net.Listener
	handler PeerHandler

	mu   sync.Mutex
	errs []error
	wg   sync.WaitGroup
}

// NewLocalDevice starts a listener on the loopback interface.
func NewLocalDevice(h PeerHandler) (*LocalDevice, error) {
	long, err := NewKeyPair()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	d := &LocalDevice{
		Long:      long,
		Protocols: []string{"framedump_local"},
		ln:        ln,
		handler:   h,
	}
	d.wg.Add(1)
	go d.serve()
	return d, nil
}

// Host and Port are where the device is listening.
func (d *LocalDevice) Host() string {
	h, _, _ := net.SplitHostPort(d.ln.Addr().String())
	return h
}

func (d *LocalDevice) Port() int {
	_, p, _ := net.SplitHostPort(d.ln.Addr().String())
	n, _ := strconv.Atoi(p)
	return n
}

// Close stops the listener and waits for the connections it is serving.
func (d *LocalDevice) Close() error {
	err := d.ln.Close()
	d.wg.Wait()
	return err
}

// Errs reports everything that went wrong while serving.
func (d *LocalDevice) Errs() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return errors.Join(d.errs...)
}

func (d *LocalDevice) record(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.errs = append(d.errs, err)
}

func (d *LocalDevice) serve() {
	defer d.wg.Done()
	for {
		nc, err := d.ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, syscall.EINVAL) {
				d.record(err)
			}
			return
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			defer nc.Close()
			d.handle(nc)
		}()
	}
}

func (d *LocalDevice) handle(nc net.Conn) {
	t := newTunnel(nc, d.Long)
	if err := t.handshake(NeedProtocol); err != nil {
		// A caller that never gets as far as VOCH is not interesting: a real
		// frame closes on anything it does not like, and so does this.
		return
	}
	if !d.answers(t.Protocol()) {
		// The tunnel is up but nothing is behind it, which is exactly what a
		// frame does with a service name it does not know.
		return
	}
	if d.handler != nil {
		d.handler(t)
	}
}

func (d *LocalDevice) answers(protocol string) bool {
	for _, p := range d.Protocols {
		if p == protocol {
			return true
		}
	}
	return false
}
