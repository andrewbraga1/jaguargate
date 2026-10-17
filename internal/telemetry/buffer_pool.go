package telemetry

import (
	"bytes"
	"sync"
)

const (
	defaultSliceSize = 32 * 1024  // 32KB optimal chunk size for SSE & HTTP proxy
	maxPooledCap     = 256 * 1024 // Do not return buffers > 256KB to pool to prevent RAM pinning
)

// ByteSlicePool implements httputil.BufferPool for zero-allocation ReverseProxy streaming.
type ByteSlicePool struct {
	pool sync.Pool
}

// NewByteSlicePool creates a recycled byte slice pool.
func NewByteSlicePool() *ByteSlicePool {
	return &ByteSlicePool{
		pool: sync.Pool{
			New: func() any {
				buf := make([]byte, defaultSliceSize)
				return &buf
			},
		},
	}
}

// Get fetches a 32KB byte slice from the pool.
func (p *ByteSlicePool) Get() []byte {
	bufPtr := p.pool.Get().(*[]byte)
	return *bufPtr
}

// Put zeroes sensitive memory and returns the slice to the pool.
func (p *ByteSlicePool) Put(b []byte) {
	if cap(b) < defaultSliceSize || cap(b) > maxPooledCap {
		return
	}
	b = b[:defaultSliceSize]
	clear(b) // Go 1.21+ built-in ultra-fast memory zeroing for Zero-Trust hygiene
	p.pool.Put(&b)
}

var globalBufferPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, 4096))
	},
}

// AcquireBuffer retrieves a pre-allocated bytes.Buffer from the global pool.
func AcquireBuffer() *bytes.Buffer {
	buf := globalBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

// ReleaseBuffer scrubs and returns a bytes.Buffer to the global pool if within capacity limits.
func ReleaseBuffer(buf *bytes.Buffer) {
	if buf == nil || buf.Cap() > maxPooledCap {
		return
	}
	clear(buf.Bytes())
	buf.Reset()
	globalBufferPool.Put(buf)
}