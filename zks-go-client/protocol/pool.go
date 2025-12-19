package protocol

import (
	"sync"
)

// BufferPoolSize is the size of buffers in the pool.
// It should be large enough to hold an encrypted packet (MTU + Overhead).
// MTU = 1420, Overhead = 12 (Nonce) + 16 (Tag) = 28.
// We use 2048 to be safe and aligned.
const BufferPoolSize = 2048

var bufferPool = sync.Pool{
	New: func() interface{} {
		// Allocate a new buffer with capacity BufferPoolSize
		// Length is 0 initially, users should reslice as needed or append
		return make([]byte, BufferPoolSize)
	},
}

// GetBuffer retrieves a buffer from the pool.
// The returned buffer has len=BufferPoolSize and cap=BufferPoolSize.
// Callers should slice it to the desired length, e.g. buf[:n]
func GetBuffer() []byte {
	return bufferPool.Get().([]byte)
}

// PutBuffer returns a buffer to the pool.
// It resets the buffer to its original capacity to be ready for reuse.
func PutBuffer(buf []byte) {
	if cap(buf) != BufferPoolSize {
		// Don't put back buffers of wrong size
		return
	}
	// We don't need to zero it out for security if we trust our code to only read what it writes,
	// but strictly speaking, for crypto, zeroing might be preferred.
	// For performance, we skip zeroing as we will overwrite it.
	bufferPool.Put(buf[:cap(buf)])
}
