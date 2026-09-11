package main

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/cilium/ebpf"
)

// newByteReader wraps a []byte as an io.ReaderAt-compatible reader for
// ebpf.LoadCollectionSpecFromReader, which wants an io.ReaderAt.
func newByteReader(b []byte) io.ReaderAt {
	return bytes.NewReader(b)
}

// isVerifierError unwraps err looking for *ebpf.VerifierError, the way
// errors.As would, kept as a tiny local helper to avoid importing
// `errors` in loader.go just for this one call site.
func isVerifierError(err error, target **ebpf.VerifierError) bool {
	return errors.As(err, target)
}

func splitTracepoint(target string) (category, name string) {
	parts := strings.SplitN(target, "/", 2)
	if len(parts) != 2 {
		return "", parts[0]
	}
	return parts[0], parts[1]
}
