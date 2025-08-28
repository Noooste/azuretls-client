package azuretls

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func DecodeResponseBody(body io.ReadCloser, encoding string) ([]byte, error) {
	var reader io.Reader
	switch encoding {
	case "gzip":
		reader = &gzipReader{
			body: body,
		}
	case "br":
		return decodeBrotli(body)
	case "deflate":
		reader = identifyDeflate(body)
	case "zstd":
		reader = &zstdReader{
			body: body,
		}
	default:
		if encoding == "" {
			// If no encoding is specified, read the body as is
			data, err := io.ReadAll(body)
			if err != nil {
				return nil, err
			}
			return data, nil
		}
		return nil, errors.New("Unsupported encoding: " + encoding)
	}

	return io.ReadAll(reader)
}

func decodeBrotli(body io.Reader) ([]byte, error) {
	brotliReader := brotli.NewReader(body)
	data, err := io.ReadAll(brotliReader)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// zstdReader wraps a response body so it can lazily
// call zstd.NewReader on the first call to Read
type zstdReader struct {
	body io.ReadCloser // underlying Response.Body
	zr   *zstd.Decoder // lazily-initialized zstd reader
	zerr error         // sticky error
}

func (zs *zstdReader) Read(p []byte) (n int, err error) {
	if zs.zerr != nil {
		return 0, zs.zerr
	}
	if zs.zr == nil {
		zs.zr, err = zstd.NewReader(zs.body)
		if err != nil {
			zs.zerr = err
			return 0, err
		}
	}
	return zs.zr.Read(p)
}

func (zs *zstdReader) Close() error {
	if zs.zr != nil {
		zs.zr.Close() // zs.zr.Close() does not return a value, hence it's not checked for an error
	}

	// Close body and return error
	return zs.body.Close()
}

// gzipReader wraps a response body so it can lazily
// call gzip.NewReader on the first call to Read
type gzipReader struct {
	body io.ReadCloser // underlying Response.Body
	zr   *gzip.Reader  // lazily-initialized gzip reader
	zerr error         // sticky error
}

func (gz *gzipReader) Read(p []byte) (n int, err error) {
	if gz.zerr != nil {
		return 0, gz.zerr
	}
	if gz.zr == nil {
		gz.zr, err = gzip.NewReader(gz.body)
		if err != nil {
			gz.zerr = err
			return 0, err
		}
	}
	return gz.zr.Read(p)
}

func (gz *gzipReader) Close() error {
	return gz.body.Close()
}

// brReader lazily wraps a response body into an
// io.ReadCloser, will call gzip.NewReader on first
// call to read
type brReader struct {
	body io.ReadCloser
	zr   *brotli.Reader
	zerr error
}

func (br *brReader) Read(p []byte) (n int, err error) {
	if br.zerr != nil {
		return 0, br.zerr
	}
	if br.zr == nil {
		br.zr = brotli.NewReader(br.body)
	}
	return br.zr.Read(p)
}

func (br *brReader) Close() error {
	return br.body.Close()
}

type zlibDeflateReader struct {
	body io.ReadCloser
	zr   io.ReadCloser
	err  error
}

func (z *zlibDeflateReader) Read(p []byte) (n int, err error) {
	if z.err != nil {
		return 0, z.err
	}
	if z.zr == nil {
		z.zr, err = zlib.NewReader(z.body)
		if err != nil {
			z.err = err
			return 0, z.err
		}
	}
	return z.zr.Read(p)
}

func (z *zlibDeflateReader) Close() error {
	return z.zr.Close()
}

type deflateReader struct {
	body io.ReadCloser
	r    io.ReadCloser
	err  error
}

func (dr *deflateReader) Read(p []byte) (n int, err error) {
	if dr.err != nil {
		return 0, dr.err
	}
	if dr.r == nil {
		dr.r = flate.NewReader(dr.body)
	}
	return dr.r.Read(p)
}

func (dr *deflateReader) Close() error {
	return dr.r.Close()
}

const (
	zlibMethodDeflate = 0x78
	zlibLevelDefault  = 0x9C
	zlibLevelLow      = 0x01
	zlibLevelMedium   = 0x5E
	zlibLevelBest     = 0xDA
)

func identifyDeflate(body io.ReadCloser) io.ReadCloser {
	var header [2]byte
	_, err := io.ReadFull(body, header[:])
	if err != nil {
		return body
	}

	if header[0] == zlibMethodDeflate &&
		(header[1] == zlibLevelDefault || header[1] == zlibLevelLow || header[1] == zlibLevelMedium || header[1] == zlibLevelBest) {
		return &zlibDeflateReader{
			body: prependBytesToReadCloser(header[:], body),
		}
	} else if header[0] == zlibMethodDeflate {
		return &deflateReader{
			body: prependBytesToReadCloser(header[:], body),
		}
	}
	return body
}

func prependBytesToReadCloser(b []byte, r io.ReadCloser) io.ReadCloser {
	w := new(bytes.Buffer)
	w.Write(b)
	io.Copy(w, r)
	defer r.Close()

	return io.NopCloser(w)
}
