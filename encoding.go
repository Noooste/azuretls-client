package azuretls

import (
	"compress/gzip"
	"errors"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"io"
)

func DecodeResponseBody(body io.Reader, encoding string) ([]byte, error) {
	switch encoding {
	case "gzip":
		return decodeGzip(body)
	case "deflate":
		return decodeDeflate(body)
	case "br":
		return decodeBrotli(body)
	case "zstd":
		return decodeZstd(body)
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
}

func decodeGzip(body io.Reader) ([]byte, error) {
	gzipReader, err := gzip.NewReader(body)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	return io.ReadAll(gzipReader)
}

func decodeDeflate(body io.Reader) ([]byte, error) {
	deflateReader := io.NopCloser(body)
	defer deflateReader.Close()

	// Use a gzip reader for deflate as well, since Go's standard library does not have a dedicated deflate reader
	gzipReader, err := gzip.NewReader(deflateReader)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	return io.ReadAll(gzipReader)
}

func decodeBrotli(body io.Reader) ([]byte, error) {
	brotliReader := brotli.NewReader(body)
	data, err := io.ReadAll(brotliReader)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func decodeZstd(body io.Reader) ([]byte, error) {
	zstdReader, err := zstd.NewReader(body)

	if err != nil {
		return nil, err
	}

	defer zstdReader.Close()
	data, err := io.ReadAll(zstdReader)
	if err != nil {
		return nil, err
	}

	return data, nil
}
