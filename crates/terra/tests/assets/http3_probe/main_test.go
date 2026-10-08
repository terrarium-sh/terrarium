package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/iotest"
)

func TestPayloadReader(t *testing.T) {
	for _, chunkSize := range []int{1, 255, 257, 65535, 65537} {
		t.Run(fmt.Sprint(chunkSize), func(t *testing.T) {
			const size = 2*65536 + 17
			reader := &payloadReader{remaining: size}
			buffer := make([]byte, chunkSize)
			for offset := 0; offset < size; {
				count, err := reader.Read(buffer)
				if err != nil || count == 0 {
					t.Fatalf("read at %d: %d, %v", offset, count, err)
				}
				for index, value := range buffer[:count] {
					if value != byte(offset+index) {
						t.Fatalf("incorrect byte at %d", offset+index)
					}
				}
				offset += count
			}
			if count, err := reader.Read(buffer); count != 0 || err != io.EOF {
				t.Fatalf("expected EOF, got %d, %v", count, err)
			}
		})
	}
}

func TestServeProbe(t *testing.T) {
	for _, size := range []int64{1, 65535, 65536, 65537, 131089} {
		for _, mode := range []string{"upload", "download"} {
			t.Run(fmt.Sprintf("%s/%d", mode, size), func(t *testing.T) {
				method := http.MethodGet
				var body io.Reader
				if mode == "upload" {
					method = http.MethodPost
					body = &payloadReader{remaining: size}
				}
				request := httptest.NewRequest(method, fmt.Sprintf("/%s?bytes=%d", mode, size), body)
				request.ProtoMajor = 3
				response := httptest.NewRecorder()
				serveProbe(response, request)
				if response.Code != http.StatusOK {
					t.Fatalf("status %d: %s", response.Code, response.Body)
				}
				if mode == "upload" {
					if response.Body.String() != uploadAcknowledgment {
						t.Fatalf("upload acknowledgment: %q", response.Body.String())
					}
				} else if err := verifyPayload(response.Body, size); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	for _, test := range []struct {
		name, method, path string
		body               io.Reader
		protocol, status   int
	}{
		{"wrong protocol", "GET", "/", nil, 2, http.StatusHTTPVersionNotSupported},
		{"wrong upload method", "GET", "/upload?bytes=1", nil, 3, http.StatusMethodNotAllowed},
		{"wrong download method", "POST", "/download?bytes=1", nil, 3, http.StatusMethodNotAllowed},
		{"missing size", "GET", "/download", nil, 3, http.StatusBadRequest},
		{"negative size", "GET", "/download?bytes=-1", nil, 3, http.StatusBadRequest},
		{"zero size", "GET", "/download?bytes=0", nil, 3, http.StatusBadRequest},
		{"overflow size", "GET", "/download?bytes=9223372036854775808", nil, 3, http.StatusBadRequest},
		{"short upload", "POST", "/upload?bytes=2", bytes.NewReader([]byte{0}), 3, http.StatusBadRequest},
		{"extra upload", "POST", "/upload?bytes=1", bytes.NewReader([]byte{0, 1}), 3, http.StatusBadRequest},
		{"corrupt upload", "POST", "/upload?bytes=2", bytes.NewReader([]byte{0, 0}), 3, http.StatusBadRequest},
		{"failed upload", "POST", "/upload?bytes=1", iotest.ErrReader(errors.New("stream failed")), 3, http.StatusBadRequest},
		{"failed final read", "POST", "/upload?bytes=1", io.MultiReader(bytes.NewReader([]byte{0}), iotest.ErrReader(errors.New("stream failed"))), 3, http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, test.body)
			request.ProtoMajor = test.protocol
			response := httptest.NewRecorder()
			serveProbe(response, request)
			if response.Code != test.status {
				t.Fatalf("status %d, expected %d", response.Code, test.status)
			}
		})
	}
}
