package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/quic-go/quic-go/http3"
)

const uploadAcknowledgment = "terra-http3-upload-ok"

var payloadPattern = func() []byte {
	pattern := make([]byte, 64*1024)
	for index := range pattern {
		pattern[index] = byte(index)
	}
	return pattern
}()

type payloadReader struct {
	remaining int64
	offset    int
}

func (reader *payloadReader) Read(buffer []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	length := min(int64(len(buffer)), reader.remaining)
	for copied := 0; copied < int(length); {
		count := copy(buffer[copied:int(length)], payloadPattern[reader.offset:])
		copied += count
		reader.offset = (reader.offset + count) % len(payloadPattern)
	}
	reader.remaining -= length
	return int(length), nil
}

func verifyPayload(reader io.Reader, size int64) error {
	buffer := make([]byte, len(payloadPattern))
	for remaining := size; remaining > 0; {
		length := int(min(remaining, int64(len(buffer))))
		if _, err := io.ReadFull(reader, buffer[:length]); err != nil {
			return fmt.Errorf("incomplete payload: %w", err)
		}
		if !bytes.Equal(buffer[:length], payloadPattern[:length]) {
			return fmt.Errorf("payload mismatch at byte %d", size-remaining)
		}
		remaining -= int64(length)
	}
	if _, err := io.ReadFull(reader, buffer[:1]); err != io.EOF {
		return fmt.Errorf("payload exceeds expected size or stream failed: %v", err)
	}
	return nil
}

func parseByteCount(value string) (int64, error) {
	size, err := strconv.ParseInt(value, 10, 64)
	if err != nil || size <= 0 {
		return 0, fmt.Errorf("byte count must be a positive integer")
	}
	return size, nil
}

func serveProbe(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 3 {
		http.Error(w, "HTTP/3 required", http.StatusHTTPVersionNotSupported)
		return
	}
	switch r.URL.Path {
	case "/upload", "/download":
		method := http.MethodGet
		if r.URL.Path == "/upload" {
			method = http.MethodPost
		}
		if r.Method != method {
			w.Header().Set("Allow", method)
			http.Error(w, "incorrect method", http.StatusMethodNotAllowed)
			return
		}
		size, err := parseByteCount(r.URL.Query().Get("bytes"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/upload" {
			if err := verifyPayload(r.Body, size); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_, err = io.WriteString(w, uploadAcknowledgment)
		} else {
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
			_, err = io.Copy(w, &payloadReader{remaining: size})
		}
		if err != nil {
			log.Print(err)
		}
	default:
		var err error
		if r.Method == http.MethodPost {
			_, err = io.Copy(w, r.Body)
		} else {
			_, err = io.WriteString(w, "terra-http3-ok")
		}
		if err != nil {
			log.Print(err)
		}
	}
}

func requestHTTP3Response(client *http.Client, request *http.Request) (*http.Response, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 3 {
		response.Body.Close()
		return nil, fmt.Errorf("HTTP/3 response mismatch: %s %s", response.Proto, response.Status)
	}
	return response, nil
}

func verifySmallResponse(response *http.Response, expected string) error {
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, int64(len(expected)+1)))
	if err != nil {
		return err
	}
	if string(payload) != expected {
		return fmt.Errorf("HTTP/3 response payload mismatch")
	}
	return nil
}

func runBenchmark(client *http.Client, mode, address string, size int64) error {
	request, err := http.NewRequest(http.MethodGet, "https://"+address+"/", nil)
	if err != nil {
		return err
	}
	response, err := requestHTTP3Response(client, request)
	if err != nil {
		return err
	}
	if err := verifySmallResponse(response, "terra-http3-ok"); err != nil {
		return err
	}
	method := http.MethodGet
	var body io.Reader
	if mode == "upload" {
		method = http.MethodPost
		body = &payloadReader{remaining: size}
	}
	request, err = http.NewRequest(method, "https://"+address+"/"+mode+"?bytes="+strconv.FormatInt(size, 10), body)
	if err != nil {
		return err
	}
	if mode == "upload" {
		request.ContentLength = size
	}
	started := time.Now()
	response, err = requestHTTP3Response(client, request)
	if err != nil {
		return err
	}
	if mode == "upload" {
		err = verifySmallResponse(response, uploadAcknowledgment)
	} else {
		err = verifyPayload(response.Body, size)
		closeErr := response.Body.Close()
		if err == nil {
			err = closeErr
		}
	}
	if err != nil {
		return err
	}
	seconds := time.Since(started).Seconds()
	return json.NewEncoder(os.Stdout).Encode(struct {
		Case         string  `json:"case"`
		Bytes        int64   `json:"bytes"`
		Seconds      float64 `json:"seconds"`
		MiBPerSecond float64 `json:"mib_per_second"`
		Protocol     string  `json:"protocol"`
		Verified     bool    `json:"verified"`
	}{"http3_" + mode, size, seconds, float64(size) / (1024 * 1024) / seconds, response.Proto, true})
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	if len(os.Args) < 4 || len(os.Args) > 5 {
		log.Fatal("usage: http3-probe server|client ADDRESS CERT_DIRECTORY | upload|download ADDRESS CERT_DIRECTORY BYTES")
	}
	mode := os.Args[1]
	var size int64
	switch mode {
	case "server", "client":
		if len(os.Args) != 4 {
			log.Fatal("server and client modes take ADDRESS CERT_DIRECTORY")
		}
	case "upload", "download":
		if len(os.Args) != 5 {
			log.Fatal("upload and download modes take ADDRESS CERT_DIRECTORY BYTES")
		}
		var err error
		size, err = parseByteCount(os.Args[4])
		check(err)
	default:
		log.Fatal("unknown mode: use server, client, upload, or download")
	}
	address, directory := os.Args[2], os.Args[3]
	certificatePath := filepath.Join(directory, "certificate.pem")
	if mode == "server" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		check(err)
		certificate := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
			DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
		check(err)
		check(os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
		connection, err := net.ListenPacket("udp4", address)
		check(err)
		check(os.WriteFile(filepath.Join(directory, "address"), []byte(connection.LocalAddr().String()), 0600))
		server := http3.Server{
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
			Handler:   http.HandlerFunc(serveProbe),
		}
		check(server.Serve(connection))
		return
	}
	certificate, err := os.ReadFile(certificatePath)
	check(err)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certificate) {
		log.Fatal("invalid fixture certificate")
	}
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}}
	defer transport.Close()
	client := http.Client{Transport: transport, Timeout: 5 * time.Minute}
	if mode == "upload" || mode == "download" {
		check(runBenchmark(&client, mode, address, size))
		return
	}
	for _, size := range []int{0, 4096, 65536} {
		method, expected := http.MethodGet, []byte("terra-http3-ok")
		var body io.Reader
		if size != 0 {
			method = http.MethodPost
			expected = bytes.Repeat([]byte{0x5a}, size)
			body = bytes.NewReader(expected)
		}
		request, err := http.NewRequest(method, "https://"+address+"/", body)
		check(err)
		response, err := client.Do(request)
		check(err)
		payload, err := io.ReadAll(response.Body)
		check(err)
		check(response.Body.Close())
		if response.StatusCode != 200 || response.ProtoMajor != 3 || !bytes.Equal(payload, expected) {
			log.Fatal("HTTP/3 response mismatch")
		}
		fmt.Printf("%s %s: %d verified bytes\n", response.Proto, method, len(payload))
	}
}
