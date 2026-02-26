// Package main demonstrates how to encrypt and upload a file to the DIDWW API v3.
//
// This is a Go port of the Java UploadFileExample from the didww-api-3-java-sdk.
// It implements hybrid encryption (RSA-OAEP + AES-256-CBC) to securely encrypt
// a local file and upload it to the DIDWW encrypted files endpoint.
//
// The encryption scheme uses two RSA public keys fetched from the DIDWW API for
// key redundancy. A random AES-256 key and IV are generated per encryption, used
// to encrypt the file data, and then themselves encrypted with both RSA public keys.
//
// Usage:
//
//	DIDWW_API_KEY=your_api_key go run main.go
//
// Environment variables:
//
//	DIDWW_API_KEY  - (required) Your DIDWW API key for authentication.
//
// The script reads "example.pdf" from the current directory, encrypts it, and
// uploads it to the DIDWW sandbox API.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

const (
	// defaultBaseURL is the DIDWW sandbox API v3 endpoint.
	// Override with DIDWW_API_BASE_URL env var.
	// Production: "https://api.didww.com/v3"
	defaultBaseURL = "https://sandbox-api.didww.com/v3"

	// userAgent identifies this client in HTTP requests.
	userAgent = "didww-go-example/1.0.0"

	// jsonAPIContent is the JSON:API media type used for Accept/Content-Type headers
	// when communicating with JSON:API-compliant DIDWW endpoints.
	jsonAPIContent = "application/vnd.api+json"

	// filePath is the path to the local file to encrypt and upload.
	filePath = "example.pdf"
)

// baseURL returns the API base URL from the environment or the default.
func getBaseURL() string {
	if url := os.Getenv("DIDWW_API_BASE_URL"); url != "" {
		return url
	}
	return defaultBaseURL
}

// --- JSON:API response types for GET /public_keys ---

// publicKeysResponse is the top-level JSON:API response envelope returned by
// GET /public_keys. It contains an array of public key resources.
type publicKeysResponse struct {
	Data []publicKeyResource `json:"data"`
}

// publicKeyResource represents a single public key resource in the JSON:API response.
// Each resource has an ID, a type ("public_keys"), and attributes containing the
// PEM-encoded RSA public key.
type publicKeyResource struct {
	ID         string              `json:"id"`
	Type       string              `json:"type"`
	Attributes publicKeyAttributes `json:"attributes"`
}

// publicKeyAttributes holds the attributes of a public key resource.
// Key contains the full PEM-encoded RSA public key string, including
// "-----BEGIN PUBLIC KEY-----" and "-----END PUBLIC KEY-----" markers.
type publicKeyAttributes struct {
	Key string `json:"key"`
}

// --- JSON response type for POST /encrypted_files ---

// uploadResponse is the JSON response returned by POST /encrypted_files.
// It contains a list of UUIDs identifying the uploaded encrypted files.
type uploadResponse struct {
	IDs []string `json:"ids"`
}

// main orchestrates the full encrypt-and-upload workflow:
//  1. Reads the DIDWW_API_KEY from the environment.
//  2. Reads the local file (example.pdf) from disk.
//  3. Fetches two RSA public keys from the DIDWW API.
//  4. Computes the encryption fingerprint from the two public keys.
//  5. Encrypts the file content using hybrid RSA-OAEP + AES-256-CBC.
//  6. Uploads the encrypted file via multipart POST to /encrypted_files.
//  7. Prints the resulting encrypted file IDs.
func main() {
	// Read the API key from environment. This key is required for the upload
	// endpoint but NOT for fetching public keys.
	apiKey := os.Getenv("DIDWW_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "DIDWW_API_KEY environment variable is required")
		os.Exit(1)
	}

	// Read the local file to be encrypted and uploaded.
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read %s: %v\n", filePath, err)
		os.Exit(1)
	}
	fileName := filepath.Base(filePath)
	fmt.Printf("Read %s (%d bytes)\n", fileName, len(fileContent))

	// Step 1: Fetch the two RSA public keys from the DIDWW API.
	// The DIDWW API always returns exactly two public keys for dual-key encryption.
	pemKeys, err := fetchPublicKeys()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to fetch public keys: %v\n", err)
		os.Exit(1)
	}
	if len(pemKeys) < 2 {
		fmt.Fprintf(os.Stderr, "Expected at least 2 public keys, got %d\n", len(pemKeys))
		os.Exit(1)
	}

	// Step 2: Calculate the fingerprint from both public keys.
	// The fingerprint is sent with the upload so the server knows which key pair
	// was used for encryption.
	fingerprint, err := calculateFingerprint(pemKeys[0], pemKeys[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to calculate fingerprint: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Fingerprint:", fingerprint)

	// Step 3: Encrypt the file content using hybrid encryption with both keys.
	encryptedData, err := encrypt(fileContent, pemKeys[0], pemKeys[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encrypt file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Encrypted size: %d bytes\n", len(encryptedData))

	// Step 4: Upload the encrypted file to the DIDWW API.
	// The ".enc" suffix is appended to the filename to indicate encryption.
	// The original filename is passed as the description.
	ids, err := uploadEncryptedFile(apiKey, encryptedData, fileName+".enc", fingerprint, fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to upload encrypted file: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Uploaded encrypted file IDs:", ids)
}

// fetchPublicKeys retrieves the RSA public keys from the DIDWW API.
//
// It sends a GET request to {baseURL}/public_keys. This endpoint does NOT
// require API key authentication — it is publicly accessible.
//
// The response follows the JSON:API specification and contains two public key
// resources, each with a PEM-encoded RSA public key in its attributes.
//
// Returns a slice of PEM-encoded public key strings, or an error if the
// request fails or the response cannot be parsed.
func fetchPublicKeys() ([]string, error) {
	req, err := http.NewRequest("GET", getBaseURL()+"/public_keys", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", jsonAPIContent)
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET /public_keys returned %d: %s", resp.StatusCode, string(body))
	}

	var result publicKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract the PEM key strings from each JSON:API resource.
	keys := make([]string, len(result.Data))
	for i, d := range result.Data {
		keys[i] = d.Attributes.Key
	}
	return keys, nil
}

// parsePEMPublicKey decodes a PEM-encoded string into an *rsa.PublicKey.
//
// The PEM block is expected to contain a PKIX-formatted (SubjectPublicKeyInfo)
// RSA public key, as returned by the DIDWW API. The function:
//  1. Decodes the PEM block (strips "-----BEGIN/END PUBLIC KEY-----" markers).
//  2. Parses the DER bytes as a PKIX public key.
//  3. Asserts the key is RSA and returns it as *rsa.PublicKey.
//
// Returns an error if the PEM cannot be decoded, the key format is invalid,
// or the key is not an RSA key.
func parsePEMPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}
	return rsaPub, nil
}

// derFromPEM extracts the raw DER-encoded bytes from a PEM-encoded key string.
//
// DER (Distinguished Encoding Rules) is the binary encoding of the public key
// before PEM base64 wrapping. These bytes are used for fingerprint calculation.
//
// Returns the DER bytes or an error if the PEM block cannot be decoded.
func derFromPEM(pemStr string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return block.Bytes, nil
}

// calculateFingerprint computes the encryption fingerprint from two PEM-encoded
// RSA public keys.
//
// The fingerprint uniquely identifies the key pair used for encryption and is
// sent to the server during upload so it can select the correct private keys
// for decryption.
//
// Algorithm:
//  1. Decode each PEM key to its raw DER bytes.
//  2. Compute the SHA-1 hash of each DER byte sequence.
//  3. Convert each hash to a lowercase hexadecimal string.
//  4. Join the two hex strings with ":::" as separator.
//
// Example result: "a1b2c3d4e5...:::f6e5d4c3b2..."
func calculateFingerprint(pemKeyA, pemKeyB string) (string, error) {
	derA, err := derFromPEM(pemKeyA)
	if err != nil {
		return "", fmt.Errorf("key A: %w", err)
	}
	derB, err := derFromPEM(pemKeyB)
	if err != nil {
		return "", fmt.Errorf("key B: %w", err)
	}

	hashA := sha1.Sum(derA)
	hashB := sha1.Sum(derB)

	return fmt.Sprintf("%x:::%x", hashA, hashB), nil
}

// encrypt performs hybrid encryption on the provided data using two RSA public keys.
//
// Hybrid encryption combines symmetric (AES) and asymmetric (RSA) cryptography:
//   - AES-256-CBC encrypts the actual file data (fast, handles large payloads).
//   - RSA-OAEP encrypts the AES key material (secure key exchange).
//
// Encryption steps:
//  1. Generate a cryptographically random AES-256 key (32 bytes).
//  2. Generate a cryptographically random AES initialization vector (16 bytes).
//  3. Encrypt the data using AES-256-CBC with PKCS#7 padding.
//  4. Concatenate the AES key and IV into a 48-byte "credentials" block.
//  5. Encrypt the credentials with RSA-OAEP (SHA-256, MGF1-SHA-256) using key A.
//  6. Encrypt the same credentials with RSA-OAEP using key B (redundancy).
//  7. Concatenate all parts into the final output.
//
// Output binary format (for 2048-bit RSA keys):
//
//	+-------------------+-------------------+------------------------+
//	| RSA_A encrypted   | RSA_B encrypted   | AES-CBC encrypted      |
//	| credentials       | credentials       | file data              |
//	| (256 bytes)       | (256 bytes)       | (variable length)      |
//	+-------------------+-------------------+------------------------+
//
// The two RSA-encrypted blocks each contain the same AES key+IV, encrypted
// independently with different RSA public keys. The server can decrypt using
// either corresponding private key.
//
// Parameters:
//   - data: the plaintext file content to encrypt.
//   - pemKeyA: first RSA public key in PEM format.
//   - pemKeyB: second RSA public key in PEM format.
//
// Returns the encrypted byte sequence or an error.
func encrypt(data []byte, pemKeyA, pemKeyB string) ([]byte, error) {
	// Parse both PEM-encoded public keys into RSA key objects.
	rsaKeyA, err := parsePEMPublicKey(pemKeyA)
	if err != nil {
		return nil, fmt.Errorf("parse key A: %w", err)
	}
	rsaKeyB, err := parsePEMPublicKey(pemKeyB)
	if err != nil {
		return nil, fmt.Errorf("parse key B: %w", err)
	}

	// Generate a random 256-bit AES key for symmetric encryption.
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("generate AES key: %w", err)
	}

	// Generate a random 128-bit initialization vector for CBC mode.
	// The IV ensures identical plaintexts produce different ciphertexts.
	aesIV := make([]byte, aes.BlockSize)
	if _, err := rand.Read(aesIV); err != nil {
		return nil, fmt.Errorf("generate AES IV: %w", err)
	}

	// Encrypt the file data with AES-256-CBC.
	// PKCS#7 padding is applied first to make the data a multiple of the
	// AES block size (16 bytes).
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	paddedData := pkcs7Pad(data, aes.BlockSize)
	aesEncrypted := make([]byte, len(paddedData))
	cipher.NewCBCEncrypter(block, aesIV).CryptBlocks(aesEncrypted, paddedData)

	// Build the AES credentials block: [32-byte key || 16-byte IV] = 48 bytes.
	// This is what gets RSA-encrypted for secure key transport.
	aesCredentials := append(aesKey, aesIV...)

	// Encrypt the AES credentials with RSA-OAEP using key A.
	// RSA-OAEP parameters: SHA-256 hash, MGF1 with SHA-256, no label.
	rsaEncA, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKeyA, aesCredentials, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA encrypt with key A: %w", err)
	}

	// Encrypt the same AES credentials with RSA-OAEP using key B.
	// This provides key redundancy — the server has two chances to decrypt.
	rsaEncB, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKeyB, aesCredentials, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA encrypt with key B: %w", err)
	}

	// Assemble the final encrypted payload:
	// [RSA_A(credentials) | RSA_B(credentials) | AES_CBC(data)]
	result := make([]byte, 0, len(rsaEncA)+len(rsaEncB)+len(aesEncrypted))
	result = append(result, rsaEncA...)
	result = append(result, rsaEncB...)
	result = append(result, aesEncrypted...)

	return result, nil
}

// pkcs7Pad appends PKCS#7 padding to data so its length is a multiple of blockSize.
//
// PKCS#7 padding works by appending N bytes, each with the value N, where N is
// the number of bytes needed to reach the next block boundary. If the data is
// already aligned, a full block of padding (blockSize bytes) is added.
//
// Example with blockSize=16:
//   - 10 bytes of data -> 6 bytes of padding (each byte = 0x06), total = 16
//   - 16 bytes of data -> 16 bytes of padding (each byte = 0x10), total = 32
//   - 20 bytes of data -> 12 bytes of padding (each byte = 0x0C), total = 32
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padBytes := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padBytes...)
}

// uploadEncryptedFile uploads an encrypted file to the DIDWW API via multipart POST.
//
// It sends a POST request to {baseURL}/encrypted_files with the following
// multipart/form-data fields:
//
//   - encrypted_files[encryption_fingerprint]: the fingerprint string identifying
//     which public key pair was used (from calculateFingerprint).
//   - encrypted_files[items][][description]: a human-readable description of the
//     file (typically the original filename before encryption).
//   - encrypted_files[items][][file]: the binary encrypted file data, sent with
//     the encrypted filename (e.g., "example.pdf.enc").
//
// This endpoint requires authentication via the "Api-Key" header.
//
// On success, the API returns a JSON object with an "ids" array containing
// UUIDs for the uploaded encrypted files.
//
// Parameters:
//   - apiKey: the DIDWW API key for authentication.
//   - encryptedData: the encrypted file bytes (output of encrypt()).
//   - encFileName: filename for the upload (e.g., "example.pdf.enc").
//   - fingerprint: the encryption fingerprint (output of calculateFingerprint()).
//   - description: human-readable file description (e.g., "example.pdf").
//
// Returns a slice of uploaded file UUIDs or an error.
func uploadEncryptedFile(apiKey string, encryptedData []byte, encFileName, fingerprint, description string) ([]string, error) {
	// Build the multipart/form-data request body.
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	// Write the encryption fingerprint so the server knows which keys were used.
	if err := writer.WriteField("encrypted_files[encryption_fingerprint]", fingerprint); err != nil {
		return nil, fmt.Errorf("write fingerprint field: %w", err)
	}

	// Write the file description (original filename).
	if err := writer.WriteField("encrypted_files[items][][description]", description); err != nil {
		return nil, fmt.Errorf("write description field: %w", err)
	}

	// Write the encrypted file binary data as a form file upload.
	part, err := writer.CreateFormFile("encrypted_files[items][][file]", encFileName)
	if err != nil {
		return nil, fmt.Errorf("create form file: %w", err)
	}
	if _, err := part.Write(encryptedData); err != nil {
		return nil, fmt.Errorf("write file data: %w", err)
	}

	// Finalize the multipart body (writes the closing boundary).
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close multipart writer: %w", err)
	}

	// Build and send the HTTP POST request.
	req, err := http.NewRequest("POST", getBaseURL()+"/encrypted_files", &body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Api-Key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the full response body for error reporting and JSON parsing.
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	// Check for non-2xx HTTP status codes.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST /encrypted_files returned %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse the JSON response to extract the uploaded file IDs.
	var result uploadResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w (body: %s)", err, string(respBody))
	}

	return result.IDs, nil
}
