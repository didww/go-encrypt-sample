# DIDWW Encrypted File Upload — Go Example

A Go example demonstrating how to encrypt and upload a file to the [DIDWW API v3](https://doc.didww.com/) using hybrid encryption (RSA-OAEP + AES-256-CBC).

## How It Works

1. **Fetch public keys** — retrieves two RSA public keys from `GET /public_keys` (no auth required).
2. **Calculate fingerprint** — computes `SHA1(DER_keyA):::SHA1(DER_keyB)` to identify the key pair.
3. **Encrypt the file** — hybrid encryption:
   - Generates a random AES-256 key and IV.
   - Encrypts file data with **AES-256-CBC** (PKCS#7 padding).
   - Encrypts the AES key+IV with **RSA-OAEP** (SHA-256, MGF1-SHA-256) using both public keys.
   - Produces: `[RSA_A(key||iv) | RSA_B(key||iv) | AES(data)]`.
4. **Upload** — sends the encrypted file via multipart `POST /encrypted_files`.

## Prerequisites

- Go 1.21+
- A DIDWW API key ([sign up](https://my.didww.com/sign_up))

## Usage

```bash
# Clone the repository
git clone git@github.com:didww/go-encrypt-sample.git
cd go-encrypt-sample

# Run with the included example.pdf
DIDWW_API_KEY=your_api_key go run main.go

# Or build and run
go build -o didww-upload
DIDWW_API_KEY=your_api_key ./didww-upload
```

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `DIDWW_API_KEY` | Yes | — | Your DIDWW API key |
| `DIDWW_API_BASE_URL` | No | `https://sandbox-api.didww.com/v3` | API base URL. Set to `https://api.didww.com/v3` for production |

### Custom File

To upload a different file, update the `filePath` constant in `main.go`:

```go
const filePath = "path/to/your/file.pdf"
```

## Example Output

```
Read example.pdf (589 bytes)
Fingerprint: 66b91934f62a92153c2e86d87e6599703aa82051:::9c82ff6d35e15691c8d8f5a9d297ef5f5b4c1ba5
Encrypted size: 1616 bytes
Uploaded encrypted file IDs: [ac769056-ef70-4162-bc4b-2afb2fe5a05e]
```

## Project Structure

```
.
├── main.go        # Full encrypt-and-upload implementation
├── example.pdf    # Sample PDF file ("Hello From Go!")
├── go.mod         # Go module definition
└── README.md
```

## Encryption Details

| Component | Algorithm | Details |
|---|---|---|
| Symmetric encryption | AES-256-CBC | 32-byte random key, 16-byte random IV, PKCS#7 padding |
| Key encryption | RSA-OAEP | SHA-256 hash, MGF1-SHA-256, applied with both public keys |
| Fingerprint | SHA-1 | Hex-encoded SHA-1 of each key's DER bytes, joined by `:::` |

## API Endpoints Used

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/public_keys` | None | Fetch RSA public keys |
| `POST` | `/encrypted_files` | `Api-Key` header | Upload encrypted file (multipart) |

## License

MIT
