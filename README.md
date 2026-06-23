# gofortify

A Go library for JWT-based authentication with access/refresh token management, token revocation via Redis blacklist, and incident-time protection.

## Features

- Generate signed access and refresh tokens with configurable TTL
- Validate access tokens with optional Access Token Verifier (ATV) cookie binding
- Validate refresh tokens
- Revoke tokens by adding them to a Redis-backed blacklist
- Incident-time protection: tokens issued before a recorded incident time are automatically rejected
- Supports multiple JWT signing methods (HS256, HS384, HS512, RS*, ES*, PS*, EdDSA)

## Requirements

- Go 1.25+
- Redis (only required when using `JWT_BLACKLIST_DRIVER=redis`)

## Installation

```bash
go get github.com/iqbalatma/gofortify
```

## Configuration

gofortify reads its configuration from environment variables. Call `LoadJWTConfig()` once at startup — it automatically sets up the blacklist driver based on `JWT_BLACKLIST_DRIVER`.

```go
import gofortify "github.com/iqbalatma/gofortify"

func main() {
    gofortify.LoadJWTConfig()
    // ...
}
```

### Environment Variables

| Variable                          | Description                                               | Default  |
|-----------------------------------|-----------------------------------------------------------|----------|
| `JWT_SIGNING_METHOD`              | Signing algorithm (e.g. `HS256`, `EdDSA`)                 | —        |
| `JWT_SECRET_KEY`                  | HMAC: shared secret. Asymmetric: PEM-encoded private key  | —        |
| `JWT_PUBLIC_KEY`                  | Asymmetric only: PEM-encoded public key                   | —        |
| `JWT_ACCESS_TOKEN_TTL`            | Access token TTL in minutes                               | `30`     |
| `JWT_REFRESH_TOKEN_TTL`           | Refresh token TTL in minutes                              | `10080`  |
| `JWT_BLACKLIST_DRIVER`            | Blacklist driver: `redis` or `memory`                     | —        |
| `JWT_REDIS_HOST`                  | Redis host (required when driver is `redis`)              | —        |
| `JWT_REDIS_PORT`                  | Redis port (required when driver is `redis`)              | —        |
| `JWT_REDIS_PASSWORD`              | Redis password                                            | —        |
| `JWT_REDIS_DB`                    | Redis database index                                      | —        |
| `JWT_BLACKLIST_INCIDENT_TIME_KEY` | Key used to store the incident timestamp in blacklist     | —        |

### .env Template

```bash
JWT_SIGNING_METHOD=HS256
JWT_SECRET_KEY=your-secret-key
JWT_PUBLIC_KEY=
JWT_ACCESS_TOKEN_TTL=30
JWT_REFRESH_TOKEN_TTL=10080
JWT_BLACKLIST_DRIVER=redis
JWT_REDIS_HOST=localhost
JWT_REDIS_PORT=6379
JWT_REDIS_PASSWORD=
JWT_REDIS_DB=0
JWT_BLACKLIST_INCIDENT_TIME_KEY=jwt_incident_time
```

### Blacklist Drivers

gofortify ships two blacklist implementations. Set `JWT_BLACKLIST_DRIVER` to choose one.

**Redis** — persistent, recommended for production:
```env
JWT_BLACKLIST_DRIVER=redis
JWT_REDIS_HOST=localhost
JWT_REDIS_PORT=6379
JWT_REDIS_PASSWORD=
JWT_REDIS_DB=0
```

**Memory** — in-process, no Redis required, resets on restart:
```env
JWT_BLACKLIST_DRIVER=memory
```

**Custom** — implement the `Blacklist` interface and register it manually:
```go
gofortify.SetBlacklist(myCustomBlacklist{})
```

```go
type Blacklist interface {
    Get(key string) any
    Set(key string, value any, expired time.Duration)
    Delete(key string)
}
```

### Supported Signing Methods

Set `JWT_SIGNING_METHOD` to one of the values below.

#### HMAC — Symmetric (shared secret key)

| Algorithm | Hash   | Notes                              |
|-----------|--------|------------------------------------|
| `HS256`   | SHA-256 | Default choice, fast, widely supported |
| `HS384`   | SHA-384 | Larger hash, marginally more secure |
| `HS512`   | SHA-512 | Largest hash in the HMAC family    |

> Use HMAC when the same service both signs and verifies tokens. The secret key must be kept private.

#### RSA — Asymmetric (private key signs, public key verifies)

| Algorithm | Hash    | Key size recommendation |
|-----------|---------|-------------------------|
| `RS256`   | SHA-256 | 2048-bit minimum        |
| `RS384`   | SHA-384 | 2048-bit minimum        |
| `RS512`   | SHA-512 | 4096-bit recommended    |

> Use RSA when you need to share the verification key publicly (e.g. between microservices) while keeping the signing key private.

#### ECDSA — Asymmetric (elliptic curve)

| Algorithm | Curve   | Hash    | Notes                     |
|-----------|---------|---------|---------------------------|
| `ES256`   | P-256   | SHA-256 | Recommended — compact keys |
| `ES384`   | P-384   | SHA-384 | Higher security margin     |
| `ES512`   | P-521   | SHA-512 | Strongest ECDSA option     |

> ECDSA produces much smaller keys and signatures than RSA at equivalent security levels.

#### RSA-PSS — Asymmetric (RSA with probabilistic padding)

| Algorithm | Hash    | Notes                                    |
|-----------|---------|------------------------------------------|
| `PS256`   | SHA-256 | More secure padding scheme than RS256    |
| `PS384`   | SHA-384 |                                          |
| `PS512`   | SHA-512 |                                          |

> PSS is the modern, recommended RSA padding scheme. Prefer `PS256` over `RS256` for new systems.

#### EdDSA — Asymmetric (Edwards-curve)

| Algorithm | Curve    | Notes                                          |
|-----------|----------|------------------------------------------------|
| `EdDSA`   | Ed25519  | Fastest asymmetric option, very small keys/signatures |

> EdDSA (Ed25519) is the recommended choice for new asymmetric setups — fast, secure, and compact.

#### Quick Recommendation

| Scenario | Recommended algorithm |
|---|---|
| Simple single-service app | `HS256` |
| Microservices with public verification | `ES256` or `EdDSA` |
| Compliance requiring RSA | `PS256` |
| Maximum security budget | `EdDSA` or `ES512` |

## Usage

### Implement `Subject`

Your user/entity struct must implement the `Subject` interface so gofortify knows what to embed as the token subject (`sub` claim).

```go
import gofortify "github.com/iqbalatma/gofortify"

type User struct {
    ID   string
    Name string
}

func (u *User) GetSubjectKey() string {
    return u.ID
}
```

### Encode (Generate Tokens)

```go
user := &User{ID: "1", Name: "Alice"}

// Generate an access token
tokenString, accessTokenVerifier, err := gofortify.Encode(
    user,                      // Subject
    gofortify.AccessToken,     // token type
    true,                      // iuc: true = cookie bound (enables ATV binding)
    "my-service",              // iss: issuer
    "Mozilla/5.0 ...",         // iua: issued user agent
)

// Generate a refresh token
refreshString, _, err := gofortify.Encode(
    user,
    gofortify.RefreshToken,
    false,
    "my-service",
    "Mozilla/5.0 ...",
)
```

`Encode` returns:
- `tokenString` — the signed JWT string
- `accessTokenVerifier` — raw ATV value (only set for access tokens with `iuc: true`); store this in an `HttpOnly` cookie
- `err` — any error

### Validate Access Token

```go
token := "Bearer eyJ..."
atv := "atv-value-from-cookie" // pass nil if iuc is false

payload, err := gofortify.ValidateAccessToken(&token, &atv)
if err != nil {
    // handle: gofortify.ErrExpiredToken, gofortify.ErrInvalidTokenType,
    //         gofortify.ErrMissingRequiredAccessTokenVerifierCookie,
    //         gofortify.ErrInvalidAccessTokenVerifier
}

fmt.Println(payload.SUB) // subject (user ID)
```

### Validate Refresh Token

```go
token := "Bearer eyJ..."

payload, err := gofortify.ValidateRefreshToken(&token)
if err != nil {
    // handle error
}
```

### Revoke a Token

Adds the token's JTI to the Redis blacklist with a TTL equal to the remaining token lifetime.

```go
token := "Bearer eyJ..."

payload, err := gofortify.Revoke(&token)
if err != nil {
    // handle error
}
```

### Decode (Raw)

Decode parses and verifies a JWT string and returns its payload without any additional validation.

```go
payload, err := gofortify.Decode(tokenString)
```

## Token Payload

| Claim  | Field | Description                                      |
|--------|-------|--------------------------------------------------|
| `iss`  | ISS   | Issuer                                           |
| `iat`  | IAT   | Issued at (Unix timestamp)                       |
| `exp`  | EXP   | Expires at (Unix timestamp)                      |
| `nbf`  | NBF   | Not valid before (Unix timestamp)                |
| `jti`  | JTI   | Unique token identifier (UUID)                   |
| `sub`  | SUB   | Subject (from `Subject.GetSubjectKey()`)         |
| `iua`  | IUA   | Issued user agent                                |
| `iuc`  | IUC   | Is using cookie (enables ATV check)              |
| `type` | TYPE  | Token type: `access_token` or `refresh_token`    |
| `atv`  | ATV   | Access token verifier (bcrypt hash, access only) |

## Errors

| Error                                          | Meaning                                                    |
|------------------------------------------------|------------------------------------------------------------|
| `ErrExpiredToken`                              | Token is expired or was issued before the incident time    |
| `ErrInvalidTokenType`                          | Wrong token type used for the operation                    |
| `ErrMissingRequiredAccessTokenVerifierCookie`  | `iuc` is true but no ATV cookie was provided               |
| `ErrInvalidAccessTokenVerifier`                | ATV cookie value does not match the token's ATV claim      |
| `ErrJWTSubjectNotFound`                        | Subject could not be resolved                              |

## Security Notes

- **Incident time**: On startup, gofortify sets an incident timestamp in the blacklist. Any token issued before this time is rejected — provides a global revocation mechanism when the blacklist was unavailable.
- **ATV (Access Token Verifier)**: When `iuc` is `true`, a bcrypt-hashed verifier is embedded in the token and the raw value must be supplied via a separate `HttpOnly` cookie. This mitigates token theft from JavaScript.
- **Blacklist TTL**: Revoked token JTIs are stored with a TTL equal to the remaining token lifetime — the blacklist stays self-cleaning.
- **Asymmetric keys**: For `RS*`, `PS*`, `ES*`, `EdDSA` — `JWT_SECRET_KEY` must be a PEM-encoded private key, `JWT_PUBLIC_KEY` must be a PEM-encoded public key. Never expose the private key to other services — only share the public key.
- **Memory blacklist**: Does not persist across restarts. All revoked tokens are forgotten on app restart. Use Redis in production.

## License

MIT