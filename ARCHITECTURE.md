# WebScrapeHelper architecture

The application is split into clear HTTP, service, and browser layers.

```text
Browser UI
  |
  +-- static/js/api-client.js       <- single HTTP client
  +-- static/js/main.js             <- shared page/UI behavior
  +-- static/js/ecdsa_analyzer.js   <- ECDSA page controller
  |
  v
Flask application
  |
  +-- webapp/__init__.py             <- app factory, middleware, errors
  +-- webapp/config.py               <- centralized configuration
  +-- webapp/routes/pages.py         <- HTML routes only
  +-- webapp/routes/api.py           <- JSON routes + validation only
  +-- webapp/routes/legacy.py        <- temporary compatibility aliases
  |
  v
Application services
  |
  +-- webapp/services/bitcoin.py     <- analysis/calculation logic
  +-- btc_analyzer.py                 <- existing Bitcoin analysis engine
  +-- address_analyzer.py             <- existing address analysis engine
```

## Rules

1. **Routes do HTTP only.** Parse/validate input, call a service, return JSON/HTML.
2. **Services do business logic.** They must not import Flask request/response objects.
3. **Frontend network calls go through `api-client.js`.** UI code should not duplicate fetch configuration.
4. **Templates use blueprint-qualified `url_for()` names.**
5. **API errors use HTTP status codes.** Upstream network failures return `502`; invalid input returns `400`; unexpected failures return `500`.
6. **No secrets are logged.** Private-key recovery values should never be written to application logs.
7. **ECDSA malleability is analysis, not key recovery.** `(r, s)` and `(r, n-s)` are alternate encodings of a signature; malleability alone does not reveal the private key.
8. `app.py` remains a compatibility shim so existing WSGI imports (`from app import app`) continue to work.

## Endpoints

### Pages

- `GET /`
- `GET /transaction`
- `GET /address`
- `GET /ecdsa-analysis`
- `GET /standalone-calculator`
- `GET /download-calculator`

### API

- `GET /api/health`
- `GET /api/addresses/known`
- `POST /api/analyze/transaction`
- `POST /api/analyze/address`
- `POST /api/analyze/ecdsa`
- `POST /api/calculate/nonce`
- `POST /api/calculate/nonce-from-private-key`
- `POST /api/recover/low-s-with-nonce`
- `POST /api/recover/malleability-signatures`
- `GET /api/auto-scan`
- `GET /api/monitor-mempool`

Legacy `POST /api/analyze_transaction` remains available for older browser code and can be removed after all clients migrate.
