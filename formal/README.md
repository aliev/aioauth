# aioauth formal models

This directory is the starting point for model-based testing `aioauth` against
small, explicit OAuth/OIDC protocol models.

## First target

The first model is intentionally narrow:

- OAuth 2.0 authorization-code exchange from RFC 6749.
- PKCE checks from RFC 7636.
- Properties that are easy to accidentally miss in example-based tests:
  redirect URI binding, one-time code consumption, expired code rejection,
  client/grant/scope checks, and verifier requirements.

## Running Quint

Install Quint:

```sh
brew install quint
# or
npm i @informalsystems/quint -g
```

Then run the simulator:

```sh
quint run formal/rfc6749/authorization_code_pkce.qnt --invariant=authorizationCodeSafety
```

Run bounded model checking:

```sh
quint verify formal/rfc6749/authorization_code_pkce.qnt --invariant=authorizationCodeSafety
```

If macOS does not find the Homebrew JDK, run:

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home \
PATH=/opt/homebrew/opt/openjdk/bin:$PATH \
quint verify formal/rfc6749/authorization_code_pkce.qnt --invariant=authorizationCodeSafety
```

Generate traces for the Python bridge:

```sh
mkdir -p formal/rfc6749/traces
quint run formal/rfc6749/authorization_code_pkce.qnt \
  --mbt \
  --n-traces=100 \
  --out-itf=formal/rfc6749/traces/auth-code.itf.json
```

Refresh-token rotation has its own RFC 6749 model:

```sh
quint run formal/rfc6749/refresh_token_rotation.qnt --invariant=refreshTokenSafety
quint verify formal/rfc6749/refresh_token_rotation.qnt --invariant=refreshTokenSafety
```

Generate refresh-token traces for the Python bridge:

```sh
mkdir -p formal/rfc6749/traces
quint run formal/rfc6749/refresh_token_rotation.qnt \
  --mbt \
  --n-traces=100 \
  --out-itf=formal/rfc6749/traces/refresh-token.itf.json
```

The Python bridge can also generate all current RFC 6749 traces:

```sh
python -m tests.formal_bridge.generate --n-traces 100
```

Replay generated traces outside pytest:

```sh
python -m tests.formal_bridge.replay
```

Run the pytest bridge modules:

```sh
pytest tests/test_formal_rfc6749_authorization_code.py
pytest tests/test_formal_rfc6749_refresh_token.py
```

The bridge also contains a deterministic scenario matrix, so it is useful even
before generated traces are produced locally.

The `Makefile` exposes the same workflow:

```sh
make formal
make formal-traces
make formal-replay
```
