import json
import base64
import os
import time
import uuid
from flask import Flask, jsonify, request

app = Flask(__name__)

ISSUER = "http://mock-oidc:9000"
CLIENT_ID = "ztlab-client"
CLIENT_SECRET = os.environ.get("MOCK_OIDC_CLIENT_SECRET", "ztlab-secret")

_jwk_key = os.environ.get("MOCK_OIDC_SIGNING_KEY", "zerotrustlab-mock-secret-key-32!")
JWK = {
    "kty": "oct",
    "alg": "HS256",
    "k": base64.urlsafe_b64encode(_jwk_key.encode()).decode(),
}

CONFIG = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/oauth/authorize",
    "token_endpoint": f"{ISSUER}/oauth/token",
    "userinfo_endpoint": f"{ISSUER}/userinfo",
    "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
    "response_types_supported": ["code", "id_token"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["HS256"],
}

USERINFO_STORE = {
    "admin": {
        "sub": "user-ztlab-001",
        "name": "Alice Zero-Trust",
        "preferred_username": "alice",
        "email": "alice@zerotrust.lab",
        "groups": ["engineers", "admins"],
    },
    "non-admin": {
        "sub": "user-ztlab-002",
        "name": "Bob No-Admin",
        "preferred_username": "bob",
        "email": "bob@zerotrust.lab",
        "groups": ["engineers"],
    },
}

USERINFO = USERINFO_STORE["admin"]
USERINFO_NON_ADMIN = USERINFO_STORE["non-admin"]


def b64_encode(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def make_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    body = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "jti": str(uuid.uuid4()),
        **payload,
    }
    return f"{b64_encode(header)}.{b64_encode(body)}.{b64_encode({'sig': 'mock'})}"


@app.route("/.well-known/openid-configuration")
def openid_config():
    return jsonify(CONFIG)


@app.route("/.well-known/jwks.json")
def jwks():
    return jsonify({"keys": [JWK]})


@app.route("/oauth/token", methods=["POST"])
def token():
    grant_type = request.form.get("grant_type", "authorization_code")
    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    user_type = request.form.get("user", "admin")
    userinfo = USERINFO_STORE.get(user_type, USERINFO_STORE["admin"])

    access_token = make_jwt({"sub": userinfo["sub"], "scope": "openid profile email"})
    id_token = make_jwt(
        {
            "sub": userinfo["sub"],
            "name": userinfo["name"],
            "preferred_username": userinfo["preferred_username"],
            "email": userinfo["email"],
            "groups": userinfo["groups"],
        }
    )

    return jsonify(
        {
            "access_token": access_token,
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        }
    )


@app.route("/userinfo")
def userinfo():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "invalid_token"}), 401

    token = auth[len("Bearer "):]
    parts = token.split(".")
    if len(parts) != 3:
        return jsonify({"error": "invalid_token"}), 401

    try:
        payload_b64 = parts[1]
        padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded))
        sub = decoded.get("sub", "")
    except (ValueError, json.JSONDecodeError):
        return jsonify({"error": "invalid_token"}), 401

    for u in USERINFO_STORE.values():
        if u["sub"] == sub:
            return jsonify(u)

    return jsonify(USERINFO_STORE["admin"])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
