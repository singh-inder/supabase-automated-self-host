#!/bin/sh
#
# Add asymmetric key pair and opaque API keys to a self-hosted Supabase installation.
#
# Reads JWT_SECRET from .env and generates:
#   - EC P-256 key pair (JWT_KEYS, JWT_JWKS)
#   - Opaque API keys (SUPABASE_PUBLISHABLE_KEY, SUPABASE_SECRET_KEY)
#   - Internal: ES256 JWT API keys (ANON_KEY_ASYMMETRIC, SERVICE_ROLE_KEY_ASYMMETRIC)
#
# Usage:
#   sh add-new-auth-keys.sh              # Interactive: prints keys, prompts to update .env
#   sh add-new-auth-keys.sh --update-env # Prints keys and writes them to .env
#
# Prerequisites:
#   - .env file with JWT_SECRET set (if its a new instance, run setup.sh first)
#

set -e

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker is required but not found."
  exit 1
fi

if [ ! -f .env ]; then
  echo "Error: .env file not found. Run setup.sh first."
  exit 1
fi

tty="-it"
update_env=false

if [ "$1" = "--update-env" ]; then
  update_env=true
  tty=""
elif [ ! -t 0 ]; then
  tty=""
fi

docker run --rm -e UPDATE_ENV_FILE="$update_env" -v ./:/app --workdir=/app $tty node:24-alpine node --env-file=.env -e "$(
  cat <<-'EOF'
console.log("\n------------------------------------------\n")
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  console.error("Error: JWT_SECRET not found in .env");
  process.exit(1);
}
const crypto = require("node:crypto");
const fs = require("node:fs");

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwkPrivate = privateKey.export({ format: "jwk" });
const jwkPublic = publicKey.export({ format: "jwk" });
const kid = crypto.randomUUID();

// Symmetric key as JWK (base64url-encoded)
const octKey = {
  kty: "oct",
  k: Buffer.from(jwtSecret).toString("base64url"),
  alg: "HS256"
};

// JWKS with private key (for Auth to sign tokens)
const jwksKeypair = {
  keys: [
    { ...jwkPrivate, kid, use: "sig", key_ops: ["sign", "verify"], alg: "ES256", ext: true },
    octKey
  ]
};

// JWKS with public key only (for PostgREST, Realtime, Storage to verify)
const jwksPublic = {
  keys: [
    { ...jwkPublic, kid, use: "sig", key_ops: ["verify"], alg: "ES256", ext: true },
    octKey
  ]
};

// Sign ES256 JWT
function signES256(payload) {
  const header = { alg: "ES256", typ: "JWT", kid };
  const b64Header = Buffer.from(JSON.stringify(header)).toString("base64url");
  const b64Payload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const data = b64Header + "." + b64Payload;
  const sig = crypto
    .sign("SHA256", Buffer.from(data), {
      key: privateKey,
      dsaEncoding: "ieee-p1363"
    })
    .toString("base64url");
  return data + "." + sig;
}

const iat = Math.floor(Date.now() / 1000);
const exp = iat + 3600 * 24 * 365 * 5; // 5 years

const anonJwt = signES256({ role: "anon", iss: "supabase", iat, exp });
const serviceJwt = signES256({ role: "service_role", iss: "supabase", iat, exp });

// Generate opaque API keys with checksum
const PROJECT_REF = "supabase-self-hosted";

function generateOpaqueKey(prefix) {
  const random = crypto.randomBytes(17).toString("base64url").slice(0, 22);
  const intermediate = prefix + random;
  const checksum = crypto
    .createHash("sha256")
    .update(PROJECT_REF + "|" + intermediate)
    .digest("base64url")
    .slice(0, 8);
  return intermediate + "_" + checksum;
}

const publishableKey = generateOpaqueKey("sb_publishable_");
const secretKey = generateOpaqueKey("sb_secret_");

const envs = {
  SUPABASE_PUBLISHABLE_KEY: publishableKey,
  SUPABASE_SECRET_KEY: secretKey,
  ANON_KEY_ASYMMETRIC: anonJwt,
  SERVICE_ROLE_KEY_ASYMMETRIC: serviceJwt,
  JWT_KEYS: JSON.stringify(jwksKeypair.keys),
  JWT_JWKS: JSON.stringify(jwksPublic)
};

for (const key in envs) {
  if (!Object.hasOwn(envs, key)) continue;
  console.log(`${key}=${envs[key]}`);
}

function updateFile() {
  console.log("Updating env file");
  fs.cpSync(".env", ".env.old");

  let content = fs.readFileSync(".env", { encoding: "utf-8" });
  for (const key in envs) {
    if (!Object.hasOwn(envs, key)) continue;
    const regex = new RegExp(`^${key}=.*$`, "m");
    const pair = `${key}=${envs[key]}`;
    if (regex.test(content)) {
      content = content.replace(regex, pair);
    } else {
      content += `\n${pair}`;
    }
  }
  fs.writeFileSync(".env", content, { encoding: "utf-8" });
};

if (process.env.UPDATE_ENV_FILE === "true") {
  updateFile();
} else if (process.stdin.isTTY) {
  const { createInterface } = require("readline/promises");
  const readline = createInterface({ input: process.stdin, output: process.stdout });
  readline
    .question("Update env file? (y/n): ")
    .then(reply => (reply.toLowerCase() === "y" ? updateFile() : undefined))
    .catch(err => console.error("Error:", err.message))
    .finally(() => readline.close());
}
EOF
)"
