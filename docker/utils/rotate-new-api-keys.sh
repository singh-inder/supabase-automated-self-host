#!/bin/sh
#
# Rotate opaque API keys for a self-hosted Supabase installation.
#
# Regenerates SUPABASE_PUBLISHABLE_KEY and SUPABASE_SECRET_KEY
# without touching the asymmetric key pair (JWKS) or JWT tokens.
#
# Usage:
#   sh rotate-new-api-keys.sh              # Interactive: prints keys, prompts to update .env
#   sh rotate-new-api-keys.sh --update-env # Prints keys and writes them to .env
#
# Prerequisites:
#   - .env file (run generate-keys.sh and add-new-auth-keys.sh first)
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
const crypto = require("crypto");
const fs = require("fs");

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

const envs = { SUPABASE_PUBLISHABLE_KEY: publishableKey, SUPABASE_SECRET_KEY: secretKey };

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
