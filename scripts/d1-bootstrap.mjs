import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const cwd = process.cwd();
const wranglerTomlPath = path.join(cwd, "wrangler.toml");

function fail(message) {
  console.error(message);
  process.exit(1);
}

function runWrangler(args) {
  try {
    return execFileSync("npx", ["wrangler", ...args], {
      cwd,
      stdio: ["inherit", "pipe", "pipe"],
      encoding: "utf8",
    });
  } catch (error) {
    const stdout = error?.stdout?.toString?.() ?? "";
    const stderr = error?.stderr?.toString?.() ?? "";
    if (stdout) process.stdout.write(stdout);
    if (stderr) process.stderr.write(stderr);
    throw error;
  }
}

function extractFirstDatabaseIdFromWranglerJson(jsonText) {
  const data = JSON.parse(jsonText);
  if (typeof data === "object" && data && "database_id" in data) return data.database_id;
  if (Array.isArray(data)) {
    const first = data.find((x) => x && typeof x === "object" && "database_id" in x);
    if (first) return first.database_id;
  }
  return null;
}

function updateDatabaseIdInToml(tomlText, { binding, newDatabaseId }) {
  // Minimal, safe-ish edit: only replace the first `database_id = "..."`
  // inside the [[d1_databases]] block that contains `binding = "<binding>"`.
  const blockRe = new RegExp(
    String.raw`(\[\[d1_databases\]\][\s\S]*?\bbinding\s*=\s*"${binding}"[\s\S]*?\bdatabase_id\s*=\s*")([^"]*)(")`,
    "m",
  );

  if (!blockRe.test(tomlText)) return null;
  return tomlText.replace(blockRe, `$1${newDatabaseId}$3`);
}

if (!fs.existsSync(wranglerTomlPath)) fail(`Missing wrangler.toml at ${wranglerTomlPath}`);

const tomlText = fs.readFileSync(wranglerTomlPath, "utf8");
const bindingMatch = tomlText.match(/\[\[d1_databases\]\][\s\S]*?\bbinding\s*=\s*"([^"]+)"/m);
if (!bindingMatch) fail("No [[d1_databases]] binding found in wrangler.toml");
const binding = bindingMatch[1];

const nameMatch = tomlText.match(/\bdatabase_name\s*=\s*"([^"]+)"/m);
if (!nameMatch) fail("No database_name found in wrangler.toml");
const databaseName = nameMatch[1];

const existingIdMatch = tomlText.match(/\bdatabase_id\s*=\s*"([^"]+)"/m);
const existingId = existingIdMatch?.[1] ?? "";

if (existingId && existingId !== "REPLACE_WITH_YOUR_D1_DATABASE_ID") {
  console.log(`wrangler.toml already has database_id set for ${binding}: ${existingId}`);
} else {
  console.log(`Creating D1 database: ${databaseName}`);
  const out = runWrangler(["d1", "create", databaseName, "--json"]);
  const createdId = extractFirstDatabaseIdFromWranglerJson(out);
  if (!createdId) fail("Failed to parse database_id from `wrangler d1 create --json` output");

  const updated = updateDatabaseIdInToml(tomlText, { binding, newDatabaseId: createdId });
  if (!updated) fail(`Failed to update database_id for binding "${binding}" in wrangler.toml`);

  fs.writeFileSync(wranglerTomlPath, updated, "utf8");
  console.log(`Updated wrangler.toml database_id for ${binding}: ${createdId}`);
}

console.log("Applying remote migrations…");
runWrangler(["d1", "migrations", "apply", binding]);
console.log("Done.");
