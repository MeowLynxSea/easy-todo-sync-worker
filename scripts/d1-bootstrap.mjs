import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const cwd = process.cwd();
const wranglerTomlPath = path.join(cwd, "wrangler.toml");

function fail(message) {
  console.error(message);
  process.exit(1);
}

function runWrangler(args) {
  const res = spawnSync("npx", ["wrangler", ...args], {
    cwd,
    stdio: ["inherit", "pipe", "pipe"],
    encoding: "utf8",
  });

  const stdout = res.stdout?.toString?.() ?? "";
  const stderr = res.stderr?.toString?.() ?? "";

  if (res.status !== 0) {
    if (stdout) process.stdout.write(stdout);
    if (stderr) process.stderr.write(stderr);
    fail(`wrangler failed (${res.status}): npx wrangler ${args.join(" ")}`);
  }

  return { stdout, stderr, output: `${stdout}${stderr}` };
}

function extractDatabaseIdFromWranglerCreateOutput(text) {
  const tomlStyle = text.match(/\bdatabase_id\s*=\s*"(.*?)"/i);
  if (tomlStyle?.[1]) return tomlStyle[1].trim();

  const uuid = text.match(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i);
  if (uuid?.[0]) return uuid[0];

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
  const res = runWrangler(["d1", "create", databaseName]);
  const createdId = extractDatabaseIdFromWranglerCreateOutput(res.output);
  if (!createdId) {
    if (res.output) process.stdout.write(res.output);
    fail("Failed to parse database_id from `wrangler d1 create` output");
  }

  const updated = updateDatabaseIdInToml(tomlText, { binding, newDatabaseId: createdId });
  if (!updated) fail(`Failed to update database_id for binding "${binding}" in wrangler.toml`);

  fs.writeFileSync(wranglerTomlPath, updated, "utf8");
  console.log(`Updated wrangler.toml database_id for ${binding}: ${createdId}`);
}

console.log("Applying remote migrations…");
runWrangler(["d1", "migrations", "apply", binding, "--remote"]);
console.log("Done.");
