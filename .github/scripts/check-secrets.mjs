import { execFileSync } from "node:child_process";
import { createReadStream } from "node:fs";
import { lstat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const patterns = [
  ["JWT", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/],
  ["bearer credential", /\bBearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}/i],
  ["credential assignment", /\b(?:access_token|refresh_token|id_token|client_secret)["']?\s*[:=]\s*["']?[A-Za-z0-9._~+/-]{20,}/i],
  ["private key", /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/],
  ["Azure shared key", /\bAccountKey\s*=\s*[A-Za-z0-9+/]{40,}={0,2}/i],
  ["signed URL", /[?&](?:amp;)?sig=[A-Za-z0-9+/_-]{30,}={0,2}/i],
];

export function secretKinds(input) {
  const texts = Buffer.isBuffer(input)
    ? [input.toString("utf8"), input.toString("utf16le")]
    : [String(input)];
  const kinds = new Set();
  for (let text of texts) {
    for (let pass = 0; pass < 3; pass += 1) {
      for (const [kind, pattern] of patterns) {
        if (pattern.test(text)) kinds.add(kind);
      }
      const decoded = text
        .replace(/%([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/\\u00([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/&#(?:x([0-9a-f]{2})|(\d{1,3}));/gi, (_, hex, decimal) =>
          String.fromCharCode(parseInt(hex ?? decimal, hex ? 16 : 10)));
      if (decoded === text) break;
      text = decoded;
    }
  }
  return [...kinds];
}

export function assertNoSecrets(input, filename) {
  const kinds = secretKinds(input);
  if (kinds.length) throw new Error(`Credential pattern in ${filename}: ${kinds.join(", ")}. Content withheld.`);
}

export async function checkRepositorySecrets(root, staged = false) {
  const args = staged
    ? ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"]
    : ["ls-files", "-z", "--cached", "--others", "--exclude-standard"];
  const names = execFileSync("git", args, {
    cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024,
  }).split("\0").filter(Boolean);
  let checked = 0;
  const findings = [];
  const excludedDirectories = [];
  for (const name of new Set(names)) {
    if (/(?:^|\/)(?:\.playwright-mcp|chrome-profile[^/]*|browser-profile[^/]*)(?:\/|$)|(?:^|\/)(?:Cookies|Login Data|Local State)$/.test(name)) {
      findings.push({ file: name, kinds: ["prohibited browser authentication artifact"] });
      continue;
    }
    if (staged) {
      const bytes = execFileSync("git", ["show", `:${name}`], { cwd: root, maxBuffer: 64 * 1024 * 1024 });
      const kinds = secretKinds(bytes);
      if (kinds.length) findings.push({ file: name, kinds });
      checked += 1;
      continue;
    }
    const filename = path.resolve(root, name);
    if (!filename.startsWith(`${root}${path.sep}`)) throw new Error("Git path escaped repository.");
    for (let parent = path.dirname(filename); parent !== root; parent = path.dirname(parent)) {
      if ((await lstat(parent)).isSymbolicLink()) throw new Error(`Linked scan ancestor: ${name}`);
    }
    let info;
    try {
      info = await lstat(filename);
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    if (info.isDirectory() && name.endsWith("/")) {
      excludedDirectories.push(name);
      continue;
    }
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`Unsupported scan entry: ${name}`);
    const kinds = new Set();
    let tail = Buffer.alloc(0);
    for await (const chunk of createReadStream(filename, { highWaterMark: 1024 * 1024 })) {
      const bytes = Buffer.concat([tail, chunk]);
      for (const kind of secretKinds(bytes)) kinds.add(kind);
      tail = bytes.subarray(Math.max(0, bytes.length - 65536));
    }
    if (kinds.size) findings.push({ file: name, kinds: [...kinds] });
    checked += 1;
  }
  return { checked, findings, excludedDirectories };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = path.resolve(process.cwd());
  const result = await checkRepositorySecrets(root, process.argv.includes("--staged"));
  console.log(JSON.stringify(result, null, 2));
  if (result.findings.length) process.exitCode = 1;
}
