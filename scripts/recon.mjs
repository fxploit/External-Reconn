#!/usr/bin/env node
// recon-harness 실행 래퍼 — 장수 컨테이너 + docker exec 모델
//
// 세션 시작 시 한 번 `up -d` 하고, 이후 각 명령을 같은 컨테이너에 exec 로 투입한다.
// 세션 종료는 `docker compose -f docker/compose.yaml down` (Cleanup).
//
// Usage:
//   node scripts/recon.mjs python scripts/collect_web.py http://10.10.110.5/ --target 10.10.110.5
//   node scripts/recon.mjs [--target <host>] python scripts/fingerprint.py <host>
//   node scripts/recon.mjs nmap -sV -p- 10.10.110.5
//
// - 컨테이너가 떠 있지 않으면 자동으로 `docker compose up -d` 한다.
// - 실행 후 (--target 지정 시) 실행 중 컨테이너의 실제 이미지 digest 를
//   targets/<host>/captures/manifest.json 의 runtime_image_digest 에 기록한다.
//   (태그 재조회가 아니라 inspect 의 .Image = 이미지 ID sha256 사용)
// - Docker 를 쓸 수 없으면 호스트에서 직접 실행하는 폴백을 유지한다
//   (기존 `python scripts/...` 경로와 동일하게 동작).
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, "..");
const composeFile = resolve(root, "docker", "compose.yaml");
const container = "recon";

function run(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, { encoding: "utf8", ...opts });
  if (res.stdout) process.stdout.write(res.stdout);
  if (res.stderr) process.stderr.write(res.stderr);
  return res.status;
}

function dockerAvailable() {
  const res = spawnSync("docker", ["version", "--format", "{{.Server.Version}}"], { encoding: "utf8" });
  return res.status === 0;
}

function containerRunning() {
  const res = spawnSync("docker", ["inspect", container, "--format", "{{.State.Running}}"], {
    encoding: "utf8",
  });
  return res.status === 0 && res.stdout.trim() === "true";
}

function runningImageDigest() {
  // 실행 중 컨테이너가 실제 쓰는 이미지 ID(sha256) — 태그 재조회 금지 규율.
  const res = spawnSync("docker", ["inspect", container, "--format", "{{.Image}}"], {
    encoding: "utf8",
  });
  if (res.status !== 0) return null;
  const digest = res.stdout.trim();
  return /^sha256:[a-f0-9]{64}$/.test(digest) ? digest : null;
}

function recordRuntimeDigest(host) {
  const mpath = resolve(root, "targets", host, "captures", "manifest.json");
  if (!existsSync(mpath)) {
    console.error(`[recon] --target ${host} 의 manifest.json 이 없어 digest 를 기록하지 못함`);
    return;
  }
  const digest = runningImageDigest();
  if (!digest) {
    console.error("[recon] 실행 중 컨테이너의 이미지 digest 를 확인하지 못함");
    return;
  }
  const manifest = JSON.parse(readFileSync(mpath, "utf8"));
  manifest.runtime_image_digest = digest;
  writeFileSync(mpath, JSON.stringify(manifest, null, 2) + "\n");
  console.log(`[recon] runtime_image_digest=${digest} -> targets/${host}/captures/manifest.json`);
}

function main() {
  const args = process.argv.slice(2);
  let host = null;
  let cmdArgs = args;
  if (args[0] === "--target") {
    host = args[1];
    cmdArgs = args.slice(2);
  } else if (args[0] === "--") {
    cmdArgs = args.slice(1);
  }
  if (!cmdArgs.length) {
    console.error(
      "Usage: node scripts/recon.mjs [--target <host>] <command...>\n" +
        "  예: node scripts/recon.mjs --target 10.10.110.5 python scripts/collect_web.py http://10.10.110.5/ --target 10.10.110.5"
    );
    process.exit(2);
  }

  if (!dockerAvailable()) {
    // 로컬 직접 실행 폴백 — Docker 미사용 시 기존 경로와 동일하게 동작.
    console.warn("[recon] Docker 를 쓸 수 없어 호스트에서 직접 실행합니다(폴백).");
    process.exit(run(cmdArgs[0], cmdArgs.slice(1)));
  }

  if (!containerRunning()) {
    console.log("[recon] 컨테이너 미가동 — docker compose up -d");
    const up = run("docker", ["compose", "-f", composeFile, "up", "-d"]);
    if (up !== 0) {
      console.error(
        "[recon] 컨테이너 기동 실패. 이미지를 먼저 빌드하세요:\n" +
          "  docker build -t recon-harness ./docker\n" +
          "  그리고 docker/compose.yaml 의 image 를 @sha256:<digest> 로 고정"
      );
      process.exit(up);
    }
  }

  const status = run("docker", ["exec", container, ...cmdArgs]);
  if (host) recordRuntimeDigest(host);
  process.exit(status ?? 1);
}

main();
