/** Fetch one immutable worker revision and run it with its frozen Bun lockfile.
 * Installation output goes to stderr: stdout belongs to the VGI Arrow protocol.
 */
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

export async function pinnedCheckout(
  repository: string,
  revision: string,
): Promise<string> {
  if (
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) ||
    !/^[0-9a-f]{40}$/.test(revision)
  ) {
    throw new Error("Expected owner/repo and a full Git commit SHA.");
  }
  const cacheRoot = join(
    process.env.XDG_CACHE_HOME || join(homedir(), ".cache"),
    "vgi-notebook-workers",
    repository,
  );
  mkdirSync(cacheRoot, { recursive: true });
  const checkout = join(cacheRoot, `${revision}-bun-${Bun.version}`);
  const ready = join(checkout, ".notebook-worker-ready");
  const lock = checkout + ".lock";
  const deadline = Date.now() + 180_000;
  let ownsLock = false;
  while (!existsSync(ready)) {
    try {
      mkdirSync(lock);
      ownsLock = true;
      break;
    } catch (error: any) {
      if (error.code !== "EEXIST") throw error;
      if (Date.now() > deadline)
        throw new Error(`Timed out waiting for worker cache lock: ${lock}`);
      await Bun.sleep(250);
    }
  }
  if (ownsLock) {
    let staging: string | undefined;
    try {
      if (!existsSync(ready)) {
        staging = mkdtempSync(join(cacheRoot, ".install-"));
        const run = (command: string, args: string[]) => {
          const result = spawnSync(command, args, {
            cwd: staging,
            stdio: ["ignore", 2, 2],
          });
          if (result.error || result.status !== 0)
            throw new Error(
              `Worker setup failed: ${command} ${args.join(" ")}`,
              { cause: result.error },
            );
        };
        run("git", ["init", "--quiet"]);
        run("git", [
          "remote",
          "add",
          "origin",
          `https://github.com/${repository}.git`,
        ]);
        run("git", ["fetch", "--quiet", "--depth", "1", "origin", revision]);
        run("git", ["checkout", "--quiet", "--detach", "FETCH_HEAD"]);
        const actual = spawnSync("git", ["rev-parse", "HEAD"], {
          cwd: staging,
          encoding: "utf8",
        });
        if (actual.status !== 0 || actual.stdout.trim() !== revision)
          throw new Error("Fetched revision did not match the pinned commit.");
        if (
          !existsSync(join(staging, "bun.lock")) &&
          !existsSync(join(staging, "bun.lockb"))
        )
          throw new Error("Pinned worker has no Bun lockfile.");
        run(process.execPath, ["install", "--frozen-lockfile"]);
        writeFileSync(
          join(staging, ".notebook-worker-ready"),
          JSON.stringify({ repository, revision, bun: Bun.version }),
        );
        renameSync(staging, checkout);
        staging = undefined;
      }
    } finally {
      if (staging) rmSync(staging, { recursive: true, force: true });
      rmSync(lock, { recursive: true, force: true });
    }
  }
  const marker = JSON.parse(readFileSync(ready, "utf8"));
  if (
    marker.repository !== repository ||
    marker.revision !== revision ||
    marker.bun !== Bun.version
  ) {
    throw new Error(`Worker cache marker does not match this pin: ${checkout}`);
  }
  return checkout;
}
