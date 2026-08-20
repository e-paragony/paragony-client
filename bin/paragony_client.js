#!/usr/bin/env node
import { run } from "../src/cli.js";

run(process.argv.slice(2)).catch((e) => {
  process.stderr.write(`${e?.stack || e}\n`);
  process.exitCode = 1;
});
