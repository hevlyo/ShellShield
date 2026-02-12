#!/usr/bin/env bun
import { main } from "./cli";

try {
  await main();
} catch (err) {
  if (process.env.DEBUG) {
    console.error(err);
  }
  process.exit(0);
}
