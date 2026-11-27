import assert from "node:assert/strict";
import { test } from "node:test";

import { clipCodePoints, codePointLength } from "../src/text.ts";

test("lengths count code points, not UTF-16 units", () => {
  assert.equal(codePointLength(""), 0);
  assert.equal(codePointLength("Savory Air"), 10);
  assert.equal(codePointLength("Tomás"), 5);
  // An astral character is two UTF-16 units and one code point.
  assert.equal("🍜".length, 2);
  assert.equal(codePointLength("🍜"), 1);
  assert.equal(codePointLength("a🍜b"), 3);
});

test("clipping never splits a surrogate pair", () => {
  assert.equal(clipCodePoints("a🍜b", 2), "a🍜");
  assert.equal(clipCodePoints("a🍜b", 1), "a");
  assert.equal(clipCodePoints("short", 10), "short");
  assert.equal(clipCodePoints("anything", 0), "");
  assert.throws(() => clipCodePoints("x", -1), RangeError);
  assert.throws(() => clipCodePoints("x", 1.5), RangeError);
});
