import { expect, test } from "bun:test";
import fs from "node:fs";
import { canonical, readSetChanges } from "./generate-conformance.mjs";

const pins = JSON.parse(fs.readFileSync(new URL("./conformance/protocol-pins.json", import.meta.url), "utf8"));

test("candidate inspection does not treat provenance and unrelated schema growth as a read-set change", () => {
	const candidate = { ...pins, pin: "0.999.0", schemaDigest: "different", counts: { clientMethods: 999 } };
	expect(readSetChanges(pins, candidate)).toEqual([]);
});

test("loss, addition, and changed meaning of a pinned field require review", () => {
	for (const key of ["requiredClientMethods", "threadStartSandboxIsMode", "hookEventNames"]) {
		const candidate = { ...pins };
		delete candidate[key];
		expect(readSetChanges(pins, candidate)).toEqual([key]);
	}
	expect(readSetChanges(pins, { ...pins, hookEventNames: [...pins.hookEventNames, "NewHook"] })).toEqual(["hookEventNames"]);
});

test("the maintenance read-set is exactly the runtime carry read-set", () => {
	const rust = fs.readFileSync(new URL("../../crates/ciao-host/src/codex_carry.rs", import.meta.url), "utf8");
	const names = [...rust.matchAll(/diff!\([^,]+, "([^"]+)"\)/g)].map(m => m[1]).sort();
	expect(names.length).toBeGreaterThan(10);
	expect(readSetChanges(pins, {})).toEqual(names);
});

test("canonicalization is stable and retains array semantics", () => {
	expect(canonical({ b: 1, a: [2, 1] })).toBe('{"a":[2,1],"b":1}');
});
