import { mount, type VueWrapper } from "@vue/test-utils";

import { Node } from "@mocks/pgpvis-core";
import InputTab from "./InputTab.vue";

vi.mock("pgpvis-core");

let input_tab: VueWrapper;

beforeEach(() => {
  input_tab = mount(InputTab);
});

test("with message, emit non-empty values on click", async () => {
  await input_tab.get("textarea").setValue("foo");
  await input_tab.get("button").trigger("click");

  expect(input_tab.emitted("update-hex-view")).toHaveLength(1);
  expect(input_tab.emitted("update-packets")).toHaveLength(1);
  // Values defined in `@mocks/pgpvis-core`
  expect(input_tab.emitted("update-hex-view")![0]).toStrictEqual([
    new Uint8Array(1),
  ]);
  expect(input_tab.emitted("update-packets")![0]).toStrictEqual([
    [new Node("1")],
  ]);
});

test("without message, emit empty values on click", async () => {
  await input_tab.get("button").trigger("click");

  expect(input_tab.emitted("update-hex-view")).toHaveLength(1);
  expect(input_tab.emitted("update-packets")).toHaveLength(1);
  // Values defined in `@mocks/pgpvis-core`
  expect(input_tab.emitted("update-hex-view")![0]).toStrictEqual([
    new Uint8Array(0),
  ]);
  expect(input_tab.emitted("update-packets")![0]).toStrictEqual([[]]);
});

test("first with message, and then with no message", async () => {
  await input_tab.get("textarea").setValue("foo");
  await input_tab.get("button").trigger("click");

  expect(input_tab.emitted("update-hex-view")).toHaveLength(1);
  expect(input_tab.emitted("update-packets")).toHaveLength(1);
  // Values defined in `@mocks/pgpvis-core`
  expect(input_tab.emitted("update-hex-view")![0]).toStrictEqual([
    new Uint8Array(1),
  ]);
  expect(input_tab.emitted("update-packets")![0]).toStrictEqual([
    [new Node("1")],
  ]);

  await input_tab.get("textarea").setValue("");
  await input_tab.get("button").trigger("click");

  expect(input_tab.emitted("update-hex-view")).toHaveLength(2);
  expect(input_tab.emitted("update-packets")).toHaveLength(2);
  // Values defined in `@mocks/pgpvis-core`
  expect(input_tab.emitted("update-hex-view")![1]).toStrictEqual([
    new Uint8Array(0),
  ]);
  expect(input_tab.emitted("update-packets")![1]).toStrictEqual([[]]);
});
