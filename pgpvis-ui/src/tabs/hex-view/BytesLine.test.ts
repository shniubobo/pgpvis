import { mount } from "@vue/test-utils";

import BytesLine from "./BytesLine.vue";
import ByteSpan from "./ByteSpan.vue";

test("no bytes", () => {
  const component = mount(BytesLine, { props: { bytes: [], offset: 0 } });

  expect(component.findAllComponents(ByteSpan)).toHaveLength(0);
});

test("one byte", () => {
  const component = mount(BytesLine, { props: { bytes: [0], offset: 0 } });

  expect(component.findAllComponents(ByteSpan)).toHaveLength(1);
  expect(component.getComponent(ByteSpan).props().byte).toBe(0);
  expect(component.getComponent(ByteSpan).props().offset).toBe(0);
});

test("three bytes", () => {
  const component = mount(BytesLine, {
    props: { bytes: [1, 2, 3], offset: 1 },
  });

  const bytes = component.findAllComponents(ByteSpan);
  expect(bytes).toHaveLength(3);
  expect(bytes[0].props().byte).toBe(1);
  expect(bytes[0].props().offset).toBe(1);
  expect(bytes[1].props().byte).toBe(2);
  expect(bytes[1].props().offset).toBe(2);
  expect(bytes[2].props().byte).toBe(3);
  expect(bytes[2].props().offset).toBe(3);
});
