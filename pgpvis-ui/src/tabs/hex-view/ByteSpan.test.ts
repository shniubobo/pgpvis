import { mount } from "@vue/test-utils";
import { ref } from "vue";

import ByteSpan from "./ByteSpan.vue";

test("works when `selected-bytes` injection is missing", () => {
  // Should successfully mount
  mount(ByteSpan, { props: { byte: 0, offset: 0 } });
});

describe("byte hex", () => {
  describe("padding", () => {
    test("two zeroes", () => {
      const component = mount(ByteSpan, { props: { byte: 0x00, offset: 0 } });

      expect(component.text()).toBe("00");
    });

    test("one zero", () => {
      const component = mount(ByteSpan, { props: { byte: 0x09, offset: 0 } });

      expect(component.text()).toBe("09");
    });

    test("no zeroes", () => {
      const component = mount(ByteSpan, { props: { byte: 0x42, offset: 0 } });

      expect(component.text()).toBe("42");
    });
  });

  describe("overflow", () => {
    test("over 0xFF", () => {
      const component = mount(ByteSpan, { props: { byte: 0x100, offset: 0 } });

      expect(component.text()).toBe("??");
    });

    test("below 0x00", () => {
      const component = mount(ByteSpan, { props: { byte: -1, offset: 0 } });

      expect(component.text()).toBe("??");
    });
  });
});

describe("highlighting", () => {
  const HIGHLIGHTING_CLASS = "bg-blue-300/60";

  test("highlighted when in `selected-bytes`", () => {
    const component = mount(ByteSpan, {
      props: { byte: 0, offset: 1 },
      global: { provide: { "selected-bytes": ref([false, true, false]) } },
    });

    expect(component.get("span").classes()).toContain(HIGHLIGHTING_CLASS);
  });

  test("not highlighted when not in `selected-bytes`", () => {
    const component = mount(ByteSpan, {
      props: { byte: 0, offset: 1 },
      global: { provide: { "selected-bytes": ref([true, false, true]) } },
    });

    expect(component.get("span").classes()).not.toContain(HIGHLIGHTING_CLASS);
  });

  test("not highlighted for out-of-bounds access of `selected-bytes`", () => {
    const component = mount(ByteSpan, {
      props: { byte: 0, offset: 1 },
      global: { provide: { "selected-bytes": ref([]) } },
    });

    expect(component.get("span").classes()).not.toContain(HIGHLIGHTING_CLASS);
  });

  describe("updating `selected-bytes`", () => {
    test("from selected to not selected", async () => {
      const selected_bytes = ref([false, true, false]);
      const component = mount(ByteSpan, {
        props: { byte: 0, offset: 1 },
        global: { provide: { "selected-bytes": selected_bytes } },
      });

      selected_bytes.value[1] = false;
      await component.vm.$nextTick();

      expect(component.get("span").classes()).not.toContain(HIGHLIGHTING_CLASS);
    });

    test("from not selected to selected", async () => {
      const selected_bytes = ref([true, false, true]);
      const component = mount(ByteSpan, {
        props: { byte: 0, offset: 1 },
        global: { provide: { "selected-bytes": selected_bytes } },
      });

      selected_bytes.value[1] = true;
      await component.vm.$nextTick();

      expect(component.get("span").classes()).toContain(HIGHLIGHTING_CLASS);
    });
  });
});
