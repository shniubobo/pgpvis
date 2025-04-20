import { mount, shallowMount, VueWrapper } from "@vue/test-utils";
import { useEventBus, type UseEventBusReturn } from "@vueuse/core";
import type { Ref } from "vue";

import BytesLine from "./BytesLine.vue";
import HexViewTab from "./HexViewTab.vue";

const LINE_HEIGHT = 24; // TODO: Do not hard-code this.

// https://github.com/TanStack/virtual/issues/29
// @ts-expect-error Mocking, type is not important
window.Element.prototype.getBoundingClientRect = () => {
  return { height: LINE_HEIGHT, width: 100 /* A random number */ };
};

// https://gist.github.com/Joandres-Lara/dbc80391d31aba7daf69b2caa23ef535#file-virtuallist-test-js-L125
// (as seen in the issue linked above)
async function render_lines(component: VueWrapper, lines_n: number = 10) {
  await component.trigger("scroll", { scrollTop: LINE_HEIGHT * lines_n });
}

// https://github.com/vuejs/test-utils/issues/713#issuecomment-1008743095
function inject<T>(key: string, component: VueWrapper): T {
  // @ts-expect-error Accessing private member
  return component.vm.$.provides[key];
}

// These could break if we allow customizing bytes per line in the future.
// TODO: Remove hard-coded number of bytes.
describe("bytes correctly seperated into lines", () => {
  test("less than one line", async () => {
    const component = mount(HexViewTab, {
      props: { bytes: new Uint8Array(3).map((offset, idx) => offset + idx) },
    });

    await render_lines(component);

    expect(component.findAllComponents(BytesLine)).toHaveLength(1);
    expect(component.getComponent(BytesLine).props().bytes).toStrictEqual([
      0, 1, 2,
    ]);
  });

  test("exactly one line", async () => {
    const component = mount(HexViewTab, {
      props: { bytes: new Uint8Array(16).map((offset, idx) => offset + idx) },
    });

    await render_lines(component);

    expect(component.findAllComponents(BytesLine)).toHaveLength(1);
    expect(component.getComponent(BytesLine).props().bytes).toStrictEqual([
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ]);
  });

  test("one complete and one incomplete line", async () => {
    const component = mount(HexViewTab, {
      props: { bytes: new Uint8Array(19).map((offset, idx) => offset + idx) },
    });

    await render_lines(component);

    const lines = component.findAllComponents(BytesLine);
    expect(lines).toHaveLength(2);
    expect(lines[0].props().bytes).toStrictEqual([
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ]);
    expect(lines[1].props().bytes).toStrictEqual([16, 17, 18]);
  });
});

describe("updating", () => {
  describe("bytes", () => {
    describe("lines are updated", () => {
      test("more", async () => {
        const component = mount(HexViewTab, {
          props: {
            bytes: new Uint8Array(16).map((offset, idx) => offset + idx),
          },
        });
        await render_lines(component);

        component.setProps({
          bytes: new Uint8Array(17).map((offset, idx) => offset + idx),
        });
        await render_lines(component);

        expect(component.findAllComponents(BytesLine)).toHaveLength(2);
      });

      test("less", async () => {
        const component = mount(HexViewTab, {
          props: {
            bytes: new Uint8Array(17).map((offset, idx) => offset + idx),
          },
        });
        await render_lines(component);

        component.setProps({
          bytes: new Uint8Array(16).map((offset, idx) => offset + idx),
        });
        await render_lines(component);

        expect(component.findAllComponents(BytesLine)).toHaveLength(1);
      });

      test("unchanged number", async () => {
        const component = mount(HexViewTab, {
          props: {
            bytes: new Uint8Array(16).map((offset, idx) => offset + idx),
          },
        });
        await render_lines(component);

        component.setProps({
          // Increase every byte by 1
          bytes: new Uint8Array(16).fill(1).map((offset, idx) => offset + idx),
        });
        await render_lines(component);

        expect(component.findAllComponents(BytesLine)).toHaveLength(1);
      });
    });

    test("`selected-bytes` is re-initialized", async () => {
      const component = shallowMount(HexViewTab, {
        props: {
          bytes: new Uint8Array(16).map((offset, idx) => offset + idx),
        },
      });
      const selected_bytes: Ref<boolean[]> = inject(
        "selected-bytes",
        component,
      );

      const bus = useEventBus<{ offset: number; length: number }>(
        "span-selected",
      );
      bus.emit({ offset: 0, length: 1 });

      // Assert the state, before `selected-bytes` is re-initialized, that all
      // but the first value is `false`.
      const expected = [true].concat(Array(15).fill(false));
      expect(selected_bytes.value).toStrictEqual(expected);

      await component.setProps({
        // Increase every byte by 1
        bytes: new Uint8Array(16).fill(1).map((offset, idx) => offset + idx),
      });

      expect(selected_bytes.value).toStrictEqual(Array(16).fill(false));
    });
  });

  describe("`span-selected` event bus", () => {
    let component: VueWrapper;
    let selected_bytes: Ref<boolean[]>;
    let bus: UseEventBusReturn<{ offset: number; length: number }, undefined>;

    beforeEach(() => {
      component = shallowMount(HexViewTab, {
        props: {
          bytes: new Uint8Array(16).map((offset, idx) => offset + idx),
        },
      });
      selected_bytes = inject("selected-bytes", component);
      bus = useEventBus<{ offset: number; length: number }>("span-selected");

      bus.emit({ offset: 0, length: 3 });

      // Assert the state, before emitting `span-selected` again, that all but
      // the first three values are `false`.
      const expected = Array(3).fill(true).concat(Array(13).fill(false));
      expect(selected_bytes.value).toStrictEqual(expected);
    });

    describe("overlapping old and new selections", () => {
      test("old is the same as new", () => {
        bus.emit({ offset: 0, length: 3 });

        const expected = Array(3).fill(true).concat(Array(13).fill(false));
        expect(selected_bytes.value).toStrictEqual(expected);
      });

      test("old is superset of new", () => {
        bus.emit({ offset: 0, length: 2 });

        const expected = Array(2).fill(true).concat(Array(14).fill(false));
        expect(selected_bytes.value).toStrictEqual(expected);
      });

      test("old is subset of new", () => {
        bus.emit({ offset: 0, length: 5 });

        const expected = Array(5).fill(true).concat(Array(11).fill(false));
        expect(selected_bytes.value).toStrictEqual(expected);
      });
    });

    test("non-overlapping old and new selections", () => {
      bus.emit({ offset: 3, length: 3 });

      const expected = Array(3)
        .fill(false)
        .concat(Array(3).fill(true))
        .concat(Array(10).fill(false));
      expect(selected_bytes.value).toStrictEqual(expected);
    });
  });
});
