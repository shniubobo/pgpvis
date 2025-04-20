import { mount, shallowMount, VueWrapper } from "@vue/test-utils";
import { useEventBus } from "@vueuse/core";
import { test as base_test, type Mock } from "vitest";

// Turns out that we don't even need `vi.mock` when using this.
import { Node as MockedNode } from "@mocks/pgpvis-core";
import NodeTree from "./NodeTree.vue";

interface Fixtures {
  span_selected: Mock<() => void>;
}

const test = base_test.extend<Fixtures>({
  // eslint-disable-next-line no-empty-pattern
  span_selected: async ({}, use) => {
    const bus = useEventBus<{ offset: number; length: number }>(
      "span-selected",
    );
    const mock = vi.fn(() => {});
    bus.on(mock);
    await use(mock);
  },
});

describe("leaf node", () => {
  test("text is displayed", () => {
    const component = shallowMount(NodeTree, {
      props: { node: new MockedNode("foo"), depth: 0 },
    });

    expect(component.findAll("span")).toHaveLength(1);
    expect(component.get("span").text()).toBe("foo");
  });

  describe("with span info", () => {
    let component: VueWrapper;

    beforeEach(() => {
      component = shallowMount(NodeTree, {
        props: { node: new MockedNode("foo", [], 0, 1), depth: 0 },
      });
    });

    test("has `cursor-pointer`", () => {
      expect(component.get("span").classes()).toContain("cursor-pointer");
    });

    describe("on clicking", () => {
      test("emit 'span-selected'", async ({ span_selected }) => {
        await component.get("span").trigger("click");

        expect(span_selected).toHaveBeenCalledOnce();
        // Not sure why there is the `undefined`
        expect(span_selected).toHaveBeenCalledWith(
          { offset: 0, length: 1 },
          undefined,
        );
      });

      test("gain `underline`", async () => {
        expect(component.get("span").classes()).not.toContain("underline");
        await component.get("span").trigger("click");
        expect(component.get("span").classes()).toContain("underline");
      });
    });
  });

  describe("without span info", () => {
    let component: VueWrapper;

    beforeEach(() => {
      component = shallowMount(NodeTree, {
        props: { node: new MockedNode("foo"), depth: 0 },
      });
    });

    test("has no `cursor-pointer`", () => {
      expect(component.get("span").classes()).not.toContain("cursor-pointer");
    });

    describe("on clicking", () => {
      test("emit no 'span-selected'", ({ span_selected }) => {
        component.get("span").trigger("click");

        expect(span_selected).not.toHaveBeenCalled();
      });

      test("gain no `underline`", async () => {
        expect(component.get("span").classes()).not.toContain("underline");
        await component.get("span").trigger("click");
        expect(component.get("span").classes()).not.toContain("underline");
      });
    });
  });

  describe("updating text and span info", () => {
    test("adding span", async ({ span_selected }) => {
      const component = shallowMount(NodeTree, {
        props: { node: new MockedNode("foo"), depth: 0 },
      });
      await component.setProps({ node: new MockedNode("foo", [], 0, 1) });
      await component.get("span").trigger("click");

      expect(component.get("span").classes()).toContain("cursor-pointer");
      expect(span_selected).toHaveBeenCalledOnce();
      expect(span_selected).toHaveBeenCalledWith(
        { offset: 0, length: 1 },
        undefined,
      );
      expect(component.get("span").classes()).toContain("underline");
    });

    test("changing both", async ({ span_selected }) => {
      const component = shallowMount(NodeTree, {
        props: { node: new MockedNode("foo", [], 0, 1), depth: 0 },
      });
      await component.setProps({ node: new MockedNode("bar", [], 2, 3) });
      await component.get("span").trigger("click");

      expect(component.get("span").text()).toBe("bar");
      expect(component.get("span").classes()).toContain("cursor-pointer");
      expect(span_selected).toHaveBeenCalledOnce();
      expect(span_selected).toHaveBeenCalledWith(
        { offset: 2, length: 3 },
        undefined,
      );
      expect(component.get("span").classes()).toContain("underline");
    });

    test("removing span", async ({ span_selected }) => {
      const component = shallowMount(NodeTree, {
        props: { node: new MockedNode("foo", [], 0, 1), depth: 0 },
      });
      await component.setProps({ node: new MockedNode("foo") });
      await component.get("span").trigger("click");

      expect(component.get("span").classes()).not.toContain("cursor-pointer");
      expect(span_selected).not.toHaveBeenCalled();
      expect(component.get("span").classes()).not.toContain("underline");
    });

    describe("`selected` removed", () => {
      test("changing span", async () => {
        const component = shallowMount(NodeTree, {
          props: { node: new MockedNode("foo", [], 0, 1), depth: 0 },
        });
        await component.get("span").trigger("click");
        expect(component.get("span").classes()).toContain("underline");

        await component.setProps({ node: new MockedNode("foo", [], 2, 3) });
        expect(component.get("span").classes()).not.toContain("underline");
      });

      test("removing span", async () => {
        const component = shallowMount(NodeTree, {
          props: { node: new MockedNode("foo", [], 0, 1), depth: 0 },
        });
        await component.get("span").trigger("click");
        expect(component.get("span").classes()).toContain("underline");

        await component.setProps({ node: new MockedNode("foo") });
        expect(component.get("span").classes()).not.toContain("underline");
      });
    });
  });
});

describe("children", () => {
  let parent: VueWrapper;
  let children: VueWrapper[];

  beforeEach(() => {
    parent = mount(NodeTree, {
      props: {
        node: new MockedNode(
          "parent",
          [
            new MockedNode("children 0"),
            new MockedNode("children 1", [], 0, 1),
          ],
          2,
          3,
        ),
        depth: 0,
      },
    });
    children = parent.findAllComponents(NodeTree);
  });

  test("text is displayed", () => {
    expect(parent.findAll("span")).toHaveLength(3);
    expect(parent.get(":scope > span").text()).toBe("parent");

    expect(children).toHaveLength(2);
    expect(children[0].get("span").text()).toBe("children 0");
    expect(children[1].get("span").text()).toBe("children 1");
  });

  test("ident guides", () => {
    const outer_classes = ["bg-gray-200", "pl-px"];
    const inner_classes = ["bg-white", "pl-[calc(2ch-1px)]"];

    outer_classes.map((c) => expect(parent.classes()).not.toContain(c));
    inner_classes.map((c) =>
      expect(parent.get(":scope > div").classes()).not.toContain(c),
    );

    outer_classes.map((c) => expect(children[0].classes()).toContain(c));
    inner_classes.map((c) =>
      expect(children[0].get(":scope > div").classes()).toContain(c),
    );
    outer_classes.map((c) => expect(children[1].classes()).toContain(c));
    inner_classes.map((c) =>
      expect(children[1].get(":scope > div").classes()).toContain(c),
    );
  });

  test("`cursor-pointer` on correct nodes", () => {
    expect(parent.get(":scope > span").classes()).toContain("cursor-pointer");
    expect(children[0].get("span").classes()).not.toContain("cursor-pointer");
    expect(children[1].get("span").classes()).toContain("cursor-pointer");
  });

  test("'span-selected' emitted from correct nodes", async ({
    span_selected,
  }) => {
    await parent.get(":scope > span").trigger("click");
    expect(span_selected).toHaveBeenCalledOnce();
    expect(span_selected).toHaveBeenCalledWith(
      { offset: 2, length: 3 },
      undefined,
    );

    await children[0].get("span").trigger("click");
    // Has not increased since the last call
    expect(span_selected).toHaveBeenCalledOnce();

    await children[1].get("span").trigger("click");
    expect(span_selected).toHaveBeenCalledTimes(2);
    expect(span_selected).toHaveBeenLastCalledWith(
      { offset: 0, length: 1 },
      undefined,
    );
  });

  test("`underline` gained by correct nodes", async () => {
    await parent.get(":scope > span").trigger("click");
    expect(parent.get(":scope > span").classes()).toContain("underline");
    expect(children[0].get("span").classes()).not.toContain("underline");
    expect(children[1].get("span").classes()).not.toContain("underline");

    await children[0].get("span").trigger("click");
    // `underline` on parent not removed, and no new `underline` gained
    expect(parent.get(":scope > span").classes()).toContain("underline");
    expect(children[0].get("span").classes()).not.toContain("underline");
    expect(children[1].get("span").classes()).not.toContain("underline");

    await children[1].get("span").trigger("click");
    expect(parent.get(":scope > span").classes()).not.toContain("underline");
    expect(children[0].get("span").classes()).not.toContain("underline");
    expect(children[1].get("span").classes()).toContain("underline");
  });
});
