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

    test("emit 'span-selected' on clicking", async ({ span_selected }) => {
      await component.get("span").trigger("click");

      expect(span_selected).toHaveBeenCalledOnce();
      // Not sure why there is the `undefined`
      expect(span_selected).toHaveBeenCalledWith(
        { offset: 0, length: 1 },
        undefined,
      );
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

    test("emit no 'span-selected' on clicking", () => {
      const bus = useEventBus<{ offset: number; length: number }>(
        "span-selected",
      );
      const mock = vi.fn(() => {});
      bus.on(mock);

      component.get("span").trigger("click");

      expect(mock).not.toHaveBeenCalled();
    });
  });

  describe("updating text and span info", () => {
    test("adding span", async ({ span_selected }) => {
      const component = shallowMount(NodeTree, {
        props: { node: new MockedNode("foo"), depth: 0 },
      });
      await component.setProps({ node: new MockedNode("foo", [], 0, 1) });
      component.get("span").trigger("click");

      expect(component.get("span").classes()).toContain("cursor-pointer");
      expect(span_selected).toHaveBeenCalledOnce();
      expect(span_selected).toHaveBeenCalledWith(
        { offset: 0, length: 1 },
        undefined,
      );
    });

    test("changing both", async ({ span_selected }) => {
      const component = shallowMount(NodeTree, {
        props: { node: new MockedNode("foo", [], 0, 1), depth: 0 },
      });
      await component.setProps({ node: new MockedNode("bar", [], 2, 3) });
      component.get("span").trigger("click");

      expect(component.get("span").text()).toBe("bar");
      expect(component.get("span").classes()).toContain("cursor-pointer");
      expect(span_selected).toHaveBeenCalledOnce();
      expect(span_selected).toHaveBeenCalledWith(
        { offset: 2, length: 3 },
        undefined,
      );
    });

    test("removing span", async ({ span_selected }) => {
      const component = shallowMount(NodeTree, {
        props: { node: new MockedNode("foo", [], 0, 1), depth: 0 },
      });
      await component.setProps({ node: new MockedNode("foo") });
      component.get("span").trigger("click");

      expect(component.get("span").classes()).not.toContain("cursor-pointer");
      expect(span_selected).not.toHaveBeenCalled();
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
});
