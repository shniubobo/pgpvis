import { mount, shallowMount } from "@vue/test-utils";

import { Node as MockedNode } from "@mocks/pgpvis-core";
import NodeTree from "./NodeTree.vue";
import PacketsTab from "./PacketsTab.vue";

test("no nodes", () => {
  const tab = shallowMount(PacketsTab, { props: { nodes: [] } });

  expect(tab.findAllComponents(NodeTree)).toHaveLength(0);
});

test("one node", () => {
  const tab = shallowMount(PacketsTab, {
    props: { nodes: [new MockedNode("node 0")] },
  });

  expect(tab.findAllComponents(NodeTree)).toHaveLength(1);
});

test("three nodes", () => {
  const tab = mount(PacketsTab, {
    props: {
      nodes: [
        new MockedNode("node 0"),
        new MockedNode("node 1"),
        new MockedNode("node 2"),
      ],
    },
  });

  expect(tab.findAllComponents(NodeTree)).toHaveLength(3);
  // Assert correct order
  expect(tab.findAllComponents(NodeTree).at(0)!.text()).toBe("node 0");
  expect(tab.findAllComponents(NodeTree).at(1)!.text()).toBe("node 1");
  expect(tab.findAllComponents(NodeTree).at(2)!.text()).toBe("node 2");
});
