<script setup lang="ts">
import { Tree, type TreeExpandedKeys } from "primevue";
import type { TreeNode } from "primevue/treenode";
import { computed, ref, watch } from "vue";

import {
  PublicKeyAlgorithmId,
  TypeId,
  type PacketSequence,
  type PublicKey,
  type PublicSubkey,
  type RsaEncryptSign,
  type UserId,
} from "pgpvis-core";

const props = defineProps<{ packets: PacketSequence }>();

const expanded_keys = ref<TreeExpandedKeys>({});

const packet_nodes = computed(() => {
  const packet_nodes: TreeNode[] = [];
  for (const [idx, packet] of props.packets.entries()) {
    if (packet.inner === undefined) {
      continue;
    }

    const format = packet.inner.header.inner.format;
    const type_id = packet.inner.header.inner.ctb.inner.type_id;
    const any_length = packet.inner.header.inner.length.inner;
    const length =
      any_length.encoding == "Full" || any_length.encoding == "Partial"
        ? `${any_length.length.toString()} (${any_length.encoding})`
        : "Indeterminate";
    const header_node: TreeNode = {
      key: `${idx}-0`,
      label: "Header",
      children: [
        {
          key: `${idx}-0-0`,
          label: "CTB",
          children: [
            {
              key: `${idx}-0-0-0`,
              label: `Format: ${format}`,
            },
            {
              key: `${idx}-0-0-1`,
              label: `Type ID: ${type_id}`,
            },
          ],
        },
        {
          key: `${idx}-0-1`,
          label: `Length: ${length}`,
        },
      ],
    };

    if (type_id === TypeId.PublicKey || type_id === TypeId.PublicSubkey) {
      const public_key = packet.inner.body.inner as PublicKey | PublicSubkey;
      const key_role = type_id === TypeId.PublicKey ? "Key" : "Subkey";
      const creation_time = public_key.creation_time.inner;
      // Creation time is stored as seconds as per RFC 9580, but here we need
      // milliseconds.
      const creation_time_iso = new Date(creation_time * 1000).toISOString();
      const algorithm = PublicKeyAlgorithmId[public_key.algorithm.inner];
      const key_material = public_key.key_material.inner;

      let key_material_nodes: TreeNode[] = [];
      if (public_key.algorithm.inner === PublicKeyAlgorithmId.RsaEncryptSign) {
        const n_length = (key_material as RsaEncryptSign).n.inner.length.inner;
        const e_length = (key_material as RsaEncryptSign).e.inner.length.inner;
        key_material_nodes = [
          {
            key: `${idx}-1-3-0`,
            label: "n",
            children: [
              {
                key: `${idx}-1-3-0-0`,
                label: `Length: ${n_length}`,
              },
              {
                key: `${idx}-1-3-0-1`,
                label: `Integers: [${n_length} octets]`,
              },
            ],
          },
          {
            key: `${idx}-1-3-1`,
            label: `e`,
            children: [
              {
                key: `${idx}-1-3-1-0`,
                label: `Length: ${e_length}`,
              },
              {
                key: `${idx}-1-3-1-1`,
                label: `Integers: [${e_length} octets]`,
              },
            ],
          },
        ];
      }

      const body_node: TreeNode = {
        key: `${idx}-1`,
        label: "Body",
        children: [
          {
            key: `${idx}-1-0`,
            label: `Version: ${public_key.version.inner}`,
          },
          {
            key: `${idx}-1-1`,
            label: `Creation Time: ${creation_time_iso} (${creation_time})`,
          },
          {
            key: `${idx}-1-2`,
            label: `Algorithm: ${algorithm}`,
          },
          {
            key: `${idx}-1-3`,
            label: "Key Material",
            children: key_material_nodes,
          },
        ],
      };

      packet_nodes.push({
        key: `${idx}`,
        label: `Public ${key_role} (${type_id}): ${public_key.key_id} (${algorithm})`,
        children: [header_node, body_node],
      });
    } else if (type_id === TypeId.UserId) {
      const user_id = packet.inner.body.inner as UserId;

      const body_node: TreeNode = {
        key: `${idx}-1`,
        label: "Body",
        children: [
          {
            key: `${idx}-1-0`,
            label: `User ID: ${user_id.user_id.inner}`,
          },
        ],
      };

      packet_nodes.push({
        key: `${idx}`,
        label: `User ID (${type_id}): ${user_id.user_id.inner}`,
        children: [header_node, body_node],
      });
    }
  }
  return packet_nodes;
});

watch(packet_nodes, expand_all_nodes);

function expand_all_nodes() {
  for (const node of packet_nodes.value) {
    expand_node(node);
  }
}

function expand_node(node: TreeNode) {
  if (node.children?.length) {
    expanded_keys.value[node.key] = true;

    for (const child of node.children) {
      expand_node(child);
    }
  }
}
</script>

<template>
  <Tree
    v-model:expanded-keys="expanded_keys"
    :value="packet_nodes"
    class="gutter-stable h-screen overflow-auto p-4"
  />
</template>

<style lang="postcss">
@reference "../style.css";

.p-tree-node-content {
  @apply py-0;
}

.p-tree-node-toggle-button {
  @apply hidden;
}

.p-tree-node-children {
  @apply pl-[2ch];
}
</style>
