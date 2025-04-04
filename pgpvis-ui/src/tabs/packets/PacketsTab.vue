<script setup lang="ts">
import { computed } from "vue";

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

const packet_nodes = computed(() => {
  const packet_nodes: string[] = [];
  for (const packet of props.packets) {
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

    const header_node = `\
Header
  CTB
    Format: ${format}
    Type ID: ${type_id}
  Length: ${length}`;

    if (type_id === TypeId.PublicKey || type_id === TypeId.PublicSubkey) {
      const public_key = packet.inner.body.inner as PublicKey | PublicSubkey;
      const key_role = type_id === TypeId.PublicKey ? "Key" : "Subkey";
      const creation_time = public_key.creation_time.inner;
      // Creation time is stored as seconds as per RFC 9580, but here we need
      // milliseconds.
      const creation_time_iso = new Date(creation_time * 1000).toISOString();
      const algorithm = PublicKeyAlgorithmId[public_key.algorithm.inner];
      const key_material = public_key.key_material.inner;

      let key_material_nodes;
      if (public_key.algorithm.inner === PublicKeyAlgorithmId.RsaEncryptSign) {
        const n_length = (key_material as RsaEncryptSign).n.inner.length.inner;
        const e_length = (key_material as RsaEncryptSign).e.inner.length.inner;

        key_material_nodes = `\
n
  Length: ${n_length}
  Integers: [${n_length} octets]
e
  Length: ${e_length}
  Integers: [${e_length} octets]`;
      }

      const body_node = `\
Body
  Version: ${public_key.version.inner}
  Creation Time: ${creation_time_iso} (${creation_time})
  Algorithm: ${algorithm}
  Key Material
${key_material_nodes?.replace(/^/gm, " ".repeat(4))}`;

      const packet_node = `\
Public ${key_role} (${type_id}): ${public_key.key_id} (${algorithm})
${header_node.replace(/^/gm, " ".repeat(2))}
${body_node.replace(/^/gm, " ".repeat(2))}
`;
      packet_nodes.push(packet_node);
    } else if (type_id === TypeId.UserId) {
      const user_id = packet.inner.body.inner as UserId;

      const body_node = `\
Body
  User ID: ${user_id.user_id.inner}`;

      const packet_node = `\
User ID (${type_id}): ${user_id.user_id.inner}
${header_node.replace(/^/gm, " ".repeat(2))}
${body_node.replace(/^/gm, " ".repeat(2))}`;
      packet_nodes.push(packet_node);
    }
  }
  console.log(packet_nodes);
  return packet_nodes;
});
</script>

<template>
  <div class="gutter-stable h-screen overflow-auto p-4">
    <pre v-for="(packet_node, idx) in packet_nodes" :key="idx">{{
      packet_node
    }}</pre>
  </div>
</template>
