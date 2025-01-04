<script setup lang="ts">
import { computed, ref } from "vue";

import { parse, TypeId, type PacketSequence, type ParseOptions, type UserId } from "pgpvis-core";

const message = ref("");
const bytes = ref<number[]>([])
const packets = ref<PacketSequence>([]);

const user_ids = computed(() => {
  const user_ids = [];
  for (let packet of packets.value) {
    if (packet.inner === undefined) {
      continue;
    }
    if (packet.inner.header.inner.ctb.inner.type_id === TypeId.UserId) {
      const user_id = packet.inner.body.inner as UserId;
      user_ids.push(user_id.user_id);
    }
  }
  return user_ids;
});

function do_parse() {
  const encoded = new TextEncoder().encode(message.value);
  const parse_options: ParseOptions = { dearmor: true };
  const parse_output = parse(parse_options, encoded);
  bytes.value = parse_output.bytes;
  packets.value = parse_output.packet_sequence;
}
</script>

<template>
  <textarea v-model="message"></textarea>
  <button @click="do_parse">Parse</button>
  <li v-for="(user_id, index) in user_ids" :key="index">{{ user_id.inner }}</li>
</template>

<style scoped></style>
