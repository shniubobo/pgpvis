<script setup lang="ts">
import { computed, ref } from "vue";

import { parse, TypeID, type PacketSequence } from "pgpvis-core";

const message = ref("");
const packets = ref<PacketSequence>([]);

const user_ids = computed(() => {
  const user_ids = [];
  for (let packet of packets.value) {
    if (packet.inner === undefined) {
      continue;
    }
    if (packet.inner.header.inner.ctb.inner.type_id === TypeID.UserID) {
      user_ids.push(packet.inner.body.inner!.user_id);
    }
  }
  return user_ids;
});

function do_parse() {
  const encoded = new TextEncoder().encode(message.value);
  packets.value = parse(encoded);
}
</script>

<template>
  <textarea v-model="message"></textarea>
  <button @click="do_parse">Parse</button>
  <li v-for="(user_id, index) in user_ids" :key="index">{{ user_id.inner }}</li>
</template>

<style scoped></style>
