<script setup lang="ts">
import { computed, ref } from "vue";

import { type Message, parse_armored } from "pgpvis-core";

const message = ref("");
const packets = ref<Message>();

const user_ids = computed(() => {
  if (packets.value === undefined) {
    return [];
  }

  const user_ids = [];
  for (let packet of packets.value) {
    if (packet === "Unknown") {
      continue;
    }
    if ("UserId" in packet) {
      user_ids.push(packet.UserId);
    }
  }
  return user_ids;
});

function parse() {
  packets.value = parse_armored(message.value);
}
</script>

<template>
  <textarea v-model="message"></textarea>
  <button @click="parse">Parse</button>
  <li v-for="(user_id, index) in user_ids" :key="index">{{ user_id.id }}</li>
</template>

<style scoped></style>
