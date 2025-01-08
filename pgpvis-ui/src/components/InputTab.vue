<script setup lang="ts">
import { Button, Textarea } from "primevue";
import { ref } from "vue";

import { parse, type PacketSequence, type ParseOptions } from "pgpvis-core";

const message = ref("");

const emit = defineEmits<{
  "update-bytes": [bytes: number[]];
  "update-packets": [packets: PacketSequence];
}>();

function do_parse() {
  const encoded = new TextEncoder().encode(message.value);
  const parse_options: ParseOptions = { dearmor: true };
  const parse_output = parse(parse_options, encoded);
  emit("update-bytes", parse_output.bytes);
  emit("update-packets", parse_output.packet_sequence);
}
</script>

<template>
  <div class="flex h-full flex-col p-4">
    <Textarea v-model="message" class="flex-grow resize-none text-nowrap" />
    <Button label="Parse" size="large" @click="do_parse" />
  </div>
</template>
