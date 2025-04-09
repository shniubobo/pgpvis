<script setup lang="ts">
import { ref } from "vue";

import { Node, parse, ParseOptions } from "pgpvis-core";

const message = ref("");

const emit = defineEmits<{
  "update-hex-view": [bytes: Uint8Array];
  "update-packets": [nodes: Node[]];
}>();

function do_parse() {
  const encoded_message = new TextEncoder().encode(message.value);
  // TODO: Allow users to choose whether to dearmor or not.
  const parse_options = new ParseOptions(true);
  const parse_output = parse(parse_options, encoded_message);
  emit("update-hex-view", parse_output.bytes);
  emit("update-packets", parse_output.nodes);
}
</script>

<template>
  <div class="flex h-full flex-col p-4">
    <textarea v-model="message" class="flex-grow resize-none text-nowrap" />
    <button @click="do_parse">Parse</button>
  </div>
</template>
