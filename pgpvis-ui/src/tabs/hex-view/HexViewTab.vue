<script setup lang="ts">
import { computed, ref } from "vue";

import type { Line } from "./BytesLine.vue";
import BytesLine from "./BytesLine.vue";

const LINE_LENGTH = 16; // TODO: Make this a prop.

const props = defineProps<{ bytes: Uint8Array }>();

const selected_byte_offsets = ref<number[]>([]);

const byte_lines = computed(() => {
  let current_offset = 0;
  const max_offset = props.bytes.length - 1;
  const lines: Line[] = [];

  while (current_offset <= max_offset) {
    const next_offset = current_offset + LINE_LENGTH;

    const bytes = Array.from(props.bytes.slice(current_offset, next_offset));
    const line = bytes.map((byte, idx) => {
      return { byte: byte, selected: is_byte_selected(current_offset + idx) };
    });
    lines.push(line);

    current_offset = next_offset;
  }

  return lines;
});

function is_byte_selected(offset: number): boolean {
  return selected_byte_offsets.value.includes(offset);
}
</script>

<template>
  <div class="gutter-stable h-screen overflow-auto p-4">
    <BytesLine
      v-for="(line, idx) in byte_lines"
      :key="idx * LINE_LENGTH"
      :line="line"
      :offset="idx * LINE_LENGTH"
    />
  </div>
</template>
