<script setup lang="ts">
import { useVirtualizer } from "@tanstack/vue-virtual";
import { useEventBus } from "@vueuse/core";
import { computed, ref, useTemplateRef } from "vue";

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

const hex_view = useTemplateRef("hex-view");
// `useVirtualizer` is not responsive over `count`, so we have to use
// `computed` here.
//
// See:
// - https://github.com/TanStack/virtual/issues/363
// - https://github.com/TanStack/virtual/issues/969
const virtual_hex_view = computed(() =>
  useVirtualizer({
    count: byte_lines.value.length,
    getScrollElement: () => hex_view.value,
    estimateSize: () => 24, // TODO: Do not hard-code this.
  }),
);
const virtual_lines = computed(() =>
  virtual_hex_view.value.value.getVirtualItems(),
);

// The virtualizer has a bug that, when it is updated with new `byte_lines`,
// the old data is still on the screen, if the new data is shorter than the
// viewport.
//
// To reproduce:
//
// 1. Paste a long message into the input tab and press "Parse"
// 2. Scroll the hex view very fast, by dragging the scrollbar (the bug is not
//    reproducible with slow scrolls with the mouse wheel)
// 3. Paste a short message into the input tab and press "Parse" (to reproduce
//    the bug, the resulting bytes in the hex view must not take up the whole
//    tab)
// 4. Some of the old bytes that are not covered by the new bytes are still on
//    the screen. They are not selectable. Switching browser tabs, switching
//    system windows, or minimizing and maximizing the browser window makes
//    the old bytes disappear.
//
// TODO: Come up with a minimal reproducible example, file a bug report and
// leave a link here to that issue.

const bus = useEventBus<{ offset: number; length: number }>("span-selected");
bus.on(({ offset, length }) => {
  selected_byte_offsets.value = Array(length)
    .fill(offset)
    .map((offset, idx) => offset + idx);

  virtual_hex_view.value.value.scrollToIndex(
    get_center_line_index(offset, length),
    { align: "center" },
  );
});

function get_center_line_index(offset: number, length: number) {
  const center_offset = offset + length / 2;
  const center_line = Math.floor(center_offset / LINE_LENGTH);
  return center_line;
}
</script>

<template>
  <div ref="hex-view" class="gutter-stable h-screen overflow-auto p-4">
    <div
      class="relative w-full"
      :style="{ height: `${virtual_hex_view.value.getTotalSize()}px` }"
    >
      <div
        v-for="virtual_line in virtual_lines"
        :key="virtual_line.index"
        class="absolute top-0 left-0 w-full"
        :style="{
          height: `${virtual_line.size}px`,
          transform: `translateY(${virtual_line.start}px)`,
        }"
      >
        <BytesLine
          :line="byte_lines[virtual_line.index]"
          :offset="virtual_line.index * LINE_LENGTH"
        />
      </div>
    </div>
  </div>
</template>
