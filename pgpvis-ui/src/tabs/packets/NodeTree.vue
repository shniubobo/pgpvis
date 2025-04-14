<script setup lang="ts">
import { useEventBus } from "@vueuse/core";
import { computed } from "vue";

import { Node } from "pgpvis-core";

const props = defineProps<{ node: Node; depth: number }>();

const has_span = computed(
  () => props.node.offset !== undefined && props.node.length !== undefined,
);

const bus = useEventBus<{ offset: number; length: number }>("span-selected");

function select() {
  if (has_span.value) {
    bus.emit({ offset: props.node.offset!, length: props.node.length! });
  }
}
</script>

<template>
  <div>
    <span
      class="select-none"
      :class="{ 'cursor-pointer': has_span }"
      @click="select"
      >{{ props.node.text }}</span
    >
    <NodeTree
      v-for="(child, idx) in props.node.children"
      :key="idx"
      class="pl-[2ch]"
      :node="child"
      :depth="props.depth + 1"
    />
  </div>
</template>
