<script setup lang="ts">
import { useEventBus } from "@vueuse/core";
import { computed, ref, watch } from "vue";

import { Node } from "pgpvis-core";

const props = defineProps<{ node: Node; depth: number }>();

const has_span = computed(
  () => props.node.offset !== undefined && props.node.length !== undefined,
);

const bus = useEventBus<{ offset: number; length: number }>("span-selected");

const selected = ref(false);
bus.on(() => (selected.value = false));
watch(props, () => (selected.value = false));

function select() {
  if (has_span.value) {
    bus.emit({ offset: props.node.offset!, length: props.node.length! });
    // The above `bus.on` happens here, and after that ...
    selected.value = true;
  }
}

const indent_guide_classes_outer = computed(() => {
  return props.depth === 0 ? [] : ["bg-gray-200", "pl-px"];
});
const indent_guide_classes_inner = computed(() => {
  return props.depth === 0 ? [] : ["bg-white", "pl-[calc(2ch-1px)]"];
});
</script>

<template>
  <div :class="indent_guide_classes_outer">
    <div :class="indent_guide_classes_inner">
      <span
        class="skip-ink decoration-blue-300/75 decoration-[0.5em] -underline-offset-[0.25em] transition-[text-decoration] duration-50 select-none"
        :class="{ 'cursor-pointer': has_span, underline: selected }"
        @click="select"
        >{{ props.node.text }}</span
      >
      <NodeTree
        v-for="(child, idx) in props.node.children"
        :key="idx"
        :node="child"
        :depth="props.depth + 1"
      />
    </div>
  </div>
</template>
