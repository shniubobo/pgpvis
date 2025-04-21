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
watch(watch_getters(), () => (selected.value = false));

// We have to write this, instead of directly `watch`ing `props`, because the
// wasm-exported `Node` keeps triggering `watch` when it should not, setting
// `selected.value` back to `false`.
//
// And because this issue only happens with wasm-exported types, it cannot be
// captured by the test "`underline` gained by correct nodes", which uses a
// mocked version of `Node`.
//
// As a sidenote, this only happens when a parent node is clicked and then its
// child. Clicking the child again highlights the child correctly. The reason
// for this not happening on every click is unknown.
function watch_getters(node?: Node): (() => string | number | undefined)[] {
  const getters: (() => string | number | undefined)[] = [];

  getters.push(() => props.depth);

  if (node === undefined) {
    getters.push(() => props.node.text);
    getters.push(() => props.node.offset);
    getters.push(() => props.node.length);
    props.node.children.forEach((child) =>
      getters.push(...watch_getters(child)),
    );
  } else {
    getters.push(() => node.text);
    getters.push(() => node.offset);
    getters.push(() => node.length);
    node.children.forEach((child) => getters.push(...watch_getters(child)));
  }

  return getters;
}

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
        class="decoration-blue-300/60 decoration-[0.5em] -underline-offset-[0.25em] transition-[text-decoration] duration-50 select-none skip-ink"
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
