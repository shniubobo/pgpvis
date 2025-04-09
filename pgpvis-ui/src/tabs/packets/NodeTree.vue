<script setup lang="ts">
import { Node } from "pgpvis-core";

const props = defineProps<{ node: Node; depth: number }>();
</script>

<template>
  <div>
    <span>{{ props.node.text }}</span>
    <NodeTree
      v-for="(child, idx) in props.node.children"
      :key="idx"
      class="pl-[2ch]"
      :node="child"
      :depth="props.depth + 1"
    />
  </div>
</template>
