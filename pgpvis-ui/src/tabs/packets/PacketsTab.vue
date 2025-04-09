<script setup lang="ts">
import { Node } from "pgpvis-core";
import NodeTree from "./NodeTree.vue";

const props = defineProps<{ nodes: Node[] }>();
</script>

<template>
  <div class="gutter-stable h-screen overflow-auto p-4">
    <NodeTree
      v-for="(node, idx) in props.nodes"
      :key="idx"
      :node="node"
      :depth="0"
    />
  </div>
</template>
