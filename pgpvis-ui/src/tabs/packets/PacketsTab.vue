<script setup lang="ts">
// The vscode plugin can understand `@pgpvis-core`, but `vue-tsc` won't, for
// some files. At the time of writing, those files include this one, `InputTab`
// and `NodeTree`. The reason is unknown.
//
// TODO: Figure out the reason.
import { Node } from "../../../../pgpvis-core/Cargo.toml";

import NodeTree from "./NodeTree.vue";

const props = defineProps<{ nodes: Node[] }>();
</script>

<template>
  <div class="h-screen overflow-auto p-4 gutter-stable">
    <NodeTree
      v-for="(node, idx) in props.nodes"
      :key="idx"
      :node="node"
      :depth="0"
    />
  </div>
</template>
