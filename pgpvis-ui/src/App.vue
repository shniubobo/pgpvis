<script setup lang="ts">
import { ref } from "vue";

import { Node } from "pgpvis-core";

import HexViewTab from "./tabs/hex-view/HexViewTab.vue";
import InputTab from "./tabs/InputTab.vue";
import PacketsTab from "./tabs/packets/PacketsTab.vue";

const bytes = ref<Uint8Array>(new Uint8Array());
const nodes = ref<Node[]>([]);
</script>

<template>
  <div class="grid grid-cols-3">
    <InputTab
      @update-hex-view="(new_bytes) => (bytes = new_bytes)"
      @update-packets="(new_nodes) => (nodes = new_nodes)"
    />
    <HexViewTab :bytes="bytes" />
    <PacketsTab :nodes="nodes" />
  </div>
</template>
