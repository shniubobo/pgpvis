<script setup lang="ts">
import { ref } from "vue";

import { type PacketSequence } from "pgpvis-core";

import HexViewTab from "./tabs/hex-view/HexViewTab.vue";
import InputTab from "./tabs/InputTab.vue";
import PacketsTab from "./tabs/packets/PacketsTab.vue";

const bytes = ref<number[]>([]);
const packets = ref<PacketSequence>([]);
</script>

<template>
  <div class="grid grid-cols-3">
    <InputTab
      @update-bytes="(new_bytes) => (bytes = new_bytes)"
      @update-packets="(new_packets) => (packets = new_packets)"
    />
    <HexViewTab :bytes="bytes" />
    <PacketsTab :packets="packets" />
  </div>
</template>
