<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{ bytes: Uint8Array }>();

const hex_bytes = computed(() => {
  const hex_bytes: string[] = [];
  props.bytes.forEach((value) => {
    hex_bytes.push(value.toString(16).padStart(2, "0"));
  });
  return hex_bytes.join(" ");
});
</script>

<template>
  <div class="gutter-stable h-screen overflow-auto p-4">
    {{ hex_bytes }}
  </div>
</template>
