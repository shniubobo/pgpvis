<script setup lang="ts">
import ByteSpan from "./ByteSpan.vue";

const props = defineProps<{
  bytes: number[];
  offset: number;
}>();
</script>

<template>
  <div>
    <ByteSpan
      v-for="(byte, idx) in props.bytes"
      :key="props.offset + idx"
      :byte="byte"
      :offset="props.offset + idx"
    />
  </div>
</template>
