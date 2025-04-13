<script setup lang="ts">
import ByteSpan from "./ByteSpan.vue";

export type Line = { byte: number; selected: boolean }[];

const props = defineProps<{
  line: Line;
  offset: number;
}>();
</script>

<template>
  <div>
    <ByteSpan
      v-for="({ byte, selected }, idx) in props.line"
      :key="props.offset + idx"
      :byte="byte"
      :selected="selected"
      :offset="props.offset + idx"
    />
  </div>
</template>
