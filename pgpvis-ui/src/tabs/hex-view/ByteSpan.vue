<script setup lang="ts">
const props = defineProps<{
  byte: number;
  selected: boolean;
  offset: number;
}>();
</script>

<template>
  <span class="px-[0.5ch]">{{ props.byte.toString(16).padStart(2, "0") }}</span>
</template>
