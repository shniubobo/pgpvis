<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{ bytes: number[] }>();

const hex_bytes = computed(() =>
  props.bytes.map((value) => value.toString(16).padStart(2, "0")).join(" "),
);
</script>

<template>
  <div class="gutter-stable h-screen overflow-auto p-4">
    {{ hex_bytes }}
  </div>
</template>
