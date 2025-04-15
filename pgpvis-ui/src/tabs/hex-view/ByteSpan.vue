<script setup lang="ts">
import { computed, inject, type Ref } from "vue";

const props = defineProps<{
  byte: number;
  offset: number;
}>();

const selected_bytes = inject("selected-bytes") as Ref<boolean[]>;
const selected = computed(() => selected_bytes.value[props.offset]);
</script>

<template>
  <span
    class="inline-block px-[0.5ch] select-none"
    :class="{ 'bg-sky-200': selected }"
    >{{ props.byte.toString(16).padStart(2, "0") }}</span
  >
</template>
