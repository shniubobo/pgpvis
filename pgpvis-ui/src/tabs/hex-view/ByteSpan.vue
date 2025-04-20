<script setup lang="ts">
import { computed, inject, ref, type Ref } from "vue";

const props = defineProps<{
  byte: number;
  offset: number;
}>();

const selected_bytes = inject("selected-bytes", ref([])) as Ref<boolean[]>;
const selected = computed(() => selected_bytes.value[props.offset]);

function has_byte_overflown(byte: number): boolean {
  return 0x00 <= byte && byte <= 0xff;
}
</script>

<template>
  <span
    class="inline-block px-[0.5ch] transition-colors duration-50 select-none"
    :class="{ 'bg-sky-200': selected }"
    >{{
      has_byte_overflown(props.byte)
        ? props.byte.toString(16).padStart(2, "0")
        : "??"
    }}</span
  >
</template>
