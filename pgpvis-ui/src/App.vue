<script setup lang="ts">
import { ref } from "vue";

import { parse_armored } from "pgpvis-core";

const message = ref("");
const packets = ref<Map<string, string>>();
</script>

<template>
  <textarea v-model="message"></textarea>
  <button @click="packets = parse_armored(message)">Parse</button>
  <li v-for="[index, packet] in packets" :key="index">{{ index }} | {{ packet }}</li>
</template>

<style scoped></style>
