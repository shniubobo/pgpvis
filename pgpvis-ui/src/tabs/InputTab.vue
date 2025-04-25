<script setup lang="ts">
import { ArrowRightIcon } from "@heroicons/vue/24/outline";
import { ref } from "vue";

// See comments on `PacketTab`.
import { Node, parse, ParseOptions } from "../../../pgpvis-core/Cargo.toml";

const message = ref("");

const emit = defineEmits<{
  "update-hex-view": [bytes: Uint8Array];
  "update-packets": [nodes: Node[]];
}>();

function do_parse() {
  if (message.value === "") {
    emit("update-hex-view", new Uint8Array());
    emit("update-packets", []);
    return;
  }
  const encoded_message = new TextEncoder().encode(message.value);
  // TODO: Allow users to choose whether to dearmor or not.
  const parse_options = new ParseOptions(true);
  const parse_output = parse(parse_options, encoded_message);
  emit("update-hex-view", parse_output.bytes);
  emit("update-packets", parse_output.nodes);
}
</script>

<template>
  <div class="relative flex h-full flex-col">
    <textarea
      v-model="message"
      class="flex-grow resize-none overflow-y-scroll bg-gray-100 pt-4 pb-4 pl-[2ch] text-nowrap focus:outline-hidden"
      placeholder="Paste armored OpenPGP message here ..."
    />
    <div class="absolute right-12 bottom-8 flex items-center justify-center">
      <button
        type="button"
        class="relative rounded-full bg-white p-3 shadow-md transition-shadow hover:shadow-lg"
        @click="do_parse"
      >
        <ArrowRightIcon class="size-6" />
      </button>
    </div>
  </div>
</template>
