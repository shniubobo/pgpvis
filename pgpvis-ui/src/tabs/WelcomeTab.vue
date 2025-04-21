<script setup lang="ts">
import { DEV, VERSION } from "../version";
</script>

<template>
  <article class="flex flex-col justify-center text-center text-lg">
    <!-- TODO: Make a logo and replace this heading --->
    <h1 class="mt-auto mb-10 text-4xl">pgpvis</h1>

    <p>
      Hi, this is <code>pgpvis</code>, a dumper / visualizer for OpenPGP
      packets.
    </p>
    <p>
      Think <code>pgpdump</code>, or <code>gpg --list-packets</code>, but with a
      GUI!
    </p>
    <p>
      Just paste anything OpenPGP into the left, and click the submit button.
    </p>

    <div
      class="mt-8 rounded-lg bg-yellow-50 py-4 text-yellow-800 before:mb-4 before:block before:content-['🚧🚧🚧']"
    >
      This project is still work in progress.<br />Many features are missing.
    </div>

    <div id="footer" class="mt-auto pb-4 text-base text-neutral-500">
      <span>{{ VERSION }}</span>
      <span v-if="DEV"> (dev)</span>
      <span> | </span>
      <a
        class="underline decoration-neutral-400 underline-offset-2"
        href="https://github.com/shniubobo/pgpvis"
        target="_blank"
        rel="noreferrer"
      >
        Source Code
      </a>
    </div>
  </article>
</template>

<style scoped lang="postcss">
@reference "../style.css";

p {
  @apply mb-4;
}

code::before,
code::after {
  content: "`";
}

code {
  @apply text-neutral-700;
}
</style>
