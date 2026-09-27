<script lang="ts">
  import { onDestroy, tick } from 'svelte';

  let { text, label = 'Copy code' }: { text: string | (() => string); label?: string } = $props();
  let feedback = $state('');
  let reset: ReturnType<typeof setTimeout>;

  async function copy() {
    clearTimeout(reset);
    feedback = '';
    await tick();
    try {
      await navigator.clipboard.writeText(typeof text === 'function' ? text() : text);
      feedback = 'Copied';
    } catch {
      feedback = 'Copy failed';
    }
    reset = setTimeout(() => feedback = '', 2000);
  }

  onDestroy(() => clearTimeout(reset));
</script>

<button type="button" class="copy-button" aria-label={feedback || label} title={feedback || label} onclick={copy}>
  <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    {#if feedback === 'Copied'}
      <path d="m5 12 4 4L19 6" />
    {:else if feedback === 'Copy failed'}
      <path d="m6 6 12 12M18 6 6 18" />
    {:else}
      <rect x="8" y="8" width="12" height="12" rx="2" />
      <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" />
    {/if}
  </svg>
</button>
<span class="sr-only" role="status">{feedback}</span>
