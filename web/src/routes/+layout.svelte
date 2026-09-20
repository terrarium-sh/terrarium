<script lang="ts">
  import '@alis-is/starlight/style.sass';
  import '../theme.css';
  import { base } from '$app/paths';
  import { page } from '$app/state';
  import { onMount } from 'svelte';

  let { children } = $props();
  let stars = $state<number | null>(null);

  onMount(() => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    async function refreshStars() {
      try {
        const response = await fetch('https://api.github.com/repos/terrarium-sh/terrarium', {
          signal: controller.signal,
          credentials: 'omit'
        });
        if (!response.ok) return;
        const repository = await response.json();
        if (Number.isSafeInteger(repository?.stargazers_count) && repository.stargazers_count >= 0) {
          stars = repository.stargazers_count;
        }
      } catch {
        stars = null;
      } finally {
        clearTimeout(timeout);
      }
    }
    void refreshStars();
    return () => { clearTimeout(timeout); controller.abort(); };
  });
</script>

<a class="skip-link" href="#main">Skip to content</a>
<header class="site-header">
  <a class="wordmark" href="{base}/" aria-label="Terrarium home">
    <img src="{base}/terrarium-placeholder.png" alt="" width="44" height="44" />
    <span>terra<span class="muted">rium</span></span>
  </a>
  <nav aria-label="Main navigation">
    <a href="{base}/docs/usage/" aria-current={page.url.pathname.includes('/docs/') ? 'page' : undefined}>Guides</a>
    <a href="{base}/commands/" aria-current={page.url.pathname.includes('/commands/') ? 'page' : undefined}>Commands</a>
    <a href="https://github.com/terrarium-sh/terrarium" target="_blank" rel="noopener noreferrer">GitHub</a>
  </nav>
</header>
<main id="main" tabindex="-1">{@render children()}</main>
<footer class="site-footer">
  <span>A small core. Room to grow.</span>
  <div><a href="https://discord.gg/CQDEtqxPwJ" target="_blank" rel="noopener noreferrer">Discord</a><a class="github-stars" href="https://github.com/terrarium-sh/terrarium" target="_blank" rel="noopener noreferrer" aria-label={stars === null ? 'Terrarium on GitHub' : `Terrarium on GitHub, ${stars} stars`}>GitHub{#if stars !== null}<span class="star-count"><span aria-hidden="true">★</span> {stars.toLocaleString('en-US')}</span>{/if}</a><span>Apache-2.0</span></div>
</footer>
