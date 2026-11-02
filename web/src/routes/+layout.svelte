<script lang="ts">
  import '@alis-is/starlight/style.sass';
  import '../theme.css';
  import { asset, resolve } from '$app/paths';
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
  <a class="wordmark" href={resolve('/')} aria-label="Terrarium home">
    <img src={asset('logo.svg')} alt="" width="44" height="42" />
    <span>terra<span class="muted">rium</span></span>
  </a>
  <nav aria-label="Main navigation">
    <a href={resolve('docs/usage/')} aria-current={page.url.pathname.includes('/docs/') ? 'page' : undefined}>Guides</a>
    <a href={resolve('commands/')} aria-current={page.url.pathname.includes('/commands/') ? 'page' : undefined}>Commands</a>
    <a href="https://github.com/terrarium-sh/terrarium_examples" target="_blank" rel="noopener noreferrer">Examples</a>
    <a class="nav-github" href="https://github.com/terrarium-sh/terrarium" target="_blank" rel="noopener noreferrer"><svg viewBox="0 0 24 24" width="17" height="17" fill="currentColor" aria-hidden="true"><path d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.86c-2.78.6-3.37-1.18-3.37-1.18-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.89 1.53 2.34 1.09 2.91.83.09-.64.35-1.09.64-1.34-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.99 1.03-2.69-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.03a9.58 9.58 0 0 1 5 0c1.91-1.3 2.75-1.03 2.75-1.03.55 1.38.2 2.4.1 2.65.64.7 1.03 1.6 1.03 2.69 0 3.84-2.34 4.69-4.57 4.94.36.31.68.92.68 1.85v2.75c0 .27.18.58.69.48A10 10 0 0 0 12 2Z" /></svg>GitHub</a>
  </nav>
</header>
<main id="main" class:home-page={page.route.id === '/'} tabindex="-1">{@render children()}</main>
<footer class="site-footer">
  <span>A small core. Room to grow.</span>
  <div><a href="https://discord.gg/CQDEtqxPwJ" target="_blank" rel="noopener noreferrer">Discord</a><a class="github-stars" href="https://github.com/terrarium-sh/terrarium" target="_blank" rel="noopener noreferrer" aria-label={stars === null ? 'Terrarium on GitHub' : `Terrarium on GitHub, ${stars} stars`}>GitHub{#if stars !== null}<span class="star-count"><span aria-hidden="true">★</span> {stars.toLocaleString('en-US')}</span>{/if}</a><span>Apache-2.0</span></div>
</footer>
