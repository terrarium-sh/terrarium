<script lang="ts">
  import '@alis-is/starlight/style.sass';
  import '../theme.css';
  import { base } from '$app/paths';
  import { page } from '$app/state';

  let { children } = $props();
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
    <a href="https://github.com/terrarium-sh/terrarium">GitHub <span aria-hidden="true">↗</span></a>
  </nav>
</header>
<main id="main" tabindex="-1">{@render children()}</main>
<footer class="site-footer">
  <span>A small core. Room to grow.</span>
  <div><a href="https://discord.gg/CQDEtqxPwJ">Discord</a><a href="https://github.com/terrarium-sh/terrarium">Source</a><span>Apache-2.0</span></div>
</footer>
