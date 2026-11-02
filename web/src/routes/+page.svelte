<script lang="ts">
  import { asset, resolve } from '$app/paths';
  import { releaseTag } from '#lib/generated/version.json';
  import { onMount } from 'svelte';
  import { Select, type SelectItem } from '@alis-is/starlight';
  import { detectClientPlatform, type ClientPlatform } from '#lib/client-platform.ts';
  import CopyButton from '#lib/CopyButton.svelte';
  import Benefits from '#lib/Benefits.svelte';
  import IsolationLayers from '#lib/IsolationLayers.svelte';
  import PageMeta from '#lib/PageMeta.svelte';
  import { page } from '$app/state';

  const platforms: SelectItem<ClientPlatform>[] = [
    { label: 'Linux', value: 'linux' },
    { label: 'macOS on Apple Silicon', value: 'macos' },
    { label: 'Windows', value: 'windows' }
  ];
  let platform = $state<ClientPlatform>('');
  let isClient = $state(false);
  let linuxInstallCode = $state<HTMLElement>();
  let windowsInstallCode = $state<HTMLElement>();
  let setupCode = $state<HTMLElement>();
  let recipeCode = $state<HTMLElement>();

  onMount(() => {
    platform = detectClientPlatform(navigator);
    isClient = true;
  });
</script>

<PageMeta title="Terrarium — room to work" description="Give your agents and development tools a lightweight VM of their own. One binary, persistent storage, and only the files and network you allow. For Linux, macOS on Apple Silicon, and Windows." />
<svelte:head>
  {@html `<script type="application/ld+json">${JSON.stringify({ '@context': 'https://schema.org', '@type': 'WebSite', name: 'Terrarium', url: page.url.origin + page.url.pathname })}</script>`}
</svelte:head>

<section class="hero" aria-labelledby="hero-heading">
  <h1 id="hero-heading">Give your agent<br />room to <em>work.</em></h1>
  <p class="lead">Persistent Linux VMs for agents and dev tools. One binary, with only the host files and network access you allow.</p>
  <div class="actions">
    <a class="primary-link" href="#start">Get started <span aria-hidden="true">→</span></a>
    <a class="text-link" href={resolve('docs/usage/')}>Read the guide <span aria-hidden="true">↗</span></a>
  </div>
  <p class="hero-platforms">Linux · macOS on Apple Silicon · Windows</p>
  <figure class="hero-art">
    <img src={asset('logo.svg')} width="969" height="914" fetchpriority="high" alt="A frog and dragonfly among ferns and a yellow flower, inside a glass terrarium." />
  </figure>
</section>

<Benefits>
  <h2>Your tools. Your rules.</h2>
</Benefits>

<IsolationLayers />

<section id="start" class="start-section" aria-labelledby="start-heading">
  <div class="start-intro section-intro">
    <div>
      <p class="eyebrow">From a recipe to a running box</p>
      <h2 id="start-heading">Make a little room.</h2>
    </div>
    <div>
      <p class="section-description">Install Terra, write a short recipe, and step inside your own Linux VM.</p>
      {#if releaseTag}<p class="release-note">Current release <a target="_blank" rel="noopener noreferrer" href={`https://github.com/terrarium-sh/terrarium/releases/tag/${releaseTag}`}>{releaseTag}</a></p>{/if}
    </div>
  </div>
  <div class="setup-install">
    <h3 class="step-heading"><span>01</span> Install Terra</h3>
    {#if isClient}
      <div class="platform-choice">
        <Select label="Install for" options={platforms} value={platforms.find(item => item.value === platform)} onselected={(item: SelectItem<ClientPlatform>) => platform = item.value} />
      </div>
      {#if !platform}<p class="small muted">Choose the desktop computer you’ll install Terra on.</p>{/if}
    {/if}
    {#if platform === 'macos'}<p class="small muted">Requires Apple Silicon. Browsers cannot reliably identify your Mac’s processor.</p>{/if}
    <div id="install-commands">
      {#if platform !== 'windows'}
        <p class="code-label">{platform === 'macos' ? 'macOS on Apple Silicon · Terminal' : platform === 'linux' ? 'Linux · Terminal' : 'Linux & macOS on Apple Silicon · Terminal'}</p>
        <div class="copyable-block"><pre><code bind:this={linuxInstallCode}>curl -fsSL https://raw.githubusercontent.com/terrarium-sh/terrarium/main/install.sh | sh</code></pre><CopyButton text={() => linuxInstallCode?.textContent?.trimEnd() ?? ''} label="Copy Linux and macOS install command" /></div>
      {/if}
      {#if platform === 'windows' || !platform}
        <p class="code-label">Windows · PowerShell</p>
        <div class="copyable-block"><pre><code bind:this={windowsInstallCode}>irm https://raw.githubusercontent.com/terrarium-sh/terrarium/main/install.ps1 | iex</code></pre><CopyButton text={() => windowsInstallCode?.textContent?.trimEnd() ?? ''} label="Copy Windows install command" /></div>
        <p class="small muted">After installing on Windows, open a new terminal so <code>terra</code> is on your PATH.</p>
      {/if}
    </div>
    <p class="small muted">Linux needs KVM. Windows needs Windows Hypervisor Platform. <a href={resolve('docs/usage/#installation-options')}>Installation details <span aria-hidden="true">↗</span></a></p>
  </div>
  <div class="setup-recipe">
    <h3 class="step-heading"><span>02</span> Give it a recipe</h3>
    <p>Save this as <code>dev.yaml</code> in your project folder.</p>
    <div class="recipe-preview">
      <div class="code-heading"><span class="status-dot" aria-hidden="true"></span><span>dev.yaml</span><span class="muted">your box, your rules</span></div>
      <div class="copyable-block"><pre><code bind:this={recipeCode}><span class="code-key">hw:</span>
  cpus: 2
  mem_mib: 1024

<span class="code-key">network:</span>
  mode: unrestricted-public

<span class="code-key">workload:</span>
  entrypoint: /bin/sh</code></pre><CopyButton text={() => recipeCode?.textContent?.trimEnd() ?? ''} label="Copy dev.yaml recipe" /></div>
      <p>This recipe allows public network access.<br />Host files stay private until you share them.</p>
    </div>
    <a class="recipe-link" href="https://github.com/terrarium-sh/terrarium_examples" target="_blank" rel="noopener noreferrer">Find a recipe for your project <span aria-hidden="true">↗</span></a>
  </div>
  <div class="setup-run">
    <h3 class="step-heading"><span>03</span> Step inside</h3>
    <div class="copyable-block"><pre><code bind:this={setupCode}>terra ./dev.yaml setup
terra</code></pre><CopyButton text={() => setupCode?.textContent?.trimEnd() ?? ''} label="Copy setup commands" /></div>
    <a class="text-link" href={resolve('docs/usage/')}>Where to go from here <span aria-hidden="true">→</span></a>
  </div>
  <aside class="status-notice" aria-label="Project status">
    <strong><span class="status-dot" aria-hidden="true"></span> Ready to try.</strong>
    <span>The CLI should stay stable. Internal protocols and on-disk storage can still change in breaking ways, though less often over time.</span>
  </aside>
</section>

<section class="reading-section">
  <p class="eyebrow">Keep exploring</p><h2>A little guidance goes a long way.</h2>
  <div class="reading-grid">
    <a href={resolve('commands/')}><h3>Command reference</h3><p>Find a command, flag, or example. Generated directly from the CLI.</p></a>
    <a href={resolve('docs/recipe/')}><h3>Write a recipe</h3><p>Configure resources, mounts, network access, and lifecycle hooks.</p></a>
    <a href={resolve('docs/security/')}><h3>Understand the boundary</h3><p>What Terra isolates, what it trusts, and how its devices are sandboxed.</p></a>
    <a href={resolve('skill.md')}><h3>Agent skill</h3><p>Let your coding agent write, check, and smoke-test a box. Save as <code>.claude/skills/terra-box/SKILL.md</code>.</p></a>
  </div>
</section>
