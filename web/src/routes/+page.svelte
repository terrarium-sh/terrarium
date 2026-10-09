<script lang="ts">
  import { base } from '$app/paths';
  import { releaseTag } from '$lib/generated/version.json';
  import { onMount } from 'svelte';
  import { Select, type SelectItem } from '@alis-is/starlight';
  import { detectClientPlatform, type ClientPlatform } from '$lib/client-platform';
  import CopyButton from '$lib/CopyButton.svelte';
  import IsolationLayers from '$lib/IsolationLayers.svelte';

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

<svelte:head>
  <title>Terrarium — room to work</title>
  <meta name="description" content="Run coding agents and development tools in a microVM. One static core, Wasm-isolated devices, explicit access, and native support for Linux and Windows (x86_64 / ARM64), and macOS on Apple Silicon." />
</svelte:head>

<aside class="construction-notice" aria-label="Project status">
  <strong><span aria-hidden="true">⚠</span> Still finding our frog legs.</strong>
  <span>Testing and internal review are ongoing. Use with caution.</span>
</aside>

<section class="hero">
  <div class="hero-copy">
    <p class="eyebrow">A little space of its own</p>
    <h1>Give your agent<br />room to <em>work.</em></h1>
    <p class="lead">Decide what it can touch.</p>
    <p class="hero-description">A portable microVM with one static core, Wasm-isolated devices, and only the access you choose.</p>
    <div class="actions"><a class="primary-link" href="#start">Get started <span aria-hidden="true">→</span></a><a href="{base}/commands/">Explore the commands</a></div>
    <p class="small muted">Linux · macOS on Apple Silicon · Windows</p>
  </div>
  <div class="hero-art">
    <figure>
      <img src="{base}/logo.svg" width="969" height="914" alt="A frog and dragonfly among ferns and a yellow flower, inside a glass terrarium." />
      <figcaption>A little world. A clear boundary.</figcaption>
    </figure>
  </div>
</section>

<section class="principles" aria-label="Why Terrarium">
  <div><span class="eyebrow">01 / Self-contained</span><h2>One static core.</h2><p>The kernel, base filesystem, and device components ship in one binary. A small core you can inspect, with recipes and hooks to extend it.</p></div>
  <div><span class="eyebrow">02 / Isolated</span><h2>Wasm-isolated devices.</h2><p>Software fault isolation (SFI) gives the VMM and every device instance a separate WebAssembly sandbox, with scoped access to a thin host API.</p></div>
  <div><span class="eyebrow">03 / Explicit</span><h2>Access is a choice.</h2><p>Host files and network access start closed. Your recipe names the directories, destinations, and capabilities you grant.</p></div>
  <div><span class="eyebrow">04 / Portable</span><h2>Bring your environment.</h2><p>Linux and Windows (x86_64 / ARM64), and macOS on Apple Silicon. Native hypervisors underneath; the same recipes and CLI wherever you work.</p></div>
</section>

<IsolationLayers />

<section id="start" class="start-section">
  <div>
    <p class="eyebrow">From a recipe to a running box</p>
    <h2>Make a little room.</h2>
    {#if releaseTag}<p class="release-note">Current release <a target="_blank" rel="noopener noreferrer" href={`https://github.com/terrarium-sh/terrarium/releases/tag/${releaseTag}`}>{releaseTag}</a></p>{/if}
    <p>Install Terra and save this recipe as <code>dev.yaml</code>. Then set up and enter your box.</p>
    {#if isClient}
      <div class="platform-choice">
        <Select label="Install for" options={platforms} value={platforms.find(item => item.value === platform)} onselected={(item: SelectItem<ClientPlatform>) => platform = item.value} />
      </div>
      {#if !platform}<p class="small muted">Choose the desktop computer you’ll install Terra on.</p>{/if}
    {/if}
    {#if platform === 'macos'}<p class="small muted">Requires Apple Silicon. Browsers cannot reliably identify your Mac’s processor.</p>{/if}
    <div id="install-commands">
      {#if platform !== 'windows'}
        <h3>{platform === 'macos' ? 'macOS on Apple Silicon · Terminal' : platform === 'linux' ? 'Linux · Terminal' : 'Linux & macOS on Apple Silicon · Terminal'}</h3>
        <div class="copyable-block"><pre><code bind:this={linuxInstallCode}>curl -fsSLO https://raw.githubusercontent.com/terrarium-sh/terrarium/main/install.sh &amp;&amp; sh install.sh</code></pre><CopyButton text={() => linuxInstallCode?.textContent?.trimEnd() ?? ''} label="Copy Linux and macOS install command" /></div>
      {/if}
      {#if platform === 'windows' || !platform}
        <h3>Windows · PowerShell</h3>
        <div class="copyable-block"><pre><code bind:this={windowsInstallCode}>Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/terrarium-sh/terrarium/main/install.ps1 -OutFile install.ps1; if ($?) &#123; powershell -ExecutionPolicy Bypass -File install.ps1 &#125;</code></pre><CopyButton text={() => windowsInstallCode?.textContent?.trimEnd() ?? ''} label="Copy Windows install command" /></div>
        <p class="small muted">After installing on Windows, open a new terminal so <code>terra</code> is on your PATH.</p>
      {/if}
    </div>
    <h3>Set up your box</h3>
    <div class="copyable-block"><pre><code bind:this={setupCode}>terra ./dev.yaml setup
terra</code></pre><CopyButton text={() => setupCode?.textContent?.trimEnd() ?? ''} label="Copy setup commands" /></div>
    <a href="{base}/docs/usage/">Read the usage guide <span aria-hidden="true">→</span></a>
  </div>
  <div class="recipe-preview">
    <div class="code-heading"><span class="status-dot"></span><span>dev.yaml</span><span class="muted">your box, your rules</span></div>
    <div class="copyable-block"><pre><code bind:this={recipeCode}><span class="code-key">hw:</span>
  cpus: 2
  mem_mib: 1024

<span class="code-key">network:</span>
  mode: unrestricted-public

<span class="code-key">workload:</span>
  entrypoint: /bin/sh</code></pre><CopyButton text={() => recipeCode?.textContent?.trimEnd() ?? ''} label="Copy dev.yaml recipe" /></div>
    <div class="copyable-block"><div class="terminal-line"><span aria-hidden="true">$</span> terra ./dev.yaml setup<br /><span aria-hidden="true">$</span> terra</div><CopyButton text={'terra ./dev.yaml setup\nterra'} label="Copy terminal commands" /></div>
    <p>Public network access is opt-in.<br />Host files stay private until you share them.</p>
  </div>
</section>

<section class="reading-section">
  <p class="eyebrow">Keep exploring</p><h2>A reference within reach.</h2>
  <div class="reading-grid">
    <a href="{base}/commands/"><h3>Command reference</h3><p>Find a command, flag, or example. Generated directly from the CLI.</p></a>
    <a href="{base}/docs/recipe/"><h3>Write a recipe</h3><p>Configure resources, mounts, network access, and lifecycle hooks.</p></a>
    <a href="{base}/docs/security/"><h3>Understand the boundary</h3><p>What Terra isolates, what it trusts, and how its devices are sandboxed.</p></a>
  </div>
</section>
