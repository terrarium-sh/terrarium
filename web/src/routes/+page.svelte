<script lang="ts">
  import { base } from '$app/paths';
  import { releaseTag } from '$lib/generated/version.json';
  import { onMount } from 'svelte';
  import { detectClientPlatform, type ClientPlatform } from '$lib/client-platform';

  let platform = $state<ClientPlatform>('');
  let isClient = $state(false);

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
  <figure class="hero-art">
    <img src="{base}/terrarium-placeholder.png" width="1254" height="1254" fetchpriority="high" alt="A turquoise frog among ferns and a yellow flower, inside a glass terrarium." />
    <figcaption>A little world. A clear boundary.</figcaption>
  </figure>
</section>

<section class="principles" aria-label="Why Terrarium">
  <div><span class="eyebrow">01 / Self-contained</span><h2>One static core.</h2><p>The kernel, base filesystem, and device components ship in one binary. A small core you can inspect, with recipes and hooks to extend it.</p></div>
  <div><span class="eyebrow">02 / Isolated</span><h2>Wasm-isolated devices.</h2><p>Software fault isolation (SFI) gives the VMM and every device instance a separate WebAssembly sandbox, with scoped access to a thin host API.</p></div>
  <div><span class="eyebrow">03 / Explicit</span><h2>Access is a choice.</h2><p>Host files and network access start closed. Your recipe names the directories, destinations, and capabilities you grant.</p></div>
  <div><span class="eyebrow">04 / Portable</span><h2>Bring your environment.</h2><p>Linux and Windows (x86_64 / ARM64), and macOS on Apple Silicon. Native hypervisors underneath; the same recipes and CLI wherever you work.</p></div>
</section>

<section class="isolation-section" aria-labelledby="isolation-heading">
  <div>
    <p class="eyebrow">Isolation at every layer</p>
    <h2 id="isolation-heading">Your workload in a VM.<br />Its machinery in Wasm.</h2>
    <p>Your agent and tools run inside the VM, on a guest Linux kernel. The virtual machine monitor (VMM) and each device instance run in separate Wasm sandboxes on the host.</p>
    <p>A thin native host API provides checked access to memory, I/O, and hypervisor operations. Each component receives only the capabilities it needs.</p>
    <a href="{base}/docs/security/">Explore the security model <span aria-hidden="true">→</span></a>
  </div>
  <figure class="architecture" aria-labelledby="architecture-caption">
    <div class="vm-boundary">
      <p class="diagram-label">Hardware-isolated VM</p>
      <div class="workload"><strong>Your workload</strong><span>Agent · tools · application</span></div>
      <p class="vm-resources">Guest Linux · vCPUs · memory</p>
    </div>
    <div class="architecture-bridge"><span>VM exits · device requests</span></div>
    <div class="host-runtime">
      <p class="diagram-label">Host · Terra runtime</p>
      <div class="sandbox-grid">
        <div class="wasm-sandbox"><span>Wasm sandbox</span><h3>VMM</h3><p>VM exits &amp; routing</p></div>
        <div class="wasm-sandbox"><span>Wasm sandbox</span><h3>Filesystem</h3><p>Directory grant</p></div>
        <div class="wasm-sandbox"><span>Wasm sandbox</span><h3>Network</h3><p>Allowed sockets</p></div>
        <div class="wasm-sandbox"><span>Wasm sandbox</span><h3>Block</h3><p>Backing disk</p></div>
        <div class="wasm-sandbox"><span>Wasm sandbox</span><h3>Memory</h3><p>Memory reclaim</p></div>
        <div class="wasm-sandbox"><span>Wasm sandbox</span><h3>Vsock</h3><p>Host–guest streams</p></div>
      </div>
      <div class="host-api"><strong>Thin host API</strong><span>Capability checks · memory · native I/O</span></div>
    </div>
    <p class="host-platform">Host OS &amp; hypervisor<br /><span>KVM · Hypervisor.framework · WHP</span></p>
    <figcaption id="architecture-caption">Selected components shown. A separate Wasm sandbox for the VMM and each device instance; a separate Wasm policy component checks access.</figcaption>
  </figure>
</section>

<section id="start" class="start-section">
  <div>
    <p class="eyebrow">From a recipe to a running box</p>
    <h2>Make a little room.</h2>
    {#if releaseTag}<p class="release-note">Current release <a target="_blank" rel="noopener noreferrer" href={`https://github.com/terrarium-sh/terrarium/releases/tag/${releaseTag}`}>{releaseTag}</a></p>{/if}
    <p>Install Terra and save this recipe as <code>dev.yaml</code>. Then set up and enter your box.</p>
    {#if isClient}
      <div class="platform-choice">
        <label for="install-platform">Install for</label>
        <select id="install-platform" bind:value={platform} aria-controls="install-commands">
          <option value="">Choose a platform</option>
          <option value="linux">Linux</option>
          <option value="macos">macOS on Apple Silicon</option>
          <option value="windows">Windows</option>
        </select>
      </div>
      {#if !platform}<p class="small muted">Choose the desktop computer you’ll install Terra on.</p>{/if}
    {/if}
    {#if platform === 'macos'}<p class="small muted">Requires Apple Silicon. Browsers cannot reliably identify your Mac’s processor.</p>{/if}
    <div id="install-commands">
      {#if platform !== 'windows'}
        <h3>{platform === 'macos' ? 'macOS on Apple Silicon · Terminal' : platform === 'linux' ? 'Linux · Terminal' : 'Linux & macOS on Apple Silicon · Terminal'}</h3>
        <pre><code>curl -fsSLO https://raw.githubusercontent.com/terrarium-sh/terrarium/main/install.sh &amp;&amp; sh install.sh</code></pre>
      {/if}
      {#if platform === 'windows' || !platform}
        <h3>Windows · PowerShell</h3>
        <pre><code>Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/terrarium-sh/terrarium/main/install.ps1 -OutFile install.ps1; if ($?) &#123; powershell -ExecutionPolicy Bypass -File install.ps1 &#125;</code></pre>
        <p class="small muted">After installing on Windows, open a new terminal so <code>terra</code> is on your PATH.</p>
      {/if}
    </div>
    <h3>Set up your box</h3>
    <pre><code>terra ./dev.yaml setup
terra</code></pre>
    <a href="{base}/docs/usage/">Read the usage guide <span aria-hidden="true">→</span></a>
  </div>
  <div class="recipe-preview">
    <div class="code-heading"><span class="status-dot"></span><span>dev.yaml</span><span class="muted">your box, your rules</span></div>
    <pre><code><span class="code-key">hw:</span>
  cpus: 2
  mem_mib: 1024

<span class="code-key">network:</span>
  mode: unrestricted-public

<span class="code-key">workload:</span>
  entrypoint: /bin/sh</code></pre>
    <div class="terminal-line"><span aria-hidden="true">$</span> terra ./dev.yaml setup<br /><span aria-hidden="true">$</span> terra</div>
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
