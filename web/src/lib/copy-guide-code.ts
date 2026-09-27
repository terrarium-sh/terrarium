import { mount, unmount } from 'svelte';
import CopyButton from './CopyButton.svelte';

export function copyGuideCode(article: HTMLElement) {
  const buttons = Array.from(article.querySelectorAll('pre'), (pre) => {
    const wrapper = document.createElement('div');
    wrapper.className = 'copyable-block';
    pre.parentNode?.insertBefore(wrapper, pre);
    wrapper.append(pre);
    return mount(CopyButton, {
      target: wrapper,
      props: { text: () => pre.textContent?.trimEnd() ?? '' }
    });
  });
  return { destroy: () => buttons.forEach((button) => void unmount(button)) };
}
