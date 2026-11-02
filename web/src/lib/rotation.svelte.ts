import { onMount } from 'svelte';

/** The shown item of a self-advancing showcase; must be constructed during component init. */
export class Rotation {
  active = $state(0);
  isHovered = $state(false);
  isFocused = $state(false);
  isVisible = $state(false);
  canAnimate = $state(false);
  isPaused = $state(false);
  dwellMs = $state(0);
  selectionCount = $state(0);
  readonly isAnimated = $derived(this.canAnimate && !this.isPaused && this.isVisible);
  readonly isCycling = $derived(this.isAnimated && !this.isHovered && !this.isFocused);

  constructor(
    readonly count: number,
    readonly cycleMs: number,
    readonly tappedDwellMs: number
  ) {
    this.dwellMs = cycleMs;
    onMount(() => {
      const motionPreference = matchMedia('(prefers-reduced-motion: reduce)');
      const updateMotionPreference = () => (this.canAnimate = !motionPreference.matches);
      updateMotionPreference();
      motionPreference.addEventListener('change', updateMotionPreference);
      return () => motionPreference.removeEventListener('change', updateMotionPreference);
    });
    $effect(() => {
      if (!this.isCycling) return;
      // Reading `active` re-arms the timer after every step, not only after a tap.
      const next = (this.active + 1) % count;
      void this.selectionCount;
      const timer = setTimeout(() => {
        this.active = next;
        this.dwellMs = cycleMs;
      }, this.dwellMs);
      return () => clearTimeout(timer);
    });
  }

  select(index: number) {
    this.active = index;
    this.dwellMs = this.tappedDwellMs;
    this.selectionCount += 1;
  }

  observeVisibility = (node: HTMLElement) => {
    const observer = new IntersectionObserver(([entry]) => (this.isVisible = entry.isIntersecting), { threshold: 0.3 });
    observer.observe(node);
    return () => observer.disconnect();
  };

  /** Pauses the cycle while a mouse or keyboard focus is inside the element they are spread on. */
  readonly holdWhileEngaged = {
    onfocusin: () => (this.isFocused = true),
    onfocusout: (event: FocusEvent & { currentTarget: HTMLElement }) =>
      (this.isFocused = event.currentTarget.contains(event.relatedTarget as Node | null)),
    onpointerenter: (event: PointerEvent) => event.pointerType === 'mouse' && (this.isHovered = true),
    onpointerleave: (event: PointerEvent) => event.pointerType === 'mouse' && (this.isHovered = false)
  };
}
