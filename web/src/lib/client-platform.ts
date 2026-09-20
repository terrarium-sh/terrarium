export type ClientPlatform = '' | 'linux' | 'macos' | 'windows';

type BrowserPlatform = {
  userAgent: string;
  platform?: string;
  maxTouchPoints?: number;
  userAgentData?: { platform?: string; mobile?: boolean };
};

export function detectClientPlatform(client: BrowserPlatform): ClientPlatform {
  const isMobile = client.userAgentData?.mobile
    || /Android|iPhone|iPad|iPod|CrOS/i.test(client.userAgent)
    || (/Mac/i.test(client.platform || client.userAgent) && (client.maxTouchPoints ?? 0) > 1);
  if (isMobile) return '';

  const platform = client.userAgentData?.platform || `${client.userAgent} ${client.platform ?? ''}`;
  if (/Windows|Win32/i.test(platform)) return 'windows';
  if (/Mac/i.test(platform)) return 'macos';
  if (/Linux/i.test(platform)) return 'linux';
  return '';
}
