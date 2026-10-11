import { base } from '$app/paths';

export const prerender = true;

export const GET = ({ url }) =>
	new Response(`User-agent: *\nAllow: /\n\nSitemap: ${url.origin}${base}/sitemap.xml\n`, {
		headers: { 'Content-Type': 'text/plain' }
	});
