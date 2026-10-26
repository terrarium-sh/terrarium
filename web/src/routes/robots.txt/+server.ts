import { resolve } from '$app/paths';

export const prerender = true;

export const GET = ({ url }) =>
	new Response(`User-agent: *\nAllow: /\n\nSitemap: ${new URL(resolve('sitemap.xml'), url)}\n`, {
		headers: { 'Content-Type': 'text/plain' }
	});
