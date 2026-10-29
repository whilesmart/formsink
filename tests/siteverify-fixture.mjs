import { readFileSync } from 'node:fs';
const fetchOriginal = globalThis.fetch;
globalThis.fetch = (url, options) => {
  if (String(url) === 'https://challenges.cloudflare.com/turnstile/v0/siteverify') {
    return Promise.resolve(new Response(readFileSync(process.env.SITEVERIFY_FIXTURE), { headers: {'Content-Type':'application/json'} }));
  }
  return fetchOriginal(url, options);
};
