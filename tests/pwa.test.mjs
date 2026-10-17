import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
const root = new URL('../public/', import.meta.url);
const get = name => readFile(new URL(name, root), 'utf8');
test('stylesheet colors are variables and mobile primary action spans full width', async () => {
  const css = await get('styles.css');
  assert.match(css, /:root\{[^}]*--bg:/);
  assert.match(css, /@media\(prefers-color-scheme:light\)/);
  assert.match(css, /\.actions \.button\.primary\{flex:1 0 100%\}/);
  assert.match(css, /\.severity\.sev-medium,\.severity\.sev-low,\.severity\.sev-info\{color:var\(--dark-text\)\}/);
  assert.doesNotMatch(css.replace(/:root\{[^}]*\}/, '').replace(/@media\(prefers-color-scheme:light\)\{:root\{[^}]*\}\}/, ''), /#[\da-fA-F]{3,8}\b/);
});
test('manifest uses independent maskable asset with shortcuts and no simulated screenshot', async () => {
  const m = JSON.parse(await get('manifest.webmanifest'));
  assert.equal(m.icons.find(i => i.purpose === 'maskable').src, './icon-maskable-512.png');
  assert.equal(m.icons.find(i => i.src === './icon-512.png').purpose, 'any');
  assert.deepEqual(m.shortcuts.map(s => s.url), ['./#scan-heading', './#websiteSection']);
  assert.equal(m.screenshots, undefined);
});
test('service worker leaves external/API/non-GET alone and serves cached while updating', async () => {
  const source = await get('service-worker.js');
  const listeners = {};
  let cacheHit = true, fetched = 0, cachePut = 0, responseValue = 'old';
  const cache = {match: async () => cacheHit ? {value:'old'} : undefined, put: async () => {cachePut++}, addAll: async()=>{}};
  const context = {URL, self:{location:{origin:'https://example.test'},addEventListener:(n,fn)=>listeners[n]=fn,skipWaiting:()=>{},clients:{claim:()=>{}}}, caches:{open:async()=>cache,keys:async()=>[],match:async()=>undefined,delete:async()=>{}}, fetch:async()=>{fetched++;return {ok:true,type:'basic',clone(){return this},value:responseValue}}, Promise};
  vm.runInNewContext(source, context);
  async function dispatch(url, method='GET') { let result; let waited; const request={url,method,mode:'cors'}; const event={request,respondWith:p=>result=p,waitUntil:p=>waited=p};listeners.fetch(event);return {result:result&&await result,waited}; }
  assert.equal((await dispatch('https://other.test/a')).result, undefined);
  assert.equal((await dispatch('https://example.test/api/data')).result, undefined);
  assert.equal((await dispatch('https://example.test/a','POST')).result, undefined);
  const stale=await dispatch('https://example.test/styles.css'); assert.equal(stale.result.value,'old'); await stale.waited; assert.equal(cachePut,1); assert.equal(fetched,1);
  cacheHit=false; const fresh=await dispatch('https://example.test/new.js'); assert.equal(fresh.result.value,'old'); // mocked network response
});
