import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from './app.js';

// Route registration catches duplicate Fastify routes before the server starts.
test('onboarding routes register and draft agreement downloads without a database', async () => {
  const app = await createApp(null);
  try {
    await app.ready();
    const page = await app.inject({method:'GET',url:'/representative/onboarding/profile'});
    assert.equal(page.statusCode,200);
    assert.match(page.headers['content-type']||'',/text\/html/);
    assert.match(page.body,/Upload agreement PDF/);
    assert.match(page.body,/Submit for review/);
    const pdf=await app.inject({method:'GET',url:'/representative/contractor-agreement/draft.pdf'});
    assert.equal(pdf.statusCode,200);
    assert.match(pdf.headers['content-type']||'',/application\/pdf/);
    assert.equal(pdf.rawPayload.subarray(0,5).toString(),'%PDF-');
    const unauthorized=await app.inject({method:'GET',url:'/admin/representative-onboarding/00000000-0000-0000-0000-000000000000/documents'});
    assert.equal(unauthorized.statusCode,403);
  } finally {
    await app.close();
  }
});
