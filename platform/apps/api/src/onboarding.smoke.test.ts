import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from './app.js';
import { createHash } from 'node:crypto';

// Route registration catches duplicate Fastify routes before the server starts.
test('onboarding routes register and draft agreement downloads without a database', async () => {
  const app = await createApp(null);
  try {
    await app.ready();
    const dashboard=await app.inject({method:'GET',url:'/admin/dashboard'});
    assert.equal(dashboard.statusCode,200);
    assert.match(dashboard.body,/Agreement version register/);
    assert.match(dashboard.body,/agreementVersionDirectory/);
    assert.match(dashboard.body,/id="repSearch"/);
    assert.match(dashboard.body,/function filterRepresentatives/);
    assert.match(dashboard.body,/No representatives match your search/);
    assert.match(dashboard.body,/representativeProfileView/);
    assert.match(dashboard.body,/openRepresentativeProfile/);
    assert.match(dashboard.body,/id="profileReviewDocuments"/);
    assert.match(dashboard.body,/rep-profile-toolbar/);
    assert.match(dashboard.body,/rep-profile-identity/);
    assert.match(dashboard.body,/Back to directory/);
    assert.match(dashboard.body,/id="reviewBackToProfile"/);
    assert.match(dashboard.body,/openProfileOnboardingReview/);
    const deepLink=await app.inject({method:'GET',url:'/admin/dashboard/representatives/00000000-0000-0000-0000-000000000000'});
    assert.equal(deepLink.statusCode,200);
    const repProfile=await app.inject({method:'GET',url:'/admin/representatives/00000000-0000-0000-0000-000000000000/overview'});
    assert.equal(repProfile.statusCode,403);
    const directReview=await app.inject({method:'GET',url:'/admin/representative-onboarding/00000000-0000-0000-0000-000000000000'});
    assert.equal(directReview.statusCode,403);
    const page = await app.inject({method:'GET',url:'/representative/onboarding/profile'});
    assert.equal(page.statusCode,200);
    assert.match(String(page.headers['content-type']||''),/text\/html/);
    assert.match(page.body,/Upload agreement PDF/);
    assert.match(page.body,/Submit for review/);
    const pdf=await app.inject({method:'GET',url:'/representative/contractor-agreement/draft.pdf'});
    assert.equal(pdf.statusCode,200);
    assert.match(String(pdf.headers['content-type']||''),/application\/pdf/);
    assert.equal(pdf.rawPayload.subarray(0,5).toString(),'%PDF-');
    assert.equal(pdf.headers['x-agreement-version'],'1.0-draft');
    assert.equal(pdf.headers['x-document-sha256'],createHash('sha256').update(pdf.rawPayload).digest('hex'));
    const version=await app.inject({method:'GET',url:'/representative/contractor-agreement/version'});
    assert.equal(version.statusCode,403);
    const sign=await app.inject({method:'POST',url:'/representative/contractor-agreement/sign'});
    assert.equal(sign.statusCode,403);
    const unauthorized=await app.inject({method:'GET',url:'/admin/representative-onboarding/00000000-0000-0000-0000-000000000000/documents'});
    assert.equal(unauthorized.statusCode,403);
  } finally {
    await app.close();
  }
});
