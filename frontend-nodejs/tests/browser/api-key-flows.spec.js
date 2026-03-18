const { test, expect } = require('@playwright/test');

const users = [
  {
    id: 'usr_admin',
    email: 'admin@example.com',
    display_name: 'Admin User',
    role: 'admin',
    status: 'active',
    last_login_at: '2026-03-17T10:00:00Z'
  }
];

const initialKeys = [
  {
    id: 'key_alpha',
    name: 'Primary deploy key',
    prefix: 'bk_live_1234',
    role: 'operator',
    source: 'dashboard',
    revoked: false,
    owner_user_id: 'usr_admin',
    created_at: '2026-03-16T08:00:00Z'
  },
  {
    id: 'key_old',
    name: 'Old key',
    prefix: 'bk_live_9999',
    role: 'viewer',
    source: 'dashboard',
    revoked: true,
    owner_user_id: 'usr_admin',
    created_at: '2026-03-10T08:00:00Z'
  }
];

async function mockAPIKeyDashboardAPI(page) {
  const state = {
    keys: initialKeys.map((key) => ({ ...key })),
    created: [],
    revoked: [],
    auditEvents: []
  };

  await page.addInitScript(() => {
    window.EventSource = class FakeEventSource {
      constructor() {}
      addEventListener() {}
      close() {}
    };
    window.localStorage.setItem(
      'baseline.dashboard.settings.admin@example.com',
      JSON.stringify({ defaultTab: 'keys', refreshIntervalMs: 60000 })
    );
  });

  await page.route('**/v1/auth/me', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        authenticated: true,
        user: 'admin@example.com',
        display_name: 'Admin User',
        user_id: 'usr_admin',
        email: 'admin@example.com',
        subject: 'usr_admin',
        identity_source: 'supabase',
        role: 'admin'
      })
    });
  });

  await page.route('**/v1/dashboard/capabilities', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        role: 'admin',
        source: 'session',
        email: 'admin@example.com',
        capabilities: {
          'dashboard.view': true,
          'projects.read': true,
          'projects.write': true,
          'scans.read': true,
          'scans.run': true,
          'api_keys.read': true,
          'api_keys.write': true,
          'audit.read': true
        }
      })
    });
  });

  await page.route('**/v1/dashboard?**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        activity_range: 'last_month',
        metrics: {
          scans: 4,
          failing_scans: 1,
          blocking_violations: 2,
          projects: 2
        },
        recent_scans: [],
        scan_activity: [],
        top_violations: []
      })
    });
  });

  await page.route('**/v1/dashboard/activity?**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ items: state.auditEvents })
    });
  });

  await page.route('**/v1/users?**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        users,
        total: users.length,
        limit: 200,
        offset: 0,
        has_more: false
      })
    });
  });

  await page.route('**/v1/me/api-keys', async (route) => {
    const method = route.request().method();
    if (method === 'GET') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ api_keys: state.keys })
      });
      return;
    }

    if (method === 'POST') {
      const payload = route.request().postDataJSON();
      const created = {
        id: `key_created_${state.created.length + 1}`,
        name: String(payload?.name || '').trim() || 'unnamed',
        prefix: `bk_live_new_${state.created.length + 1}`,
        role: String(payload?.role || 'viewer').trim().toLowerCase(),
        source: 'dashboard',
        revoked: false,
        owner_user_id: 'usr_admin',
        created_at: '2026-03-18T12:00:00Z',
        api_key: `baseline_secret_value_${state.created.length + 1}`
      };
      state.keys.unshift({ ...created });
      state.created.push(created);
      state.auditEvents.unshift({
        id: `audit_created_${state.created.length}`,
        action: 'api_key_created',
        actor: 'Admin User',
        project_id: '',
        scan_id: '',
        created_at: created.created_at
      });
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(created)
      });
      return;
    }

    await route.fallback();
  });

  await page.route(/.*\/v1\/me\/api-keys\/[^/]+$/, async (route) => {
    if (route.request().method() !== 'DELETE') {
      await route.fallback();
      return;
    }

    const keyID = decodeURIComponent(route.request().url().split('/').pop() || '');
    state.revoked.push(keyID);
    state.keys = state.keys.map((key) => key.id === keyID ? { ...key, revoked: true } : key);
    state.auditEvents.unshift({
      id: `audit_revoked_${state.revoked.length}`,
      action: 'api_key_revoked',
      actor: 'Admin User',
      project_id: '',
      scan_id: '',
      created_at: '2026-03-18T12:10:00Z'
    });
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ revoked: true, id: keyID })
    });
  });

  await page.route('**/v1/audit/events?**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ events: state.auditEvents, total: state.auditEvents.length })
    });
  });

  return state;
}

test('API keys tab supports generate and revoke flows', async ({ page }) => {
  const state = await mockAPIKeyDashboardAPI(page);

  await page.goto('/dashboard.html');
  await page.getByRole('link', { name: 'API Keys' }).click();

  await expect(page.locator('#page-title')).toHaveText('API Keys');
  await expect(page.locator('#keys-tab')).toContainText('Primary deploy key');

  await page.getByRole('button', { name: 'Generate Key' }).click();
  await expect(page.locator('#generateKeyModal')).toBeVisible();
  await expect(page.locator('#generate-key-role')).toHaveValue('viewer');

  await page.locator('#generate-key-name').fill('Nightly automation');
  await page.getByRole('button', { name: 'Generate Key' }).nth(1).click();

  await expect(page.locator('#copyKeyModal')).toBeVisible();
  await expect(page.locator('#issued-key-value')).toHaveValue('baseline_secret_value_1');
  await expect(page.locator('#issued-key-meta')).toContainText('key_created_1');
  await expect(page.locator('#keys-tab')).toContainText('Nightly automation');
  expect(state.created).toHaveLength(1);

  await page.getByRole('button', { name: 'Done' }).click();
  await expect(page.locator('#copyKeyModal')).toBeHidden();

  await page.getByRole('button', { name: 'Revoke' }).first().click();
  await expect(page.locator('#revokeKeyModal')).toBeVisible();
  await expect(page.locator('#revoke-key-name')).toHaveValue('Nightly automation');

  await page.locator('#revoke-key-reason').fill('rotation schedule');
  await page.locator('#revoke-key-confirm').fill('revoke');
  await page.getByRole('button', { name: 'Revoke Key' }).click();

  await expect(page.locator('#revokeKeyModal')).toBeHidden();
  await expect(page.locator('#keys-tab')).toContainText('Nightly automation');
  await expect(page.locator('#keys-tab')).toContainText('revoked');
  expect(state.revoked).toEqual(['key_created_1']);
});
