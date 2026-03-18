const { test, expect } = require('@playwright/test');

async function mockSettingsDashboardAPI(page) {
  const state = {
    profile: {
      display_name: 'Admin User',
      email: 'admin@example.com',
      role: 'admin'
    },
    profileUpdates: []
  };

  await page.addInitScript(() => {
    window.EventSource = class FakeEventSource {
      constructor() {}
      addEventListener() {}
      close() {}
    };
    window.localStorage.setItem(
      'baseline.dashboard.settings.usr_admin',
      JSON.stringify({ defaultTab: 'settings', refreshIntervalMs: 30000 })
    );
  });

  await page.route('**/v1/auth/me', async (route) => {
    if (route.request().method() === 'PATCH') {
      const payload = route.request().postDataJSON();
      const displayName = String(payload?.display_name || '').trim();
      state.profile.display_name = displayName;
      state.profileUpdates.push(displayName);
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          display_name: state.profile.display_name,
          email: state.profile.email,
          role: state.profile.role
        })
      });
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        authenticated: true,
        user: state.profile.email,
        display_name: state.profile.display_name,
        user_id: 'usr_admin',
        email: state.profile.email,
        subject: 'usr_admin',
        identity_source: 'supabase',
        role: state.profile.role
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
        email: state.profile.email,
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
      body: JSON.stringify({ items: [] })
    });
  });

  await page.route('**/v1/cli/session?**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ sessions: [] })
    });
  });

  return state;
}

test('settings profile save updates the displayed account name', async ({ page }) => {
  const state = await mockSettingsDashboardAPI(page);

  await page.goto('/dashboard.html');
  await page.getByRole('link', { name: 'Settings' }).click();

  await expect(page.getByRole('heading', { name: 'Account settings' })).toBeVisible();
  await expect(page.locator('#settings-display-name')).toHaveValue('Admin User');

  await page.locator('#settings-display-name').fill('Operations Admin');
  await page.getByRole('button', { name: 'Save name' }).click();

  await expect(page.locator('#settings-display-name')).toHaveValue('Operations Admin');
  await expect(page.locator('#settings-tab')).toContainText('Operations Admin');

  expect(state.profileUpdates).toEqual(['Operations Admin']);
});

test('settings preferences save and reset persist dashboard defaults', async ({ page }) => {
  await mockSettingsDashboardAPI(page);

  await page.goto('/dashboard.html');
  await page.getByRole('link', { name: 'Settings' }).click();

  await expect(page.locator('#settings-default-tab')).toHaveValue('settings');
  await expect(page.locator('#settings-refresh-interval')).toHaveValue('30000');

  await page.locator('#settings-default-tab').selectOption('audit');
  await page.locator('#settings-refresh-interval').selectOption('120000');
  await page.getByRole('button', { name: 'Save preferences' }).click();

  await expect(page.locator('#settings-preferences-feedback')).toHaveText('Saved');
  await expect(page.locator('#settings-default-tab')).toHaveValue('audit');
  await expect(page.locator('#settings-refresh-interval')).toHaveValue('120000');

  const savedPreferences = await page.evaluate(() => JSON.parse(window.localStorage.getItem('baseline.dashboard.settings.usr_admin') || '{}'));
  expect(savedPreferences).toMatchObject({
    defaultTab: 'audit',
    refreshIntervalMs: 120000
  });

  await page.getByRole('button', { name: 'Reset' }).click();

  await expect(page.locator('#settings-preferences-feedback')).toHaveText('Reset to defaults');
  await expect(page.locator('#settings-default-tab')).toHaveValue('overview');
  await expect(page.locator('#settings-refresh-interval')).toHaveValue('60000');

  const resetPreferences = await page.evaluate(() => JSON.parse(window.localStorage.getItem('baseline.dashboard.settings.usr_admin') || '{}'));
  expect(resetPreferences).toMatchObject({
    defaultTab: 'overview',
    refreshIntervalMs: 60000
  });
});
