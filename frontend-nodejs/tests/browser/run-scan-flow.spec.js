const { test, expect } = require('@playwright/test');

const projects = [
  {
    id: 'alpha_repo',
    name: 'Alpha Repo',
    repository_url: 'https://github.com/example/alpha',
    default_branch: 'main',
    policy_set: 'baseline:prod',
    owner_id: 'usr_admin'
  },
  {
    id: 'beta_repo',
    name: 'Beta Repo',
    repository_url: 'https://github.com/example/beta',
    default_branch: 'develop',
    policy_set: 'baseline:strict',
    owner_id: 'usr_admin'
  }
];

const initialScans = [
  {
    id: 'scan_alpha_1',
    project_id: 'alpha_repo',
    project_name: 'Alpha Repo',
    status: 'pass',
    created_at: '2026-03-16T08:00:00Z',
    violations: [],
    failure_details: '',
    commit_sha: '111111111111aaaa',
    files_scanned: 120
  },
  {
    id: 'scan_beta_1',
    project_id: 'beta_repo',
    project_name: 'Beta Repo',
    status: 'warn',
    created_at: '2026-03-16T09:00:00Z',
    violations: [{ id: 'R1' }],
    failure_details: 'Missing rollback notes',
    commit_sha: '222222222222bbbb',
    files_scanned: 98
  }
];

async function mockRunScanDashboardAPI(page) {
  const state = {
    scans: initialScans.map((scan) => ({ ...scan })),
    createdPayloads: []
  };

  await page.addInitScript(() => {
    window.EventSource = class FakeEventSource {
      constructor() {}
      addEventListener() {}
      close() {}
    };
    window.localStorage.setItem(
      'baseline.dashboard.settings.usr_admin',
      JSON.stringify({ defaultTab: 'scans', refreshIntervalMs: 60000 })
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
          scans: state.scans.length,
          failing_scans: state.scans.filter((scan) => scan.status === 'fail').length,
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

  await page.route('**/v1/projects', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ projects })
    });
  });

  await page.route(/.*\/v1\/scans(?:\?.*)?$/, async (route) => {
    if (route.request().method() === 'POST') {
      const payload = route.request().postDataJSON();
      state.createdPayloads.push(payload);
      const project = projects.find((item) => item.id === payload.project_id);
      const created = {
        id: `scan_created_${state.createdPayloads.length}`,
        project_id: String(payload.project_id || ''),
        project_name: project?.name || String(payload.project_id || ''),
        status: String(payload.status || 'pass'),
        created_at: '2026-03-18T14:00:00Z',
        violations: Array.isArray(payload.violations) ? payload.violations : [],
        failure_details: '',
        commit_sha: String(payload.commit_sha || ''),
        files_scanned: 0
      };
      state.scans.unshift(created);
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(created)
      });
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ scans: state.scans })
    });
  });

  return state;
}

test('run-scan modal loads projects and creates a new scan', async ({ page }) => {
  const state = await mockRunScanDashboardAPI(page);

  await page.goto('/dashboard.html');

  await expect(page.locator('#page-title')).toHaveText('Scan History');
  await expect(page.locator('#scans-tab')).toContainText('Alpha Repo');
  await expect(page.locator('#scans-tab')).toContainText('Beta Repo');

  await page.getByRole('button', { name: 'Run New Scan' }).click();
  await expect(page.locator('#runScanModal')).toBeVisible();
  await expect(page.locator('#run-scan-feedback')).toContainText('Creates a scan record in the backend');
  await expect(page.locator('#run-scan-project')).toContainText('Alpha Repo');
  await expect(page.locator('#run-scan-project')).toContainText('Beta Repo');

  await page.locator('#run-scan-project').selectOption('beta_repo');
  await page.locator('#run-scan-status').selectOption('fail');
  await page.locator('#run-scan-commit-sha').fill('deadbeefcafe1234');
  await page.getByRole('button', { name: 'Start Scan' }).click();

  await expect(page.locator('#runScanModal')).toBeHidden();
  await expect(page.locator('#scans-tab')).toContainText('Beta Repo');
  await expect(page.locator('#scans-tab')).toContainText('FAIL');
  await expect(page.locator('#scans-tab')).toContainText('0 blocking, 0 warnings');
  await expect(page.locator('#scans-page-meta')).toContainText('Showing 1-3 of 3 scans');
  expect(state.createdPayloads).toEqual([
    {
      project_id: 'beta_repo',
      status: 'fail',
      violations: [],
      commit_sha: 'deadbeefcafe1234'
    }
  ]);
});
