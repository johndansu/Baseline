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

const allScans = [
  {
    id: 'scan_alpha_1',
    project_id: 'alpha_repo',
    status: 'pass',
    commit_sha: '111111111111aaaa',
    files_scanned: 120,
    created_at: '2026-03-16T08:00:00Z',
    violations: []
  },
  {
    id: 'scan_alpha_2',
    project_id: 'alpha_repo',
    status: 'fail',
    commit_sha: '222222222222bbbb',
    files_scanned: 118,
    created_at: '2026-03-16T10:00:00Z',
    violations: [{ id: 'R1' }, { id: 'H1' }]
  },
  {
    id: 'scan_beta_1',
    project_id: 'beta_repo',
    status: 'pass',
    commit_sha: '333333333333cccc',
    files_scanned: 88,
    created_at: '2026-03-16T09:30:00Z',
    violations: []
  }
];

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function mockProjectDashboardAPI(page) {
  await page.addInitScript(() => {
    window.EventSource = class FakeEventSource {
      constructor() {}
      addEventListener() {}
      close() {}
    };
    window.localStorage.setItem(
      'baseline.dashboard.settings.admin@example.com',
      JSON.stringify({ defaultTab: 'projects', refreshIntervalMs: 60000 })
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
          scans: 3,
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

  await page.route('**/v1/projects', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ projects })
    });
  });

  await page.route(/.*\/v1\/scans(?:\?.*)?$/, async (route) => {
    const requestURL = new URL(route.request().url());
    const projectID = requestURL.searchParams.get('project_id');
    if (!projectID) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ scans: allScans })
      });
      return;
    }

    const scans = allScans.filter((scan) => scan.project_id === projectID);
    if (projectID === 'alpha_repo') {
      await sleep(250);
    } else if (projectID === 'beta_repo') {
      await sleep(25);
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ scans })
    });
  });
}

test.beforeEach(async ({ page }) => {
  await mockProjectDashboardAPI(page);
});

test('project details modal shows project summary and can jump to scans', async ({ page }) => {
  await page.goto('/dashboard.html');
  await page.getByRole('link', { name: 'Projects' }).click();

  await expect(page.locator('#page-title')).toHaveText('Projects');
  await expect(page.locator('#projects-tab')).toContainText('Alpha Repo');
  await expect(page.locator('#projects-tab')).toContainText('Beta Repo');

  await page.locator('[data-project-action="view"][data-project-id="alpha_repo"]').click();

  await expect(page.getByRole('heading', { name: 'Project Details' })).toBeVisible();
  await expect(page.locator('#projectDetailsBody')).toContainText('Alpha Repo');
  await expect(page.locator('#projectDetailsBody')).toContainText('https://github.com/example/alpha');
  await expect(page.locator('#projectDetailsBody')).toContainText('1 of 2 scans failed.');
  await expect(page.locator('#projectDetailsBody')).toContainText('Scans');
  await expect(page.locator('#projectDetailsBody')).toContainText('Failures');
  await expect(page.locator('#projectDetailsBody')).toContainText('Recent scans');

  await page.getByRole('button', { name: 'Open Scans' }).click();
  await expect(page.locator('#page-title')).toHaveText('Scan History');
  await expect(page.locator('#projectDetailsModal')).toBeHidden();
});

test('project details modal ignores stale responses when switching projects quickly', async ({ page }) => {
  await page.goto('/dashboard.html');
  await page.getByRole('link', { name: 'Projects' }).click();

  await page.locator('[data-project-action="view"][data-project-id="alpha_repo"]').click();
  await page.locator('[data-project-action="view"][data-project-id="beta_repo"]').evaluate((button) => button.click());

  await expect(page.getByRole('heading', { name: 'Project Details' })).toBeVisible();
  await expect(page.locator('#projectDetailsBody')).toContainText('Loading project summary...');

  await page.waitForTimeout(350);

  await expect(page.locator('#projectDetailsBody')).toContainText('Beta Repo');
  await expect(page.locator('#projectDetailsBody')).toContainText('https://github.com/example/beta');
  await expect(page.locator('#projectDetailsBody')).not.toContainText('Alpha Repo');
  await expect(page.locator('#projectDetailsBody')).not.toContainText('https://github.com/example/alpha');
});
