const { test, expect } = require('@playwright/test');

const traceList = [
  {
    trace_id: 'trc_err_1',
    command: 'scan',
    repository: 'Baseline',
    project_id: 'baseline_repo',
    scan_id: 'scan_001',
    status: 'error',
    message: 'dashboard upload failed',
    version: 'dev',
    started_at: '2026-03-16T08:00:00Z',
    finished_at: '2026-03-16T08:00:03Z',
    duration_ms: 3000,
    event_count: 4,
    files_scanned: 176,
    security_issues: 1,
    violation_count: 2
  },
  {
    trace_id: 'trc_warn_1',
    command: 'report',
    repository: 'Baseline',
    project_id: 'baseline_repo',
    scan_id: '',
    status: 'warning',
    message: 'report generated with warnings',
    version: 'dev',
    started_at: '2026-03-16T09:00:00Z',
    finished_at: '2026-03-16T09:00:01Z',
    duration_ms: 1200,
    event_count: 3,
    files_scanned: 0,
    security_issues: 0,
    violation_count: 0
  },
  {
    trace_id: 'trc_ok_1',
    command: 'check',
    repository: 'AnotherRepo',
    project_id: 'another_repo',
    scan_id: '',
    status: 'ok',
    message: 'check completed cleanly',
    version: 'dev',
    started_at: '2026-03-15T11:00:00Z',
    finished_at: '2026-03-15T11:00:01Z',
    duration_ms: 900,
    event_count: 2,
    files_scanned: 120,
    security_issues: 0,
    violation_count: 0
  }
];

const traceDetail = {
  summary: traceList[0],
  events: [
    {
      id: 1,
      trace_id: 'trc_err_1',
      span_id: 'spn_root',
      parent_span_id: '',
      type: 'cli_command_started',
      component: 'cli',
      function: 'scan',
      branch: '',
      status: 'started',
      message: 'command invoked',
      attributes: {},
      created_at: '2026-03-16T08:00:00Z'
    },
    {
      id: 2,
      trace_id: 'trc_err_1',
      span_id: 'spn_upload',
      parent_span_id: 'spn_root',
      type: 'cli_branch_taken',
      component: 'cli',
      function: 'uploadScanResults',
      branch: 'dashboard_upload_failed',
      status: 'error',
      message: 'upload rejected with status 403',
      attributes: { project_id: 'baseline_repo' },
      created_at: '2026-03-16T08:00:01Z'
    },
    {
      id: 3,
      trace_id: 'trc_err_1',
      span_id: 'spn_root',
      parent_span_id: '',
      type: 'cli_command_completed',
      component: 'cli',
      function: 'scan',
      branch: '',
      status: 'error',
      message: 'dashboard upload failed',
      attributes: {},
      created_at: '2026-03-16T08:00:03Z'
    }
  ]
};

async function mockDashboardAPI(page) {
  await page.addInitScript(() => {
    window.EventSource = class FakeEventSource {
      constructor() {}
      addEventListener() {}
      close() {}
    };
    window.localStorage.setItem(
      'baseline.dashboard.settings.admin@example.com',
      JSON.stringify({ defaultTab: 'cli', refreshIntervalMs: 60000 })
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
          'audit.read': true,
          'integrations.read': true,
          'integrations.write': true,
          'integrations.secrets.write': true
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
          scans: 6,
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

  await page.route('**/v1/cli/traces?**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ traces: traceList })
    });
  });

  await page.route('**/v1/cli/traces/trc_err_1', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(traceDetail)
    });
  });
}

test.beforeEach(async ({ page }) => {
  await mockDashboardAPI(page);
});

test('CLI trace tab supports filters, drill-down, and reset', async ({ page }) => {
  await page.goto('/dashboard.html');
  await page.getByRole('link', { name: 'CLI Telemetry' }).click();

  await expect(page.getByRole('heading', { name: 'CLI Trace Runs' })).toBeVisible();
  await expect(page.getByText('Errors today')).toBeVisible();
  await expect(page.getByText('Warnings today')).toBeVisible();

  await page.getByRole('button', { name: 'Errors only' }).click();
  await expect(page.getByText('trc_err_1')).toBeVisible();
  await expect(page.getByText('trc_warn_1')).not.toBeVisible();

  await page.getByRole('button', { name: 'Baseline' }).first().click();
  await expect(page.locator('#cli-filter-repository')).toHaveValue('Baseline');
  await expect(page.getByText('trc_err_1')).toBeVisible();
  await expect(page.getByText('trc_ok_1')).not.toBeVisible();

  await page.getByRole('button', { name: 'View trace' }).first().click();
  await expect(page.getByRole('heading', { name: 'CLI Trace Detail' })).toBeVisible();
  await expect(page.locator('#cli-trace-detail-content').getByText('dashboard upload failed').first()).toBeVisible();
  await expect(page.locator('#cli-trace-detail-content').getByText('upload rejected with status 403')).toBeVisible();
  await page.locator('#cliTraceDetailModal [data-close-modal="cliTraceDetailModal"]').click();

  await page.getByRole('button', { name: 'Clear filters' }).click();
  await expect(page.locator('#cli-filter-repository')).toHaveValue('all');
  await expect(page.locator('#cli-filter-project')).toHaveValue('all');
  await expect(page.locator('#cli-filter-status')).toHaveValue('all');
  await expect(page.locator('#cli-filter-command')).toHaveValue('all');
  await expect(page.locator('#cli-tab').getByText('trc_err_1')).toBeVisible();
  await expect(page.locator('#cli-tab').getByText('trc_warn_1')).toBeVisible();
  await expect(page.locator('#cli-tab').getByText('trc_ok_1')).toBeVisible();
});

test('CLI trace tab keeps active filters when returning to the tab', async ({ page }) => {
  await page.goto('/dashboard.html');
  await page.getByRole('link', { name: 'CLI Telemetry' }).click();

  await page.getByRole('button', { name: 'Warnings only' }).click();
  await page.getByRole('button', { name: 'Baseline' }).first().click();

  await expect(page.locator('#cli-filter-repository')).toHaveValue('Baseline');
  await expect(page.locator('#cli-tab').getByText('trc_warn_1')).toBeVisible();
  await expect(page.locator('#cli-tab').getByText('trc_err_1')).not.toBeVisible();
  await expect(page.locator('#cli-tab').getByText('trc_ok_1')).not.toBeVisible();

  await page.getByRole('link', { name: 'Projects' }).click();
  await expect(page.locator('#page-title')).toHaveText('Projects');

  await page.getByRole('link', { name: 'CLI Telemetry' }).click();
  await expect(page.getByRole('heading', { name: 'CLI Trace Runs' })).toBeVisible();
  await expect(page.locator('#cli-filter-repository')).toHaveValue('Baseline');
  await expect(page.locator('#cli-tab').getByText('trc_warn_1')).toBeVisible();
  await expect(page.locator('#cli-tab').getByText('trc_err_1')).not.toBeVisible();
  await expect(page.locator('#cli-tab').getByText('trc_ok_1')).not.toBeVisible();
});
