const { test, expect } = require('@playwright/test');

const cliSessions = [
  {
    session_id: 'sess_alpha',
    owner_key: 'owner_admin',
    user: 'Admin User',
    email: 'admin@example.com',
    role: 'admin',
    client_name: 'John Laptop',
    client_host: 'DESKTOP-01',
    last_ip: '127.0.0.1',
    cli_version: 'dev',
    last_repository: 'Baseline',
    last_project_id: 'baseline_repo',
    last_command: 'scan',
    last_scan_id: 'scan_123',
    last_used_at: '2026-03-16T10:00:00Z',
    refresh_expires_at: '2026-03-30T10:00:00Z'
  },
  {
    session_id: 'sess_beta',
    owner_key: 'owner_admin',
    user: 'Admin User',
    email: 'admin@example.com',
    role: 'admin',
    client_name: 'Build Agent',
    client_host: 'CI-Runner',
    last_ip: '10.0.0.8',
    cli_version: 'dev',
    last_repository: 'Baseline',
    last_project_id: 'baseline_repo',
    last_command: 'report',
    last_scan_id: '',
    last_used_at: '2026-03-16T09:15:00Z',
    refresh_expires_at: '2026-03-30T09:15:00Z'
  },
  {
    session_id: 'sess_gamma',
    owner_key: 'owner_other',
    user: 'Ops User',
    email: 'ops@example.com',
    role: 'operator',
    client_name: 'Ops Laptop',
    client_host: 'OPS-15',
    last_ip: '10.0.0.19',
    cli_version: 'dev',
    last_repository: 'OtherRepo',
    last_project_id: 'other_repo',
    last_command: 'check',
    last_scan_id: '',
    last_used_at: '2026-03-15T18:20:00Z',
    refresh_expires_at: '2026-03-29T18:20:00Z'
  }
];

const cliSessionDetail = {
  session: {
    session_id: 'sess_alpha',
    owner_key: 'owner_admin',
    user: 'Admin User',
    email: 'admin@example.com',
    role: 'admin',
    client_name: 'John Laptop',
    client_host: 'DESKTOP-01',
    last_ip: '127.0.0.1',
    cli_version: '0.9.0',
    last_repository: 'Baseline',
    last_project_id: 'baseline_repo',
    last_command: 'scan',
    last_scan_id: 'scan_123',
    created_at: '2026-03-16T08:00:00Z',
    approved_at: '2026-03-16T08:00:12Z',
    last_used_at: '2026-03-16T10:00:00Z',
    access_expires_at: '2026-03-16T10:30:00Z',
    refresh_expires_at: '2026-03-30T10:00:00Z'
  },
  risk_signals: [
    {
      id: 'recent_failed_command',
      severity: 'error',
      title: 'Recent command failed',
      detail: 'scan failed at Mon, 16 Mar 2026 10:00:00 UTC.'
    },
    {
      id: 'stale_cli_version',
      severity: 'warning',
      title: 'CLI version differs from current build',
      detail: 'Session last reported CLI 0.9.0 while the current build is dev.'
    }
  ],
  anomaly_flags: [
    {
      id: 'repeated_failures',
      severity: 'error',
      title: 'Repeated command failures',
      detail: '2 recent traced commands ended in error for this session.'
    },
    {
      id: 'multi_target_activity',
      severity: 'warning',
      title: 'Session touched multiple targets recently',
      detail: 'Recent activity spans 2 repositories and 2 projects.'
    }
  ],
  timeline: [
    {
      at: '2026-03-16T10:00:00Z',
      kind: 'trace',
      title: 'CLI command: scan',
      detail: 'Baseline | baseline_repo | scan completed cleanly',
      status: 'ok'
    },
    {
      at: '2026-03-16T08:00:12Z',
      kind: 'session_approved',
      title: 'Session approved',
      detail: 'Admin User',
      status: 'ok'
    }
  ],
  recent_traces: [
    {
      trace_id: 'trc_session_0',
      command: 'report',
      repository: 'OtherRepo',
      project_id: 'other_repo',
      started_at: '2026-03-16T09:56:00Z',
      event_count: 1
    },
    {
      trace_id: 'trc_session_1',
      command: 'scan',
      repository: 'Baseline',
      project_id: 'baseline_repo',
      started_at: '2026-03-16T10:00:00Z',
      event_count: 4
    }
  ]
};

async function mockDashboardSessionAPI(page) {
  const state = {
    sessions: cliSessions.map((session) => ({ ...session })),
    approvedCodes: [],
    revokedSessionIDs: [],
    revokedOwnerKeys: []
  };

  await page.addInitScript(() => {
    window.EventSource = class FakeEventSource {
      constructor() {}
      addEventListener() {}
      close() {}
    };
    window.localStorage.setItem(
      'baseline.dashboard.settings.admin@example.com',
      JSON.stringify({ defaultTab: 'settings', refreshIntervalMs: 60000 })
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

  await page.route('**/v1/cli/session/approve', async (route) => {
    const payload = route.request().postDataJSON();
    state.approvedCodes.push(String(payload?.user_code || ''));
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        approved: true,
        user_code: String(payload?.user_code || ''),
        role: 'admin',
        user: 'Admin User',
        approved_at: '2026-03-16T10:02:00Z'
      })
    });
  });

  await page.route('**/v1/cli/session/owner/**', async (route) => {
    if (route.request().method() !== 'DELETE') {
      await route.fallback();
      return;
    }
    const ownerKey = decodeURIComponent(route.request().url().split('/owner/')[1] || '');
    state.revokedOwnerKeys.push(ownerKey);
    const before = state.sessions.length;
    state.sessions = state.sessions.filter((session) => session.owner_key !== ownerKey);
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ revoked_count: before - state.sessions.length })
    });
  });

  await page.route('**/v1/cli/session/sess_alpha', async (route) => {
    if (route.request().method() === 'GET') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(cliSessionDetail)
      });
      return;
    }
    if (route.request().method() === 'DELETE') {
      state.revokedSessionIDs.push('sess_alpha');
      state.sessions = state.sessions.filter((session) => session.session_id !== 'sess_alpha');
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ revoked: true })
      });
      return;
    }
    await route.fallback();
  });

  await page.route('**/v1/cli/session/sess_beta', async (route) => {
    if (route.request().method() === 'DELETE') {
      state.revokedSessionIDs.push('sess_beta');
      state.sessions = state.sessions.filter((session) => session.session_id !== 'sess_beta');
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ revoked: true })
      });
      return;
    }
    await route.fallback();
  });

  await page.route('**/v1/cli/session/sess_gamma', async (route) => {
    if (route.request().method() === 'DELETE') {
      state.revokedSessionIDs.push('sess_gamma');
      state.sessions = state.sessions.filter((session) => session.session_id !== 'sess_gamma');
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ revoked: true })
      });
      return;
    }
    await route.fallback();
  });

  await page.route('**/v1/cli/session?limit=100', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ sessions: state.sessions })
    });
  });

  return state;
}

test('CLI login bridge opens the existing dashboard approval modal from query URL', async ({ page }) => {
  const state = await mockDashboardSessionAPI(page);

  await page.goto('/cli-login.html?device_code=device-123&user_code=PBMK-NKUA');

  await expect(page.getByRole('heading', { name: 'Approve CLI Login' })).toBeVisible();
  await expect(page.locator('#cli-login-user-code')).toHaveValue('PBMK-NKUA');
  await expect(page.locator('#cli-login-user-code-display')).toHaveText('PBMK-NKUA');

  await page.getByRole('button', { name: 'Approve CLI Session' }).click();

  await expect(page.locator('#cli-login-approval-feedback')).toContainText('CLI session approved');
  await expect.poll(() => state.approvedCodes).toContain('PBMK-NKUA');
});

test('manual CLI approval modal opens blank without query params', async ({ page }) => {
  await mockDashboardSessionAPI(page);

  await page.goto('/dashboard.html');
  await page.getByRole('link', { name: 'Settings' }).click();
  await page.getByRole('button', { name: 'Approve CLI login' }).click();

  await expect(page.getByRole('heading', { name: 'Approve CLI Login' })).toBeVisible();
  await expect(page.locator('#cli-login-user-code')).toHaveValue('');
  await expect(page.locator('#cli-login-user-code-display')).toHaveText('ENTER CODE BELOW');
});

test('CLI login approval page redirects to sign-in and preserves query', async ({ page }) => {
  await page.addInitScript(() => {
  });

  await page.route('**/v1/auth/me', async (route) => {
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ error: { code: 'unauthorized', message: 'Unauthorized' } })
    });
  });

  await page.goto('/cli-login.html?device_code=device-123&user_code=PBMK-NKUA');

  await expect(page).toHaveURL(/\/signin\.html\?return_to=%2Fcli-login\.html%3Fdevice_code%3Ddevice-123%26user_code%3DPBMK-NKUA$/);
});

test('CLI session settings supports detail, single revoke, and revoke-all flows', async ({ page }) => {
  const state = await mockDashboardSessionAPI(page);

  await page.goto('/dashboard.html');
  await page.getByRole('link', { name: 'Settings' }).click();

  await expect(page.getByRole('heading', { name: 'Account settings' })).toBeVisible();
  await expect(page.locator('#settings-cli-sessions-list')).toContainText('John Laptop');
  await expect(page.locator('#settings-cli-sessions-list')).toContainText('Build Agent');
  await expect(page.locator('#settings-cli-sessions-list')).toContainText('Ops Laptop');

  await page.locator('[data-cli-session-view="sess_alpha"]').click();
  await expect(page.getByRole('heading', { name: 'CLI Session Detail' })).toBeVisible();
  await expect(page.locator('#cli-session-detail-content')).toContainText('John Laptop');
  await expect(page.locator('#cli-session-detail-content')).toContainText('scan_123');
  await expect(page.locator('#cli-session-detail-content')).toContainText('Risk signals');
  await expect(page.locator('#cli-session-detail-content')).toContainText('Recent command failed');
  await expect(page.locator('#cli-session-detail-content')).toContainText('Anomaly flags');
  await expect(page.locator('#cli-session-detail-content')).toContainText('Repeated command failures');
  await expect(page.locator('#cli-session-detail-content')).toContainText('Session timeline');
  await expect(page.locator('#cli-session-detail-content')).toContainText('Session approved');
  if (await page.locator('#cliSessionDetailModal [data-close-modal="cliSessionDetailModal"]').isVisible()) {
    await page.locator('#cliSessionDetailModal [data-close-modal="cliSessionDetailModal"]').evaluate((button) => button.click());
  }

  await page.locator('[data-cli-session-revoke="sess_gamma"]').click();
  await expect.poll(() => state.revokedSessionIDs).toContain('sess_gamma');
  await expect(page.locator('#settings-cli-sessions-list')).not.toContainText('Ops Laptop');
  await expect(page.locator('#settings-cli-sessions-feedback')).toContainText('Revoked');

  page.once('dialog', (dialog) => dialog.accept());
  await page.locator('[data-cli-session-revoke-user="owner_admin"]').first().click();
  await expect.poll(() => state.revokedOwnerKeys).toContain('owner_admin');
  await expect(page.locator('#settings-cli-sessions-list')).not.toContainText('John Laptop');
  await expect(page.locator('#settings-cli-sessions-list')).not.toContainText('Build Agent');
  await expect(page.locator('#settings-cli-sessions-list')).toContainText('No active CLI sessions are connected right now.');
});
