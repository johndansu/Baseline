import { DashboardAPIClient } from './api-client.js';

// Baseline Dashboard JavaScript
class BaselineDashboard {
    constructor() {
        this.currentTab = 'overview';
        this.apiClient = new DashboardAPIClient({
            baseURL: window.location.origin,
            onUnauthorized: () => this.handleUnauthorized()
        });
        this.capabilitiesLoaded = false;
        this.authz = {
            role: 'viewer',
            source: 'session',
            capabilities: this.defaultCapabilities()
        };
        this.identity = {
            user: '',
            userID: '',
            email: '',
            subject: ''
        };
        this.chart = null;
        this.scanState = {
            all: [],
            filtered: [],
            page: 1,
            pageSize: 10,
            statusFilter: 'all',
            projectFilter: 'all'
        };
        this.projectState = {
            all: [],
            byID: new Map()
        };
        this.apiKeyState = {
            all: [],
            byID: new Map(),
            mode: 'me',
            targetUserID: '',
            lastPath: '/v1/me/api-keys'
        };
        this.userState = {
            all: [],
            byID: new Map(),
            loaded: false,
            rows: [],
            selected: null,
            selectedActivity: [],
            selectedActivityTotal: 0,
            selectedActivityOffset: 0,
            selectedActivityHasMore: false,
            selectedActivityLimit: 10,
            selectedActivityFilters: {
                eventType: '',
                from: '',
                to: ''
            },
            total: 0,
            offset: 0,
            hasMore: false,
            limit: 100,
            filters: {
                q: '',
                role: 'all',
                status: 'all',
                limit: 100,
                page: 1,
                pageSize: 20,
                sortBy: 'updated_at',
                sortDir: 'desc'
            }
        };
        this.integrationState = {
            events: [],
            jobs: []
        };
        this.userActivityEventTypeCatalog = [];
        this.userActivityEventTypesPromise = null;
        this.pendingProjectEditID = '';
        this.pendingProjectOwnerID = '';
        this.pendingKeyRevokeID = '';
        this.lastIssuedAPIKey = '';
        this.lastIssuedAPIKeyMeta = null;
        this.dashboardSummary = {
            metrics: {},
            recentScans: []
        };
        this.notificationsState = {
            items: [],
            readIDs: new Set()
        };
        this.init();
    }

    handleUnauthorized() {
        const returnTarget = window.location.pathname || '/dashboard';
        const returnTo = encodeURIComponent(returnTarget);
        window.location.href = `/signin.html?return_to=${returnTo}`;
    }

    defaultCapabilities() {
        return {
            'dashboard.view': true,
            'projects.read': true,
            'projects.write': false,
            'scans.read': true,
            'scans.run': false,
            'api_keys.read': true,
            'api_keys.write': false,
            'audit.read': true,
            'integrations.read': true,
            'integrations.write': false,
            'integrations.secrets.write': false
        };
    }

    init() {
        this.setupTabNavigation();
        this.initializeChart();
        this.setupEventListeners();
        this.bindAddProjectForm();
        this.bindProjectOwnerForm();
        this.bindRunScanForm();
        this.bindGenerateKeyForm();
        this.bindRevokeKeyForm();
        this.updateUserUI({});
        this.bootstrap();
    }

    async bootstrap() {
        const authSession = await this.loadAuthSession();
        if (!authSession) {
            return;
        }
        if (authSession.role) {
            this.authz.role = String(authSession.role).toLowerCase() || this.authz.role;
        }
        await this.loadCapabilities();
        if (this.isAdmin()) {
            this.apiKeyState.mode = 'legacy';
        } else {
            this.apiKeyState.mode = 'me';
            this.apiKeyState.targetUserID = '';
        }
        this.applyCapabilitiesToNavigation();
        if (!this.canAccessTab(this.currentTab)) {
            const fallback = this.firstAllowedTab();
            if (fallback) {
                this.currentTab = fallback;
                this.switchTab(fallback);
                return;
            }
        }
        await this.loadDashboardData();
        await this.loadTabData(this.currentTab);
    }

    async loadAuthSession() {
        try {
            const payload = await this.apiRequest('/v1/auth/me');
            if (!payload || payload.authenticated !== true) {
                this.handleUnauthorized();
                return null;
            }
            this.identity = {
                user: String(payload.user || '').trim(),
                userID: String(payload.user_id || '').trim(),
                email: String(payload.email || '').trim().toLowerCase(),
                subject: String(payload.subject || '').trim()
            };
            this.notificationsState.readIDs = this.loadReadNotificationIDs();
            this.updateUserUI({
                email: String(payload.email || ''),
                role: String(payload.role || '')
            });
            return payload;
        } catch (_) {
            this.handleUnauthorized();
            return null;
        }
    }

    async loadCapabilities() {
        try {
            const payload = await this.apiRequest('/v1/dashboard/capabilities');
            const fromServer = payload && typeof payload.capabilities === 'object' && payload.capabilities
                ? payload.capabilities
                : {};
            this.authz = {
                role: String(payload?.role || 'viewer').toLowerCase() || 'viewer',
                source: String(payload?.source || 'session').toLowerCase() || 'session',
                capabilities: {
                    ...this.defaultCapabilities(),
                    ...fromServer
                }
            };
            this.capabilitiesLoaded = true;
            this.updateUserUI({
                email: String(payload?.email || ''),
                role: this.authz.role
            });
        } catch (error) {
            this.authz = {
                role: 'viewer',
                source: 'session',
                capabilities: this.defaultCapabilities()
            };
            this.capabilitiesLoaded = true;
            this.updateUserUI({ role: this.authz.role });
            this.showError(error.message || 'Failed to load capabilities. Running with restricted dashboard mode.');
        }
    }

    hasCapability(capability) {
        return this.authz?.capabilities?.[capability] === true;
    }

    isAdmin() {
        return String(this.authz?.role || '').toLowerCase() === 'admin';
    }

    canAccessTab(tabName) {
        const tab = String(tabName || '').trim();
        switch (tab) {
            case 'overview':
            case 'policies':
            case 'settings':
                return this.hasCapability('dashboard.view');
            case 'scans':
                return this.hasCapability('scans.read');
            case 'projects':
                return this.hasCapability('projects.read');
            case 'users':
                return this.isAdmin() && this.hasCapability('dashboard.view');
            case 'keys':
                return this.hasCapability('api_keys.read');
            case 'integrations':
                return this.hasCapability('integrations.read');
            case 'audit':
                return this.hasCapability('audit.read');
            default:
                return false;
        }
    }

    firstAllowedTab() {
        const orderedTabs = ['overview', 'scans', 'policies', 'projects', 'users', 'keys', 'integrations', 'audit', 'settings'];
        return orderedTabs.find(tab => this.canAccessTab(tab)) || '';
    }

    applyCapabilitiesToNavigation() {
        document.querySelectorAll('a[data-tab]').forEach((item) => {
            const tabName = String(item.dataset.tab || '').trim();
            if (!this.canAccessTab(tabName)) {
                item.classList.add('hidden');
                item.setAttribute('aria-hidden', 'true');
            } else {
                item.classList.remove('hidden');
                item.removeAttribute('aria-hidden');
            }
        });
    }

    setupTabNavigation() {
        const navItems = document.querySelectorAll('a[data-tab]');
        
        navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const tabName = item.dataset.tab;
                this.switchTab(tabName);
            });
        });
    }

    switchTab(tabName) {
        if (this.capabilitiesLoaded && !this.canAccessTab(tabName)) {
            this.showError('You do not have permission to access this section.');
            const fallback = this.firstAllowedTab();
            if (fallback && fallback !== tabName) {
                this.switchTab(fallback);
            }
            return;
        }

        // Update sidebar navigation
        document.querySelectorAll('a[data-tab]').forEach(item => {
            item.classList.remove('bg-blue-50', 'text-blue-700');
            item.classList.add('text-gray-600', 'hover:bg-gray-50', 'hover:text-gray-900');
        });

        const activeItem = document.querySelector(`[data-tab="${tabName}"]`);
        if (activeItem) {
            activeItem.classList.remove('text-gray-600', 'hover:bg-gray-50', 'hover:text-gray-900');
            activeItem.classList.add('bg-blue-50', 'text-blue-700');
        }

        // Hide all tab contents
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.add('hidden');
        });

        // Show selected tab content
        const selectedTab = document.getElementById(`${tabName}-tab`);
        if (selectedTab) {
            selectedTab.classList.remove('hidden');
        }

        // Update page title and subtitle
        this.updatePageHeader(tabName);
        
        // Load tab-specific data
        this.loadTabData(tabName);
        
        this.currentTab = tabName;
    }

    updatePageHeader(tabName) {
        const titles = {
            overview: { title: 'Dashboard', subtitle: 'Monitor policy compliance and scan results' },
            scans: { title: 'Scan History', subtitle: 'View past scan results and enforcement outcomes' },
            policies: { title: 'Policies', subtitle: 'Deterministic production-readiness checks (A1–R1)' },
            projects: { title: 'Projects', subtitle: 'Repositories tracked by Baseline' },
            users: { title: 'Users', subtitle: 'Admin user and role management' },
            keys: { title: 'API Keys', subtitle: 'Manage API authentication keys and tokens' },
            integrations: { title: 'Integrations', subtitle: 'GitHub, GitLab, and webhook connections' },
            audit: { title: 'Audit Log', subtitle: 'Enforcement activity and event trail' },
            settings: { title: 'Settings', subtitle: 'Configure Baseline API and CLI behavior' }
        };

        const meta = titles[tabName] || titles.overview;
        document.getElementById('page-title').textContent = meta.title;
        document.getElementById('page-subtitle').textContent = meta.subtitle;
    }

    initializeChart() {
        const ctx = document.getElementById('usageChart');
        if (!ctx) return;

        this.chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Scans',
                    data: [],
                    borderColor: 'rgb(59, 130, 246)',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4
                }, {
                    label: 'Failing Scans',
                    data: [],
                    borderColor: 'rgb(239, 68, 68)',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            usePointStyle: true,
                            padding: 20,
                            font: {
                                size: 12,
                                weight: '500'
                            },
                            generateLabels: function(chart) {
                                const data = chart.data;
                                if (data.labels.length && data.datasets.length) {
                                    return data.datasets.map(function(dataset, i) {
                                        const meta = chart.getDatasetMeta(i);
                                        return {
                                            text: dataset.label,
                                            fillStyle: dataset.backgroundColor,
                                            strokeStyle: dataset.borderColor,
                                            lineWidth: 3,
                                            pointStyle: 'line',
                                            hidden: meta.hidden,
                                            index: i
                                        };
                                    });
                                }
                                return [];
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    async loadDashboardData() {
        if (!this.hasCapability('dashboard.view')) {
            return;
        }
        await Promise.allSettled([
            this.loadOverviewStats(),
            this.loadRecentActivity()
        ]);
    }

    async loadOverviewStats() {
        try {
            const data = await this.apiRequest('/v1/dashboard');
            const metrics = data && typeof data.metrics === 'object' && data.metrics ? data.metrics : {};
            const recentScans = Array.isArray(data?.recent_scans) ? data.recent_scans : [];
            const topViolations = Array.isArray(data?.top_violations) ? data.top_violations : [];
            this.dashboardSummary = {
                metrics,
                recentScans
            };
            this.updateStatsCards(metrics);
            this.updateUsageChart(recentScans);
            this.updateQuickStatsPanel(metrics, topViolations);
        } catch (error) {
            this.showError(error.message || 'Failed to load dashboard metrics');
        }
    }

    updateStatsCards(metrics) {
        const scansCard = document.getElementById('overview-stat-scans');
        const failingCard = document.getElementById('overview-stat-failing');
        const blockingCard = document.getElementById('overview-stat-blocking');
        const projectsCard = document.getElementById('overview-stat-projects');

        this.setCardMetric(scansCard, metrics.scans ?? 0, 'Total Scans');
        this.setCardMetric(failingCard, metrics.failing_scans ?? 0, 'Failing Scans');
        this.setCardMetric(blockingCard, metrics.blocking_violations ?? 0, 'Blocking Violations');
        this.setCardMetric(projectsCard, metrics.projects ?? 0, 'Projects');

        const deltas = this.computeOverviewDeltas(this.dashboardSummary.recentScans);
        this.setMetricDeltaBadge('overview-stat-scans-badge', deltas.scans);
        this.setMetricDeltaBadge('overview-stat-failing-badge', deltas.failingScans);
        this.setMetricDeltaBadge('overview-stat-blocking-badge', deltas.blockingViolations);
        this.setMetricDeltaBadge('overview-stat-projects-badge', deltas.activeProjects);
    }

    setMetricBadge(id, text, className) {
        const node = document.getElementById(id);
        if (!node) return;
        node.textContent = text;
        node.className = className;
    }

    setMetricDeltaBadge(id, delta) {
        const numericDelta = Number(delta || 0);
        let text = 'Δ 0';
        let className = 'text-xs font-medium text-gray-500 uppercase tracking-wide';
        if (numericDelta > 0) {
            text = `+${numericDelta}`;
            className = 'text-xs font-medium text-green-600 uppercase tracking-wide';
        } else if (numericDelta < 0) {
            text = `${numericDelta}`;
            className = 'text-xs font-medium text-red-600 uppercase tracking-wide';
        }
        this.setMetricBadge(id, text, className);
    }

    computeOverviewDeltas(recentScans) {
        const items = Array.isArray(recentScans) ? recentScans.slice(0, 12) : [];
        const current = items.slice(0, 6);
        const previous = items.slice(6, 12);

        const summarize = (scans) => {
            const activeProjects = new Set();
            let failingScans = 0;
            let blockingViolations = 0;

            scans.forEach((scan) => {
                if (scan?.project_id) {
                    activeProjects.add(scan.project_id);
                }
                const status = String(scan?.status || '').toLowerCase();
                if (status === 'fail' || status === 'failed') {
                    failingScans += 1;
                }
                const violations = Array.isArray(scan?.violations) ? scan.violations : [];
                violations.forEach((violation) => {
                    if (String(violation?.severity || '').toLowerCase() === 'block') {
                        blockingViolations += 1;
                    }
                });
            });

            return {
                scans: scans.length,
                failingScans,
                blockingViolations,
                activeProjects: activeProjects.size
            };
        };

        const currentSummary = summarize(current);
        const previousSummary = summarize(previous);

        return {
            scans: currentSummary.scans - previousSummary.scans,
            failingScans: currentSummary.failingScans - previousSummary.failingScans,
            blockingViolations: currentSummary.blockingViolations - previousSummary.blockingViolations,
            activeProjects: currentSummary.activeProjects - previousSummary.activeProjects
        };
    }

    updateUsageChart(recentScans) {
        if (!this.chart) {
            return;
        }
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const dayKeys = [];
        const labels = [];
        for (let i = 6; i >= 0; i -= 1) {
            const day = new Date(today);
            day.setDate(today.getDate() - i);
            const key = day.toISOString().slice(0, 10);
            dayKeys.push(key);
            labels.push(day.toLocaleDateString(undefined, { weekday: 'short' }));
        }

        const scanCounts = new Map(dayKeys.map((key) => [key, 0]));
        const failingCounts = new Map(dayKeys.map((key) => [key, 0]));
        for (const scan of recentScans) {
            const createdAt = new Date(scan?.created_at || '');
            if (Number.isNaN(createdAt.getTime())) {
                continue;
            }
            const key = createdAt.toISOString().slice(0, 10);
            if (!scanCounts.has(key)) {
                continue;
            }
            scanCounts.set(key, (scanCounts.get(key) || 0) + 1);
            const status = String(scan?.status || '').toLowerCase();
            if (status === 'fail' || status === 'failed') {
                failingCounts.set(key, (failingCounts.get(key) || 0) + 1);
            }
        }

        this.chart.data.labels = labels;
        this.chart.data.datasets[0].data = dayKeys.map((key) => scanCounts.get(key) || 0);
        this.chart.data.datasets[1].data = dayKeys.map((key) => failingCounts.get(key) || 0);
        this.chart.update();
    }

    updateQuickStatsPanel(metrics, topViolations) {
        const scans = Number(metrics?.scans || 0);
        const failing = Number(metrics?.failing_scans || 0);
        const blocking = Number(metrics?.blocking_violations || 0);
        const successRate = scans > 0 ? Math.max(0, Math.min(100, Math.round(((scans - failing) / scans) * 100))) : 100;
        const failRate = scans > 0 ? Math.max(0, Math.min(100, Math.round((failing / scans) * 100))) : 0;

        const successRateValue = document.getElementById('quick-success-rate-value');
        const successRateBar = document.getElementById('quick-success-rate-bar');
        const failRateValue = document.getElementById('quick-fail-rate-value');
        const failRateBar = document.getElementById('quick-fail-rate-bar');
        const topViolationValue = document.getElementById('quick-top-violation-value');
        const topViolationBar = document.getElementById('quick-top-violation-bar');

        if (successRateValue) successRateValue.textContent = `${successRate}%`;
        if (successRateBar) successRateBar.style.width = `${successRate}%`;

        if (failRateValue) failRateValue.textContent = `${failRate}%`;
        if (failRateBar) failRateBar.style.width = `${failRate}%`;

        const top = topViolations.length > 0 ? topViolations[0] : null;
        const topLabel = top ? `${top.policy_id} (${top.count})` : 'None';
        const topPercent = scans > 0 && top ? Math.max(0, Math.min(100, Math.round((Number(top.count || 0) / scans) * 100))) : 0;
        if (topViolationValue) topViolationValue.textContent = topLabel;
        if (topViolationBar) topViolationBar.style.width = `${topPercent}%`;

        const blockingValue = document.getElementById('quick-blocking-count');
        if (blockingValue) {
            blockingValue.textContent = `${blocking}`;
        }
    }

    async loadRecentActivity() {
        if (!this.hasCapability('audit.read')) {
            this.notificationsState.items = [];
            this.updateNotificationsIndicator();
            this.updateActivityLog([]);
            return;
        }
        try {
            const data = await this.apiRequest('/v1/dashboard/activity?limit=10');
            const items = Array.isArray(data.items) ? data.items : [];
            this.notificationsState.items = items;
            this.updateNotificationsIndicator();
            this.updateActivityLog(items);
        } catch (error) {
            this.showError(error.message || 'Failed to load activity');
            this.notificationsState.items = [];
            this.updateNotificationsIndicator();
            this.updateActivityLog([]);
        }
    }

    updateActivityLog(events) {
        const activityContainer = document.querySelector('#overview-tab .divide-y');
        if (!activityContainer) return;

        activityContainer.innerHTML = '';
        if (!events.length) {
            const empty = document.createElement('div');
            empty.className = 'p-4 text-sm text-gray-500';
            empty.textContent = 'No recent activity.';
            activityContainer.appendChild(empty);
            return;
        }

        events.forEach(event => {
            const activityItem = this.createActivityItem(event);
            activityContainer.appendChild(activityItem);
        });
    }

    createActivityItem(event) {
        const div = document.createElement('div');
        div.className = 'p-4 flex items-center justify-between';
        
        const itemType = String(event.type || '').toLowerCase();
        const action = this.describeEventLabel(event);
        const projectText = this.describeActivitySummary(event);
        const statusColor = itemType === 'scan' ? 'green' : itemType === 'integration' ? 'yellow' : 'blue';
        
        div.innerHTML = `
            <div class="flex items-center gap-3">
                <div class="w-2 h-2 bg-${statusColor}-500 rounded-full"></div>
                <div>
                    <p class="text-sm font-medium text-gray-900">${this.escapeHtml(action)}</p>
                    <p class="text-xs text-gray-500">${this.escapeHtml(projectText)}</p>
                </div>
            </div>
            <span class="text-xs text-gray-500">${this.formatDate(event.created_at || event.timestamp)}</span>
        `;
        
        return div;
    }

    updateNotificationsIndicator() {
        const indicator = document.getElementById('notifications-indicator');
        if (!indicator) return;
        const unread = this.getUnreadNotifications();
        if (unread.length > 0) {
            indicator.classList.remove('hidden');
        } else {
            indicator.classList.add('hidden');
        }
    }

    async openNotificationsModal() {
        openModal('notificationsModal');
        if (!this.hasCapability('audit.read')) {
            this.renderNotifications([]);
            return;
        }
        try {
            const data = await this.apiRequest('/v1/dashboard/activity?limit=12');
            const items = Array.isArray(data.items) ? data.items : [];
            this.notificationsState.items = items;
            this.updateNotificationsIndicator();
            this.renderNotifications(this.selectNotifications(items));
        } catch (error) {
            this.showError(error.message || 'Failed to load notifications');
            this.renderNotifications([]);
        }
    }

    renderNotifications(items) {
        const list = document.getElementById('notifications-list');
        const summary = document.getElementById('notifications-summary');
        const markReadButton = document.getElementById('notifications-mark-read-button');
        if (!list) return;

        if (markReadButton && markReadButton.dataset.bound !== '1') {
            markReadButton.dataset.bound = '1';
            markReadButton.addEventListener('click', () => {
                this.markAllNotificationsRead();
            });
        }

        if (summary) {
            summary.innerHTML = '';
        }

        if (!Array.isArray(items) || items.length === 0) {
            if (summary) {
                summary.innerHTML = `<span class="inline-flex items-center px-2.5 py-1 rounded-full bg-gray-100 border border-gray-200 text-gray-600">No important updates</span>`;
            }
            if (markReadButton) {
                markReadButton.disabled = true;
            }
            list.innerHTML = `
                <div class="p-4 rounded-xl border border-gray-200 bg-gray-50 text-sm text-gray-500">
                    No important updates right now.
                </div>
            `;
            return;
        }

        const grouped = this.groupNotifications(items);

        if (summary) {
            const unreadCount = this.countUnreadNotifications(items);
            const chips = [];
            chips.push(`<span class="inline-flex items-center px-2.5 py-1 rounded-full bg-gray-100 border border-gray-200 text-gray-700">${items.length} updates</span>`);
            if (unreadCount > 0) {
                chips.push(`<span class="inline-flex items-center px-2.5 py-1 rounded-full bg-gray-900 text-white">${unreadCount} unread</span>`);
            }
            summary.innerHTML = chips.join('');
        }

        if (markReadButton) {
            markReadButton.disabled = this.countUnreadNotifications(items) === 0;
        }

        list.innerHTML = `
            ${this.renderNotificationSection('Needs review', 'Items that may need your attention soon.', grouped.attention)}
            ${this.renderNotificationSection('Latest updates', 'Recent changes across your projects and access.', grouped.changes)}
        `;

        list.querySelectorAll('[data-notification-tab]').forEach((button) => {
            if (button.dataset.bound === '1') {
                return;
            }
            button.dataset.bound = '1';
            button.addEventListener('click', () => {
                const targetTab = button.getAttribute('data-notification-tab') || 'overview';
                closeModal('notificationsModal');
                this.switchTab(targetTab);
            });
        });
    }

    renderNotificationSection(title, subtitle, items) {
        const body = Array.isArray(items) && items.length > 0
            ? items.map((item) => this.renderNotificationCard(item)).join('')
            : `<div class="p-3 rounded-xl border border-dashed border-gray-200 bg-gray-50 text-sm text-gray-500">Nothing to show here.</div>`;

        return `
            <section class="space-y-2">
                <div>
                    <h4 class="text-sm font-semibold text-gray-900">${this.escapeHtml(title)}</h4>
                    <p class="text-xs text-gray-500 mt-0.5">${this.escapeHtml(subtitle)}</p>
                </div>
                <div class="space-y-2">
                    ${body}
                </div>
            </section>
        `;
    }

    renderNotificationCard(item) {
            const tone = this.notificationTone(item);
            const targetTab = this.notificationTargetTab(item);
            const actionLabel = this.notificationActionLabel(item, targetTab);
            const unread = this.isNotificationUnread(item);
        return `
            <div class="rounded-xl border ${tone.border} bg-white overflow-hidden ${unread ? 'ring-1 ring-offset-0 ring-gray-200' : ''}">
                <button
                    type="button"
                    data-notification-tab="${this.escapeHtml(targetTab)}"
                    class="w-full text-left px-3.5 py-3 hover:bg-gray-50 transition-colors"
                >
                    <div class="flex items-start gap-3">
                        <div class="w-8 h-8 rounded-xl border ${tone.iconBorder} bg-gray-50 flex items-center justify-center flex-shrink-0">
                            <div class="w-2 h-2 rounded-full ${tone.dot}"></div>
                        </div>
                        <div class="flex-1 min-w-0">
                            <div class="flex items-start justify-between gap-3 mb-1">
                                <div class="min-w-0">
                                    <div class="flex items-center gap-2">
                                        <p class="text-sm font-semibold text-gray-900">${this.escapeHtml(this.notificationTitle(item))}</p>
                                        ${unread ? '<span class="inline-flex items-center justify-center w-2.5 h-2.5 rounded-full bg-amber-500" aria-label="Unread notification" title="Unread"></span>' : ''}
                                    </div>
                                    <p class="text-xs text-gray-600 mt-1">${this.escapeHtml(this.notificationSummary(item))}</p>
                                </div>
                                <span class="text-[11px] font-medium whitespace-nowrap text-gray-400">${this.formatDate(item.created_at || item.timestamp)}</span>
                            </div>
                            <div class="mt-2 flex items-center justify-between gap-3">
                                <span class="text-[11px] text-gray-500">${this.escapeHtml(this.notificationTargetLabel(targetTab))}</span>
                                <span class="inline-flex items-center text-[11px] font-medium text-gray-700">${this.escapeHtml(actionLabel)}</span>
                            </div>
                        </div>
                    </div>
                </button>
            </div>
        `;
    }

    groupNotifications(items) {
        const groups = { attention: [], changes: [] };
        for (const item of items) {
            if (this.isAttentionNotification(item)) {
                if (groups.attention.length < 3) {
                    groups.attention.push(item);
                }
                continue;
            }
            if (groups.changes.length < 3) {
                groups.changes.push(item);
            }
        }
        return groups;
    }

    selectNotifications(items) {
        if (!Array.isArray(items)) {
            return [];
        }
        const actionable = items.filter((item) => this.isImportantNotification(item));
        return actionable.slice(0, 8);
    }

    isNotificationUnread(item) {
        const id = String(item?.id || '').trim();
        if (!id) {
            return false;
        }
        return !this.notificationsState.readIDs.has(id);
    }

    countUnreadNotifications(items) {
        return (Array.isArray(items) ? items : []).filter((item) => this.isNotificationUnread(item)).length;
    }

    getUnreadNotifications() {
        const important = this.selectNotifications(this.notificationsState.items);
        return important.filter((item) => this.isNotificationUnread(item));
    }

    markAllNotificationsRead() {
        const important = this.selectNotifications(this.notificationsState.items);
        if (!important.length) {
            return;
        }
        important.forEach((item) => {
            const id = String(item?.id || '').trim();
            if (id) {
                this.notificationsState.readIDs.add(id);
            }
        });
        this.persistReadNotificationIDs();
        this.updateNotificationsIndicator();
        this.renderNotifications(important);
    }

    notificationStorageKey() {
        const identityKey = String(this.identity?.userID || this.identity?.email || this.identity?.subject || this.authz?.role || 'anonymous')
            .trim()
            .toLowerCase();
        return `baseline.notifications.read.${identityKey}`;
    }

    loadReadNotificationIDs() {
        try {
            const raw = window.localStorage.getItem(this.notificationStorageKey());
            if (!raw) {
                return new Set();
            }
            const parsed = JSON.parse(raw);
            if (!Array.isArray(parsed)) {
                return new Set();
            }
            return new Set(parsed.map((value) => String(value || '').trim()).filter(Boolean));
        } catch (_) {
            return new Set();
        }
    }

    persistReadNotificationIDs() {
        try {
            const importantIDs = new Set(
                this.selectNotifications(this.notificationsState.items)
                    .map((item) => String(item?.id || '').trim())
                    .filter(Boolean)
            );
            const retained = Array.from(this.notificationsState.readIDs).filter((id) => importantIDs.has(id));
            window.localStorage.setItem(this.notificationStorageKey(), JSON.stringify(retained));
            this.notificationsState.readIDs = new Set(retained);
        } catch (_) {
            // Ignore storage failures.
        }
    }

    isImportantNotification(item) {
        const action = String(item?.action || item?.event_type || '').toLowerCase();
        const type = String(item?.type || '').toLowerCase();
        if (!action || action === 'dashboard_initialized') {
            return false;
        }
        if (action.includes('fail') || action.includes('blocked') || action.includes('warn') || action.includes('retry')) {
            return true;
        }
        if (action.startsWith('api_key_') || action.startsWith('project_') || action.startsWith('user_')) {
            return true;
        }
        if (action === 'policy_updated' || action === 'ruleset_updated') {
            return true;
        }
        if (type === 'integration' || action.startsWith('integration_') || action.startsWith('github_') || action.startsWith('gitlab_')) {
            return true;
        }
        return false;
    }

    isAttentionNotification(item) {
        const action = String(item?.action || item?.event_type || '').toLowerCase();
        return action.includes('fail') || action.includes('blocked') || action.includes('warn') || action.includes('retry');
    }

    countNotificationGroups(items) {
        return items.reduce((acc, item) => {
            const action = String(item?.action || item?.event_type || '').toLowerCase();
            const type = String(item?.type || '').toLowerCase();
            if (action.includes('fail') || action.includes('blocked') || action.includes('warn') || action.includes('retry')) {
                acc.attention += 1;
            }
            if (type === 'integration' || action.startsWith('integration_') || action.startsWith('github_') || action.startsWith('gitlab_')) {
                acc.integrations += 1;
            }
            if (action.startsWith('api_key_') || action.startsWith('user_')) {
                acc.access += 1;
            }
            return acc;
        }, { attention: 0, integrations: 0, access: 0 });
    }

    notificationTone(item) {
        const action = String(item?.action || item?.event_type || '').toLowerCase();
        if (action.includes('fail') || action.includes('blocked')) {
            return {
                border: 'border-gray-200',
                iconBorder: 'border-red-200',
                dot: 'bg-red-500'
            };
        }
        if (action.includes('warn') || action.includes('retry')) {
            return {
                border: 'border-gray-200',
                iconBorder: 'border-amber-200',
                dot: 'bg-amber-500'
            };
        }
        if (String(item?.type || '').toLowerCase() === 'integration') {
            return {
                border: 'border-gray-200',
                iconBorder: 'border-gray-300',
                dot: 'bg-gray-600'
            };
        }
        return {
            border: 'border-gray-200',
            iconBorder: 'border-gray-300',
            dot: 'bg-gray-500'
        };
    }

    notificationTargetTab(item) {
        const action = String(item?.action || item?.event_type || '').toLowerCase();
        const itemType = String(item?.type || '').toLowerCase();
        if (itemType === 'integration' || action.startsWith('integration_') || action.startsWith('github_') || action.startsWith('gitlab_')) {
            return this.hasCapability('integrations.read') ? 'integrations' : 'audit';
        }
        if (action.startsWith('scan_') || action === 'scan_uploaded' || action === 'enforcement_failed') {
            return this.hasCapability('scans.read') ? 'scans' : 'audit';
        }
        if (action.startsWith('project_')) {
            return this.hasCapability('projects.read') ? 'projects' : 'audit';
        }
        if (action.startsWith('api_key_')) {
            return this.hasCapability('api_keys.read') ? 'keys' : 'audit';
        }
        if (action === 'policy_updated' || action === 'ruleset_updated') {
            return 'policies';
        }
        if (action === 'user_updated' && this.isAdmin()) {
            return 'users';
        }
        return 'audit';
    }

    notificationTargetLabel(tab) {
        const labels = {
            overview: 'overview',
            scans: 'scan history',
            projects: 'projects',
            policies: 'policies',
            users: 'users',
            keys: 'API keys',
            integrations: 'integrations',
            audit: 'audit log',
            settings: 'settings'
        };
        return labels[tab] || 'details';
    }

    notificationActionLabel(item, targetTab) {
        const action = String(item?.action || item?.event_type || '').toLowerCase();
        if (action.includes('fail') || action.includes('blocked')) {
            return 'Review issue';
        }
        if (action.includes('warn') || action.includes('retry')) {
            return 'Check status';
        }
        if (action.startsWith('api_key_')) {
            return 'Open keys';
        }
        if (action.startsWith('project_')) {
            return 'Open project';
        }
        if (action.startsWith('user_')) {
            return 'Review user';
        }
        if (action === 'policy_updated' || action === 'ruleset_updated') {
            return 'Review policy';
        }
        if (String(item?.type || '').toLowerCase() === 'integration' || action.startsWith('integration_') || action.startsWith('github_') || action.startsWith('gitlab_')) {
            return 'Open integration';
        }
        return `Open ${this.notificationTargetLabel(targetTab)}`;
    }

    notificationTitle(item) {
        const action = String(item?.action || item?.event_type || '').toLowerCase();
        const titles = {
            project_registered: 'Project added',
            project_updated: 'Project updated',
            project_owner_claimed: 'Project claimed',
            project_owner_assigned: 'Project owner updated',
            scan_uploaded: 'Scan uploaded',
            scan_pass: 'Checks passed',
            scan_fail: 'Checks failed',
            scan_warn: 'Checks need review',
            enforcement_failed: 'Release blocked',
            api_key_issued: 'API key created',
            api_key_revoked: 'API key removed',
            user_updated: 'Access updated',
            policy_updated: 'Policy changed',
            ruleset_updated: 'Ruleset changed',
            github_webhook_received: 'GitHub sync received',
            gitlab_webhook_received: 'GitLab sync received',
            github_check_published: 'GitHub status sent',
            gitlab_status_published: 'GitLab status sent',
            integration_job_enqueued: 'Integration queued',
            integration_job_retry_scheduled: 'Integration retry queued',
            integration_job_succeeded: 'Integration complete',
            integration_job_failed: 'Integration needs attention',
            integration_secrets_updated: 'Integration credentials updated'
        };
        return titles[action] || this.describeEventLabel(item);
    }

    notificationSummary(item) {
        const action = String(item?.action || item?.event_type || '').toLowerCase();
        const projectID = String(item?.project_id || '').trim();
        const scanID = String(item?.scan_id || '').trim();
        const actor = this.formatActorLabel(item?.actor);

        const join = (...parts) => parts.filter(Boolean).join(' | ');

        switch (action) {
            case 'project_registered':
                return join(projectID ? `${projectID} is now being tracked` : 'A project is now being tracked', actor ? `added by ${actor}` : '');
            case 'project_updated':
                return join(projectID ? `${projectID} settings were updated` : 'Project settings were updated', actor ? `by ${actor}` : '');
            case 'project_owner_claimed':
                return join(projectID ? `${projectID} was claimed` : 'A project was claimed', actor ? `by ${actor}` : '');
            case 'project_owner_assigned':
                return join(projectID ? `${projectID} owner was updated` : 'A project owner was updated', scanID ? `owner ${scanID}` : '');
            case 'scan_uploaded':
                return join(projectID ? `${projectID} has a new scan` : 'A new scan is available', scanID ? `scan ${scanID}` : '');
            case 'scan_pass':
                return join(projectID ? `${projectID}` : 'This project', 'passed the latest checks');
            case 'scan_fail':
                return join(projectID ? `${projectID}` : 'This project', 'has failing checks to fix');
            case 'scan_warn':
                return join(projectID ? `${projectID}` : 'This project', 'has warnings worth reviewing');
            case 'enforcement_failed':
                return join(projectID ? `${projectID}` : 'A release', 'was stopped by a policy rule');
            case 'api_key_issued':
                return join('A new API key is ready to use', actor ? `created by ${actor}` : '');
            case 'api_key_revoked':
                return join('An API key is no longer active', actor ? `removed by ${actor}` : '');
            case 'user_updated':
                return join('Someone’s access or profile details changed', actor ? `updated by ${actor}` : '');
            case 'policy_updated':
                return 'One of your enforcement rules was updated.';
            case 'ruleset_updated':
                return 'The active release rules were updated.';
            case 'integration_job_failed':
                return join(projectID ? `${projectID} integration` : 'An integration', 'failed and may need attention');
            case 'integration_job_retry_scheduled':
                return join(projectID ? `${projectID} integration` : 'An integration', 'will retry automatically');
            case 'integration_job_succeeded':
                return join(projectID ? `${projectID} integration` : 'An integration', 'completed successfully');
            case 'integration_job_enqueued':
                return join(projectID ? `${projectID} integration` : 'An integration', 'is queued');
            case 'github_check_published':
            case 'gitlab_status_published':
                return join(projectID ? `${projectID}` : 'A project', 'sent a status update to your integration');
            case 'github_webhook_received':
            case 'gitlab_webhook_received':
                return join(projectID ? `${projectID}` : 'A project', 'received an update from your integration');
            case 'integration_secrets_updated':
                return 'Integration credentials were updated.';
            default:
                return this.describeActivitySummary(item);
        }
    }

    async loadTabData(tabName) {
        if (!this.canAccessTab(tabName)) {
            return;
        }
        switch (tabName) {
            case 'scans':
                await this.loadScansData();
                break;
            case 'policies':
                await this.loadPoliciesData();
                break;
            case 'projects':
                await this.loadProjectsData();
                break;
            case 'users':
                await this.loadUsersTabData();
                break;
            case 'keys':
                await this.loadApiKeysData();
                break;
            case 'integrations':
                await this.loadIntegrationsData();
                break;
            case 'audit':
                await this.loadAuditData();
                break;
            case 'settings':
                await this.loadSettingsData();
                break;
        }
    }

    async loadScansData() {
        try {
            const [scanPayload, projectPayload] = await Promise.all([
                this.apiRequest('/v1/scans'),
                this.apiRequest('/v1/projects')
            ]);

            const projects = Array.isArray(projectPayload.projects) ? projectPayload.projects : [];
            const projectNamesByID = new Map();
            projects.forEach(project => {
                if (project && project.id) {
                    projectNamesByID.set(project.id, project.name || project.id);
                }
            });

            const scans = Array.isArray(scanPayload.scans) ? scanPayload.scans : [];
            this.scanState.all = scans
                .map(scan => {
                    const violations = Array.isArray(scan.violations) ? scan.violations : [];
                    const blockingViolations = violations.filter(v => String(v.severity || '').toLowerCase() === 'block').length;
                    const warnings = violations.filter(v => String(v.severity || '').toLowerCase() === 'warn').length;
                    return {
                        id: scan.id || '',
                        project_id: scan.project_id || '',
                        project_name: projectNamesByID.get(scan.project_id) || scan.project_id || 'Unknown',
                        status: String(scan.status || '').toLowerCase() || 'unknown',
                        violations: violations.length,
                        blocking_violations: blockingViolations,
                        warnings: warnings,
                        first_violation: violations.length ? violations[0].message || violations[0].policy_id || 'Violation detected' : '',
                        created_at: scan.created_at || ''
                    };
                })
                .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
            this.scanState.page = 1;
            this.scanState.statusFilter = 'all';
            this.scanState.projectFilter = 'all';
            this.renderScansTable(this.scanState.all);
        } catch (error) {
            this.showError(error.message || 'Failed to load scan history');
            this.scanState.all = [];
            this.renderScansTable([]);
        }
    }

    bindAddProjectForm() {
        const form = document.getElementById('add-project-form');
        if (!form || form.dataset.bound === '1') {
            return;
        }
        form.dataset.bound = '1';
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            await this.submitAddProjectForm();
        });
    }

    prepareAddProjectModal() {
        if (!this.hasCapability('projects.write')) {
            this.showError('Project write access is required.');
            closeModal('addProjectModal');
            return;
        }
        this.bindAddProjectForm();

        const form = document.getElementById('add-project-form');
        const title = document.getElementById('add-project-modal-title');
        const nameInput = document.getElementById('add-project-name');
        const repoInput = document.getElementById('add-project-repo');
        const branchInput = document.getElementById('add-project-branch');
        const policySetInput = document.getElementById('add-project-policy-set');
        const submitButton = document.getElementById('add-project-submit');

        if (!form || !nameInput || !repoInput || !branchInput || !policySetInput) {
            return;
        }

        const pendingID = String(this.pendingProjectEditID || '').trim();
        const project = pendingID ? this.projectState.byID.get(pendingID) : null;
        this.pendingProjectEditID = '';

        if (project) {
            form.dataset.mode = 'edit';
            form.dataset.projectId = project.id;
            if (title) title.textContent = 'Edit Project';
            nameInput.value = project.name || '';
            repoInput.value = project.repository_url || '';
            branchInput.value = project.default_branch || 'main';
            policySetInput.value = project.policy_set || 'baseline:prod';
            this.setAddProjectFeedback(`Updating project ${project.name || project.id}.`, false);
        } else {
            form.dataset.mode = 'create';
            delete form.dataset.projectId;
            if (title) title.textContent = 'Add New Project';
            nameInput.value = '';
            repoInput.value = '';
            branchInput.value = 'main';
            policySetInput.value = 'baseline:prod';
            this.setAddProjectFeedback('Creates a new project and refreshes dashboard data.', false);
        }
        if (submitButton) submitButton.disabled = false;
    }

    setAddProjectFeedback(message, isError) {
        const feedback = document.getElementById('add-project-feedback');
        if (!feedback) {
            return;
        }
        feedback.textContent = message;
        feedback.className = isError ? 'text-xs text-red-600' : 'text-xs text-gray-500';
    }

    async submitAddProjectForm() {
        if (!this.hasCapability('projects.write')) {
            this.showError('Project write access is required.');
            return;
        }
        const form = document.getElementById('add-project-form');
        const nameInput = document.getElementById('add-project-name');
        const repoInput = document.getElementById('add-project-repo');
        const branchInput = document.getElementById('add-project-branch');
        const policySetInput = document.getElementById('add-project-policy-set');
        const submitButton = document.getElementById('add-project-submit');

        if (!form || !nameInput || !repoInput || !branchInput || !policySetInput) {
            this.showError('Add Project form is not available.');
            return;
        }

        const name = String(nameInput.value || '').trim();
        const repositoryURL = String(repoInput.value || '').trim();
        const defaultBranch = String(branchInput.value || '').trim() || 'main';
        const policySet = String(policySetInput.value || '').trim() || 'baseline:prod';

        if (!name) {
            this.setAddProjectFeedback('Project name is required.', true);
            return;
        }
        if (/\s/.test(defaultBranch)) {
            this.setAddProjectFeedback('Default branch cannot contain whitespace.', true);
            return;
        }
        if (/\s/.test(policySet)) {
            this.setAddProjectFeedback('Policy set cannot contain whitespace.', true);
            return;
        }

        const payload = {
            name: name,
            repository_url: repositoryURL,
            default_branch: defaultBranch,
            policy_set: policySet
        };
        const isEdit = String(form.dataset.mode || 'create') === 'edit';
        const projectID = String(form.dataset.projectId || '').trim();
        if (isEdit && !projectID) {
            this.setAddProjectFeedback('Missing project identifier for update.', true);
            return;
        }
        const method = isEdit ? 'PUT' : 'POST';
        const path = isEdit ? `/v1/projects/${encodeURIComponent(projectID)}` : '/v1/projects';

        if (submitButton) submitButton.disabled = true;
        this.setAddProjectFeedback(isEdit ? 'Submitting project update...' : 'Submitting project creation...', false);

        try {
            const created = await this.apiRequest(path, {
                method: method,
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            closeModal('addProjectModal');
            await Promise.allSettled([
                this.loadDashboardData(),
                this.loadProjectsData()
            ]);
            const createdName = created && created.name ? ` ${created.name}` : '';
            this.showSuccess(isEdit
                ? `Project${createdName} updated successfully.`
                : `Project${createdName} created successfully.`);
        } catch (error) {
            this.setAddProjectFeedback(error.message || (isEdit ? 'Failed to update project.' : 'Failed to create project.'), true);
            this.showError(error.message || (isEdit ? 'Failed to update project.' : 'Failed to create project.'));
        } finally {
            if (submitButton) submitButton.disabled = false;
        }
    }

    openEditProjectModal(projectID) {
        if (!this.hasCapability('projects.write')) {
            this.showError('Project write access is required.');
            return;
        }
        const normalizedID = String(projectID || '').trim();
        if (!normalizedID) {
            this.showError('Invalid project selected.');
            return;
        }
        if (!this.projectState.byID.has(normalizedID)) {
            this.showError('Project details not loaded yet.');
            return;
        }
        this.pendingProjectEditID = normalizedID;
        openModal('addProjectModal');
    }

    bindProjectOwnerForm() {
        const form = document.getElementById('project-owner-form');
        if (!form || form.dataset.bound === '1') {
            return;
        }
        form.dataset.bound = '1';
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            await this.submitProjectOwnerForm();
        });
    }

    async prepareProjectOwnerModal() {
        if (!this.isAdmin()) {
            this.showError('Admin access is required.');
            closeModal('projectOwnerModal');
            return;
        }
        this.bindProjectOwnerForm();
        const projectID = String(this.pendingProjectOwnerID || '').trim();
        if (!projectID) {
            this.showError('Project owner assignment is missing a project.');
            closeModal('projectOwnerModal');
            return;
        }

        await this.loadUsersData();
        const project = this.projectState.byID.get(projectID);
        if (!project) {
            this.showError('Project details are not available.');
            closeModal('projectOwnerModal');
            return;
        }

        const title = document.getElementById('project-owner-modal-title');
        const projectLabel = document.getElementById('project-owner-project-label');
        const currentOwner = document.getElementById('project-owner-current-owner');
        const select = document.getElementById('project-owner-user-select');
        const submitButton = document.getElementById('project-owner-submit');

        if (title) title.textContent = 'Assign Project Owner';
        if (projectLabel) projectLabel.textContent = project.name || project.id || 'Project';
        if (currentOwner) currentOwner.textContent = this.describeProjectOwner(project.owner_id);
        if (select) {
            const options = this.userState.all
                .filter((user) => String(user?.id || '').trim())
                .sort((a, b) => String(a.email || a.display_name || a.id || '').localeCompare(String(b.email || b.display_name || b.id || '')))
                .map((user) => {
                    const userID = String(user.id || '').trim();
                    const selected = String(project.owner_id || '').toLowerCase() === `user:${userID.toLowerCase()}` ? ' selected' : '';
                    const label = user.email || user.display_name || userID;
                    return `<option value="${this.escapeHtml(userID)}"${selected}>${this.escapeHtml(label)}</option>`;
                });
            const currentOwnerID = this.currentPrincipalOwnerID();
            if (currentOwnerID.startsWith('user:')) {
                const currentUserID = currentOwnerID.slice('user:'.length);
                const exists = this.userState.all.some((user) => String(user?.id || '').trim().toLowerCase() === currentUserID.toLowerCase());
                if (!exists) {
                    const selected = String(project.owner_id || '').toLowerCase() === currentOwnerID.toLowerCase() ? ' selected' : '';
                    options.unshift(`<option value="${this.escapeHtml(currentUserID)}"${selected}>You (${this.escapeHtml(this.identity.email || this.identity.user || currentUserID)})</option>`);
                }
            }
            select.innerHTML = `<option value="">Select a user</option>${options.join('')}`;
        }
        if (submitButton) submitButton.disabled = false;
        this.setProjectOwnerFeedback('Choose the user who should own new scans for this project.', false);
    }

    setProjectOwnerFeedback(message, isError) {
        const feedback = document.getElementById('project-owner-feedback');
        if (!feedback) {
            return;
        }
        feedback.textContent = message;
        feedback.className = isError ? 'text-xs text-red-600' : 'text-xs text-gray-500';
    }

    async submitProjectOwnerForm() {
        if (!this.isAdmin()) {
            this.showError('Admin access is required.');
            return;
        }
        const projectID = String(this.pendingProjectOwnerID || '').trim();
        const select = document.getElementById('project-owner-user-select');
        const submitButton = document.getElementById('project-owner-submit');
        if (!projectID || !select) {
            this.showError('Project owner form is not available.');
            return;
        }
        const userID = String(select.value || '').trim();
        if (!userID) {
            this.setProjectOwnerFeedback('Select a user to continue.', true);
            return;
        }

        if (submitButton) submitButton.disabled = true;
        this.setProjectOwnerFeedback('Assigning project owner...', false);
        try {
            const updated = await this.apiRequest(`/v1/projects/${encodeURIComponent(projectID)}/owner`, {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ user_id: userID })
            });
            closeModal('projectOwnerModal');
            this.pendingProjectOwnerID = '';
            await Promise.allSettled([
                this.loadDashboardData(),
                this.loadProjectsData()
            ]);
            this.showSuccess(`Project owner updated to ${this.describeProjectOwner(updated?.owner_id || '')}.`);
        } catch (error) {
            this.setProjectOwnerFeedback(error.message || 'Failed to assign project owner.', true);
            this.showError(error.message || 'Failed to assign project owner.');
        } finally {
            if (submitButton) submitButton.disabled = false;
        }
    }

    async claimProject(projectID) {
        const normalizedID = String(projectID || '').trim();
        if (!normalizedID) {
            this.showError('Invalid project selected.');
            return;
        }
        try {
            const updated = await this.apiRequest(`/v1/projects/${encodeURIComponent(normalizedID)}/claim`, {
                method: 'POST'
            });
            await Promise.allSettled([
                this.loadDashboardData(),
                this.loadProjectsData()
            ]);
            this.showSuccess(`Project now belongs to ${this.describeProjectOwner(updated?.owner_id || this.currentPrincipalOwnerID())}.`);
        } catch (error) {
            this.showError(error.message || 'Failed to claim project.');
        }
    }

    openProjectOwnerModal(projectID) {
        if (!this.isAdmin()) {
            this.showError('Admin access is required.');
            return;
        }
        const normalizedID = String(projectID || '').trim();
        if (!normalizedID) {
            this.showError('Invalid project selected.');
            return;
        }
        this.pendingProjectOwnerID = normalizedID;
        openModal('projectOwnerModal');
    }

    currentPrincipalOwnerID() {
        if (this.identity.userID) {
            return `user:${String(this.identity.userID).trim().toLowerCase()}`;
        }
        if (this.identity.subject) {
            return `sub:${String(this.identity.subject).trim().toLowerCase()}`;
        }
        if (this.identity.email) {
            return `email:${String(this.identity.email).trim().toLowerCase()}`;
        }
        if (this.identity.user) {
            return `user:${String(this.identity.user).trim().toLowerCase()}`;
        }
        return '';
    }

    describeProjectOwner(ownerID) {
        const normalized = String(ownerID || '').trim();
        if (!normalized) {
            return 'Unassigned';
        }
        if (normalized.toLowerCase() === this.currentPrincipalOwnerID()) {
            return 'You';
        }
        if (normalized.startsWith('user:')) {
            const userID = normalized.slice('user:'.length);
            const user = this.userState.byID.get(userID) || this.userState.byID.get(userID.toLowerCase()) || null;
            if (user) {
                return user.email || user.display_name || user.id || normalized;
            }
            return `User ${userID}`;
        }
        if (normalized.startsWith('email:')) {
            return normalized.slice('email:'.length);
        }
        if (normalized.startsWith('sub:')) {
            return 'Linked identity';
        }
        if (normalized.startsWith('api_key:')) {
            return `API key ${normalized.slice('api_key:'.length)}`;
        }
        return normalized;
    }

    bindGenerateKeyForm() {
        const form = document.getElementById('generate-key-form');
        if (!form || form.dataset.bound === '1') {
            return;
        }
        form.dataset.bound = '1';
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            await this.submitGenerateKeyForm();
        });

        const copyButton = document.getElementById('issued-key-copy-btn');
        if (copyButton && copyButton.dataset.bound !== '1') {
            copyButton.dataset.bound = '1';
            copyButton.addEventListener('click', async () => {
                await this.copyIssuedAPIKey();
            });
        }
    }

    prepareGenerateKeyModal() {
        if (!this.hasCapability('api_keys.write')) {
            this.showError('API key write access is required.');
            closeModal('generateKeyModal');
            return;
        }
        this.bindGenerateKeyForm();
        const nameInput = document.getElementById('generate-key-name');
        const roleSelect = document.getElementById('generate-key-role');
        const submitButton = document.getElementById('generate-key-submit');
        if (!nameInput || !roleSelect) {
            return;
        }
        nameInput.value = '';
        const roleOptions = this.allowedRoleOptionsForCurrentScope();
        roleSelect.innerHTML = roleOptions
            .map(role => `<option value="${this.escapeHtml(role)}">${this.escapeHtml(role.charAt(0).toUpperCase() + role.slice(1))}</option>`)
            .join('');
        roleSelect.value = roleOptions[0] || 'viewer';
        if (submitButton) submitButton.disabled = false;
        const scope = this.resolveAPIKeyScope();
        const scopeLabel = scope.mode === 'user'
            ? `selected user (${this.apiKeyScopeUserLabel()})`
            : scope.mode === 'me'
                ? 'your account'
                : 'global admin scope';
        this.setGenerateKeyFeedback(`Generated key value is shown once. Scope: ${scopeLabel}.`, false);
    }

    setGenerateKeyFeedback(message, isError) {
        const feedback = document.getElementById('generate-key-feedback');
        if (!feedback) {
            return;
        }
        feedback.textContent = message;
        feedback.className = isError ? 'text-xs text-red-600' : 'text-xs text-gray-500';
    }

    allowedRoleOptionsForCurrentScope() {
        const scope = this.resolveAPIKeyScope();
        if (scope.mode === 'legacy') {
            return ['viewer', 'operator', 'admin'];
        }

        let maxRole = String(this.authz?.role || 'viewer').toLowerCase();
        if (scope.mode === 'user') {
            const userID = String(this.apiKeyState.targetUserID || '').trim();
            const user = this.userState.byID.get(userID);
            if (user && user.role) {
                maxRole = String(user.role).toLowerCase();
            }
        }
        if (maxRole === 'admin') {
            return ['viewer', 'operator', 'admin'];
        }
        if (maxRole === 'operator') {
            return ['viewer', 'operator'];
        }
        return ['viewer'];
    }

    apiKeyScopeUserLabel() {
        const userID = String(this.apiKeyState.targetUserID || '').trim();
        if (!userID) {
            return '';
        }
        const user = this.userState.byID.get(userID);
        if (!user) {
            return userID;
        }
        return String(user.email || user.display_name || user.id || userID);
    }

    async submitGenerateKeyForm() {
        if (!this.hasCapability('api_keys.write')) {
            this.showError('API key write access is required.');
            return;
        }
        const nameInput = document.getElementById('generate-key-name');
        const roleSelect = document.getElementById('generate-key-role');
        const submitButton = document.getElementById('generate-key-submit');
        if (!nameInput || !roleSelect) {
            this.showError('Generate Key form is not available.');
            return;
        }

        const name = String(nameInput.value || '').trim();
        const role = String(roleSelect.value || 'viewer').trim().toLowerCase();
        const allowedRoles = this.allowedRoleOptionsForCurrentScope();
        if (!allowedRoles.includes(role)) {
            this.setGenerateKeyFeedback('Invalid role selected.', true);
            return;
        }

        const payload = {
            name: name,
            role: role
        };

        if (submitButton) submitButton.disabled = true;
        this.setGenerateKeyFeedback('Issuing API key...', false);

        try {
            const scope = this.resolveAPIKeyScope();
            const created = await this.apiRequest(scope.createPath, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            closeModal('generateKeyModal');
            await Promise.allSettled([
                this.loadDashboardData(),
                this.loadApiKeysData(),
                this.loadAuditData()
            ]);
            this.openIssuedKeyModal(created);
            this.showSuccess('API key generated successfully.');
        } catch (error) {
            this.setGenerateKeyFeedback(error.message || 'Failed to generate API key.', true);
            this.showError(error.message || 'Failed to generate API key.');
        } finally {
            if (submitButton) submitButton.disabled = false;
        }
    }

    openIssuedKeyModal(created) {
        const keyValue = String(created?.api_key || '').trim();
        this.lastIssuedAPIKey = keyValue;
        this.lastIssuedAPIKeyMeta = created || null;

        const keyField = document.getElementById('issued-key-value');
        const metaField = document.getElementById('issued-key-meta');
        if (keyField) {
            keyField.value = keyValue || 'No key value returned.';
        }
        if (metaField) {
            const id = created?.id ? `id=${created.id}` : '';
            const role = created?.role ? `role=${created.role}` : '';
            const prefix = created?.prefix ? `prefix=${created.prefix}` : '';
            const parts = [id, role, prefix].filter(Boolean);
            metaField.textContent = parts.length ? parts.join(' | ') : '';
        }
        openModal('copyKeyModal');
    }

    async copyIssuedAPIKey() {
        const keyValue = String(this.lastIssuedAPIKey || '').trim();
        if (!keyValue) {
            this.showError('No issued API key value available to copy.');
            return;
        }
        try {
            await navigator.clipboard.writeText(keyValue);
            this.showSuccess('API key copied to clipboard.');
        } catch (_) {
            this.showError('Unable to copy API key. Copy it manually.');
        }
    }

    bindRevokeKeyForm() {
        const form = document.getElementById('revoke-key-form');
        if (!form || form.dataset.bound === '1') {
            return;
        }
        form.dataset.bound = '1';
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            await this.submitRevokeKeyForm();
        });
    }

    openRevokeKeyModal(keyID) {
        if (!this.hasCapability('api_keys.write')) {
            this.showError('API key write access is required.');
            return;
        }
        const normalizedID = String(keyID || '').trim();
        if (!normalizedID) {
            this.showError('Invalid key selected.');
            return;
        }
        if (!this.apiKeyState.byID.has(normalizedID)) {
            this.showError('API key details not loaded yet.');
            return;
        }
        this.pendingKeyRevokeID = normalizedID;
        openModal('revokeKeyModal');
    }

    prepareRevokeKeyModal() {
        if (!this.hasCapability('api_keys.write')) {
            this.showError('API key write access is required.');
            closeModal('revokeKeyModal');
            return;
        }
        this.bindRevokeKeyForm();
        const key = this.apiKeyState.byID.get(String(this.pendingKeyRevokeID || '').trim());
        const nameField = document.getElementById('revoke-key-name');
        const prefixField = document.getElementById('revoke-key-prefix');
        const reasonField = document.getElementById('revoke-key-reason');
        const confirmField = document.getElementById('revoke-key-confirm');
        const submitButton = document.getElementById('revoke-key-submit');
        if (!nameField || !prefixField || !reasonField || !confirmField) {
            return;
        }

        if (!key) {
            nameField.value = '';
            prefixField.value = '';
            reasonField.value = '';
            confirmField.value = '';
            if (submitButton) submitButton.disabled = true;
            this.setRevokeKeyFeedback('No API key selected for revocation.', true);
            return;
        }

        nameField.value = key.name || 'unnamed';
        prefixField.value = key.prefix || '';
        reasonField.value = '';
        confirmField.value = '';
        if (submitButton) submitButton.disabled = !!key.revoked;
        if (key.revoked) {
            this.setRevokeKeyFeedback('This key is already revoked.', true);
        } else {
            this.setRevokeKeyFeedback('Type revoke and provide a reason to continue.', false);
        }
    }

    setRevokeKeyFeedback(message, isError) {
        const feedback = document.getElementById('revoke-key-feedback');
        if (!feedback) {
            return;
        }
        feedback.textContent = message;
        feedback.className = isError ? 'text-xs text-red-600' : 'text-xs text-gray-500';
    }

    async requestSensitiveReauthToken() {
        const payload = await this.apiRequest('/v1/auth/reauth', {
            method: 'POST'
        });
        const token = String(payload?.reauth_token || '').trim();
        if (!token) {
            throw new Error('Re-auth token was not returned by server.');
        }
        return token;
    }

    async submitRevokeKeyForm() {
        if (!this.hasCapability('api_keys.write')) {
            this.showError('API key write access is required.');
            return;
        }
        const keyID = String(this.pendingKeyRevokeID || '').trim();
        const reasonField = document.getElementById('revoke-key-reason');
        const confirmField = document.getElementById('revoke-key-confirm');
        const submitButton = document.getElementById('revoke-key-submit');
        if (!keyID || !reasonField || !confirmField) {
            this.showError('Revoke Key form is not available.');
            return;
        }

        const reason = String(reasonField.value || '').trim();
        const confirmation = String(confirmField.value || '').trim().toLowerCase();
        if (!reason) {
            this.setRevokeKeyFeedback('Reason is required.', true);
            return;
        }
        if (reason.length > 256) {
            this.setRevokeKeyFeedback('Reason must be 256 characters or less.', true);
            return;
        }
        if (confirmation !== 'revoke') {
            this.setRevokeKeyFeedback('Type revoke to confirm.', true);
            return;
        }

        const baseHeaders = {
            'X-Baseline-Confirm': 'revoke_api_key',
            'X-Baseline-Reason': reason
        };
        const scope = this.resolveAPIKeyScope();
        const revokePath = `${scope.revokePathPrefix}/${encodeURIComponent(keyID)}`;

        if (submitButton) submitButton.disabled = true;
        this.setRevokeKeyFeedback('Revoking API key...', false);

        try {
            await this.apiRequest(revokePath, {
                method: 'DELETE',
                headers: baseHeaders
            });
        } catch (error) {
            const needsReauth = Number(error?.status) === 428 && String(error?.code || '') === 'reauth_required';
            if (!needsReauth) {
                this.setRevokeKeyFeedback(error.message || 'Failed to revoke API key.', true);
                this.showError(error.message || 'Failed to revoke API key.');
                if (submitButton) submitButton.disabled = false;
                return;
            }
            try {
                const reauthToken = await this.requestSensitiveReauthToken();
                await this.apiRequest(revokePath, {
                    method: 'DELETE',
                    headers: {
                        ...baseHeaders,
                        'X-Baseline-Reauth': reauthToken
                    }
                });
            } catch (retryError) {
                this.setRevokeKeyFeedback(retryError.message || 'Failed to revoke API key.', true);
                this.showError(retryError.message || 'Failed to revoke API key.');
                if (submitButton) submitButton.disabled = false;
                return;
            }
        }

        closeModal('revokeKeyModal');
        this.pendingKeyRevokeID = '';
        await Promise.allSettled([
            this.loadDashboardData(),
            this.loadApiKeysData(),
            this.loadAuditData()
        ]);
        this.showSuccess('API key revoked successfully.');
        if (submitButton) submitButton.disabled = false;
    }

    bindRunScanForm() {
        const form = document.getElementById('run-scan-form');
        if (!form || form.dataset.bound === '1') {
            return;
        }
        form.dataset.bound = '1';
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            await this.submitRunScanForm();
        });
    }

    async prepareRunScanModal() {
        if (!this.hasCapability('scans.run')) {
            this.showError('Scan run access is required.');
            closeModal('runScanModal');
            return;
        }
        this.bindRunScanForm();

        const projectSelect = document.getElementById('run-scan-project');
        const statusSelect = document.getElementById('run-scan-status');
        const commitInput = document.getElementById('run-scan-commit-sha');
        const submitButton = document.getElementById('run-scan-submit');

        if (!projectSelect || !statusSelect || !commitInput) {
            return;
        }

        statusSelect.value = 'pass';
        commitInput.value = '';
        this.setRunScanFeedback('Loading projects...', false);
        projectSelect.disabled = true;
        if (submitButton) submitButton.disabled = true;
        projectSelect.innerHTML = '<option value="">Loading projects...</option>';

        try {
            const payload = await this.apiRequest('/v1/projects');
            const projects = Array.isArray(payload.projects) ? payload.projects : [];
            if (projects.length === 0) {
                projectSelect.innerHTML = '<option value="">No projects available</option>';
                this.setRunScanFeedback('Create a project before running scans.', true);
                return;
            }

            projects.sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
            projectSelect.innerHTML = projects
                .map(project => {
                    const projectId = this.escapeHtml(project.id || '');
                    const label = this.escapeHtml(project.name || project.id || 'Unnamed');
                    return `<option value="${projectId}">${label}</option>`;
                })
                .join('');
            this.setRunScanFeedback('Creates a scan record in the backend and refreshes dashboard metrics/history.', false);
            if (submitButton) submitButton.disabled = false;
        } catch (error) {
            projectSelect.innerHTML = '<option value="">Failed to load projects</option>';
            this.setRunScanFeedback(error.message || 'Unable to load projects', true);
        } finally {
            projectSelect.disabled = false;
        }
    }

    setRunScanFeedback(message, isError) {
        const feedback = document.getElementById('run-scan-feedback');
        if (!feedback) {
            return;
        }
        feedback.textContent = message;
        feedback.className = isError ? 'text-xs text-red-600' : 'text-xs text-gray-500';
    }

    async submitRunScanForm() {
        if (!this.hasCapability('scans.run')) {
            this.showError('Scan run access is required.');
            return;
        }
        const projectSelect = document.getElementById('run-scan-project');
        const statusSelect = document.getElementById('run-scan-status');
        const commitInput = document.getElementById('run-scan-commit-sha');
        const submitButton = document.getElementById('run-scan-submit');

        if (!projectSelect || !statusSelect || !commitInput) {
            this.showError('Run Scan form is not available.');
            return;
        }

        const projectID = String(projectSelect.value || '').trim();
        const status = String(statusSelect.value || 'pass').trim().toLowerCase();
        const commitSHA = String(commitInput.value || '').trim();

        if (!projectID) {
            this.setRunScanFeedback('Select a project to continue.', true);
            return;
        }
        if (status !== 'pass' && status !== 'warn' && status !== 'fail') {
            this.setRunScanFeedback('Invalid scan status selected.', true);
            return;
        }
        if (/\s/.test(commitSHA)) {
            this.setRunScanFeedback('Commit SHA cannot contain whitespace.', true);
            return;
        }

        const payload = {
            project_id: projectID,
            status: status,
            violations: []
        };
        if (commitSHA) {
            payload.commit_sha = commitSHA;
        }

        if (submitButton) submitButton.disabled = true;
        this.setRunScanFeedback('Submitting scan request...', false);

        try {
            const created = await this.apiRequest('/v1/scans', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            closeModal('runScanModal');
            await Promise.allSettled([
                this.loadDashboardData(),
                this.loadScansData()
            ]);
            const createdID = created && created.id ? ` ${created.id}` : '';
            this.showSuccess(`Scan${createdID} created successfully.`);
        } catch (error) {
            this.setRunScanFeedback(error.message || 'Failed to create scan.', true);
            this.showError(error.message || 'Failed to create scan.');
        } finally {
            if (submitButton) submitButton.disabled = false;
        }
    }

    async loadPoliciesData() {
        try {
            const listPayload = await this.apiRequest('/v1/policies');
            const policies = Array.isArray(listPayload.policies) ? listPayload.policies : [];

            const enrichedPolicies = await Promise.all(
                policies.map(async policy => {
                    const name = String(policy.name || '');
                    const base = {
                        name,
                        latest_version: String(policy.latest_version || ''),
                        updated_at: policy.updated_at || '',
                        description: '',
                        version_count: 0,
                        content_keys: 0,
                        metadata_keys: 0
                    };

                    const [latestResult, versionsResult] = await Promise.allSettled([
                        this.apiRequest(`/v1/policies/${encodeURIComponent(name)}/latest`),
                        this.apiRequest(`/v1/policies/${encodeURIComponent(name)}/versions`)
                    ]);

                    if (latestResult.status === 'fulfilled' && latestResult.value) {
                        const latest = latestResult.value;
                        base.latest_version = base.latest_version || String(latest.version || '');
                        base.updated_at = base.updated_at || latest.published_at || '';
                        base.description = String(latest.description || '');
                        base.content_keys = latest.content && typeof latest.content === 'object' ? Object.keys(latest.content).length : 0;
                        base.metadata_keys = latest.metadata && typeof latest.metadata === 'object' ? Object.keys(latest.metadata).length : 0;
                    }
                    if (versionsResult.status === 'fulfilled' && versionsResult.value) {
                        const versions = Array.isArray(versionsResult.value.versions) ? versionsResult.value.versions : [];
                        base.version_count = versions.length;
                    }
                    return base;
                })
            );

            enrichedPolicies.sort((a, b) => a.name.localeCompare(b.name));
            this.renderPoliciesTable(enrichedPolicies);
        } catch (error) {
            this.showError(error.message || 'Failed to load policies');
            this.renderPoliciesTable([]);
        }
    }

    async loadProjectsData() {
        try {
            const [projectPayload, scanPayload] = await Promise.all([
                this.apiRequest('/v1/projects'),
                this.apiRequest('/v1/scans')
            ]);

            const projects = Array.isArray(projectPayload.projects) ? projectPayload.projects : [];
            const scans = Array.isArray(scanPayload.scans) ? scanPayload.scans : [];

            const scansByProject = new Map();
            scans.forEach(scan => {
                const projectID = String(scan.project_id || '');
                if (!projectID) return;
                if (!scansByProject.has(projectID)) {
                    scansByProject.set(projectID, []);
                }
                scansByProject.get(projectID).push(scan);
            });

            const normalizedProjects = projects.map(project => {
                const projectScans = scansByProject.get(project.id) || [];
                projectScans.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
                const latestScan = projectScans[0] || null;
                const latestStatus = this.normalizeScanStatus(latestScan?.status || '');

                return {
                    id: String(project.id || ''),
                    name: String(project.name || project.id || 'Unnamed'),
                    repository_url: String(project.repository_url || ''),
                    default_branch: String(project.default_branch || 'main'),
                    policy_set: String(project.policy_set || 'baseline:prod'),
                    owner_id: String(project.owner_id || ''),
                    scan_count: projectScans.length,
                    last_scan_at: latestScan?.created_at || '',
                    last_scan_status: latestStatus || 'unknown'
                };
            }).sort((a, b) => a.name.localeCompare(b.name));

            this.projectState.all = normalizedProjects;
            this.projectState.byID = new Map(normalizedProjects.map(project => [project.id, project]));
            this.renderProjectsTable(normalizedProjects);
        } catch (error) {
            this.showError(error.message || 'Failed to load projects');
            this.projectState.all = [];
            this.projectState.byID = new Map();
            this.renderProjectsTable([]);
        }
    }

    async loadApiKeysData() {
        try {
            if (this.isAdmin()) {
                await this.loadUsersData();
                if (!this.apiKeyState.mode) {
                    this.apiKeyState.mode = 'legacy';
                }
                if (this.apiKeyState.mode === 'user' && !String(this.apiKeyState.targetUserID || '').trim()) {
                    this.apiKeyState.mode = 'legacy';
                }
            } else {
                this.apiKeyState.mode = 'me';
                this.apiKeyState.targetUserID = '';
            }

            const scope = this.resolveAPIKeyScope();
            const payload = await this.apiRequest(scope.listPath);
            const apiKeys = Array.isArray(payload.api_keys) ? payload.api_keys : [];
            apiKeys.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
            this.apiKeyState.all = apiKeys;
            this.apiKeyState.byID = new Map(apiKeys.map(key => [String(key.id || ''), key]));
            this.apiKeyState.lastPath = scope.listPath;
            this.renderApiKeysTable(apiKeys);
        } catch (error) {
            this.showError(error.message || 'Failed to load API keys');
            this.apiKeyState.all = [];
            this.apiKeyState.byID = new Map();
            this.renderApiKeysTable([]);
        }
    }

    async loadUsersData(force = false) {
        if (!this.isAdmin()) {
            this.userState = {
                all: [],
                byID: new Map(),
                loaded: true,
                rows: [],
                selected: null,
                selectedActivity: [],
                selectedActivityTotal: 0,
                selectedActivityOffset: 0,
                selectedActivityHasMore: false,
                selectedActivityLimit: this.userState.selectedActivityLimit || 10,
                selectedActivityFilters: this.userState.selectedActivityFilters || { eventType: '', from: '', to: '' },
                total: 0,
                offset: 0,
                hasMore: false,
                limit: 0,
                filters: this.userState.filters
            };
            return [];
        }
        if (!force && this.userState.loaded) {
            return this.userState.all;
        }
        const result = await this.fetchUsers({ limit: 200, offset: 0 });
        const users = result.rows;
        this.userState = {
            all: users,
            byID: new Map(users.map(user => [String(user.id || ''), user])),
            loaded: true,
            rows: this.userState.rows,
            selected: this.userState.selected,
            selectedActivity: this.userState.selectedActivity,
            selectedActivityTotal: this.userState.selectedActivityTotal,
            selectedActivityOffset: this.userState.selectedActivityOffset,
            selectedActivityHasMore: this.userState.selectedActivityHasMore,
            selectedActivityLimit: this.userState.selectedActivityLimit,
            selectedActivityFilters: this.userState.selectedActivityFilters,
            total: this.userState.total,
            offset: this.userState.offset,
            hasMore: this.userState.hasMore,
            limit: this.userState.limit,
            filters: this.userState.filters
        };
        return users;
    }

    async fetchUsers(options = {}) {
        const limitValue = Number(options.limit || 100);
        const offsetValue = Number(options.offset || 0);
        const params = new URLSearchParams();
        params.set('limit', String(Number.isFinite(limitValue) && limitValue > 0 ? Math.min(limitValue, 200) : 100));
        params.set('offset', String(Number.isFinite(offsetValue) && offsetValue >= 0 ? offsetValue : 0));

        const q = String(options.q || '').trim();
        const role = String(options.role || '').trim().toLowerCase();
        const status = String(options.status || '').trim().toLowerCase();
        if (q !== '') {
            params.set('q', q);
        }
        if (role !== '' && role !== 'all') {
            params.set('role', role);
        }
        if (status !== '' && status !== 'all') {
            params.set('status', status);
        }
        const sortBy = String(options.sortBy || '').trim().toLowerCase();
        const sortDir = String(options.sortDir || '').trim().toLowerCase();
        if (sortBy !== '') {
            params.set('sort_by', sortBy);
        }
        if (sortDir !== '') {
            params.set('sort_dir', sortDir);
        }

        const payload = await this.apiRequest(`/v1/users?${params.toString()}`);
        const users = Array.isArray(payload.users) ? payload.users : [];
        const total = Number(payload.total);
        const limit = Number(payload.limit);
        const offset = Number(payload.offset);
        const hasMore = payload.has_more === true;
        return {
            rows: users,
            total: Number.isFinite(total) && total >= 0 ? total : users.length,
            limit: Number.isFinite(limit) && limit > 0 ? limit : users.length,
            offset: Number.isFinite(offset) && offset >= 0 ? offset : 0,
            hasMore: hasMore
        };
    }

    resolveAPIKeyScope() {
        if (!this.isAdmin()) {
            return {
                mode: 'me',
                listPath: '/v1/me/api-keys',
                createPath: '/v1/me/api-keys',
                revokePathPrefix: '/v1/me/api-keys'
            };
        }

        const mode = String(this.apiKeyState.mode || 'legacy').trim().toLowerCase();
        if (mode === 'me') {
            return {
                mode: 'me',
                listPath: '/v1/me/api-keys',
                createPath: '/v1/me/api-keys',
                revokePathPrefix: '/v1/me/api-keys'
            };
        }
        if (mode === 'user') {
            const userID = String(this.apiKeyState.targetUserID || '').trim();
            if (userID) {
                const encoded = encodeURIComponent(userID);
                return {
                    mode: 'user',
                    listPath: `/v1/users/${encoded}/api-keys`,
                    createPath: `/v1/users/${encoded}/api-keys`,
                    revokePathPrefix: `/v1/users/${encoded}/api-keys`
                };
            }
        }
        return {
            mode: 'legacy',
            listPath: '/v1/api-keys',
            createPath: '/v1/api-keys',
            revokePathPrefix: '/v1/api-keys'
        };
    }

    setAPIKeyScope(mode, userID = '') {
        const normalizedMode = String(mode || '').trim().toLowerCase();
        if (!this.isAdmin()) {
            this.apiKeyState.mode = 'me';
            this.apiKeyState.targetUserID = '';
            return;
        }
        if (normalizedMode === 'user') {
            this.apiKeyState.mode = 'user';
            this.apiKeyState.targetUserID = String(userID || '').trim();
            return;
        }
        if (normalizedMode === 'me') {
            this.apiKeyState.mode = 'me';
            this.apiKeyState.targetUserID = '';
            return;
        }
        this.apiKeyState.mode = 'legacy';
        this.apiKeyState.targetUserID = '';
    }

    async handleAPIKeyScopeChange(value) {
        const raw = String(value || '').trim();
        if (raw === 'legacy') {
            this.setAPIKeyScope('legacy');
        } else if (raw === 'me') {
            this.setAPIKeyScope('me');
        } else if (raw.startsWith('user:')) {
            this.setAPIKeyScope('user', raw.slice('user:'.length));
        } else {
            this.setAPIKeyScope('legacy');
        }
        await this.loadApiKeysData();
    }

    async loadIntegrationsData() {
        const integrationsTab = document.getElementById('integrations-tab');
        if (!integrationsTab) return;
        const canWrite = this.hasCapability('integrations.write');
        const canSecretsWrite = this.hasCapability('integrations.secrets.write');

        let events = [];
        let jobs = [];
        let firstError = '';

        try {
            const activityPayload = await this.apiRequest('/v1/dashboard/activity?type=integration&limit=20');
            events = Array.isArray(activityPayload.items) ? activityPayload.items : [];
        } catch (error) {
            firstError = firstError || String(error?.message || 'Failed to load integrations activity');
        }

        try {
            const jobsPayload = await this.apiRequest('/v1/integrations/jobs?limit=20');
            jobs = Array.isArray(jobsPayload.jobs) ? jobsPayload.jobs : [];
        } catch (error) {
            firstError = firstError || String(error?.message || 'Failed to load integration jobs');
        }

        this.integrationState.events = events;
        this.integrationState.jobs = jobs;
        this.renderIntegrationsTab(events, jobs, canWrite, canSecretsWrite);
        if (firstError) {
            this.showError(firstError);
        }
    }

    renderIntegrationsTab(events, jobs, canWrite, canSecretsWrite) {
        const integrationsTab = document.getElementById('integrations-tab');
        if (!integrationsTab) return;

        const disabledAttr = canWrite ? '' : 'disabled aria-disabled="true"';
        const disabledClass = canWrite ? '' : ' opacity-60 cursor-not-allowed';
        const secretsDisabledAttr = canSecretsWrite ? '' : 'disabled aria-disabled="true"';
        const secretsDisabledClass = canSecretsWrite ? '' : ' opacity-60 cursor-not-allowed';
        const writeBanner = canWrite
            ? `<div class="mb-4 px-4 py-3 rounded-lg border border-green-200 bg-green-50 text-sm text-green-800">Integration actions are live and mapped to backend endpoints.</div>`
            : `<div class="mb-4 px-4 py-3 rounded-lg border border-amber-200 bg-amber-50 text-sm text-amber-800">Read-only mode: integrations.write capability is required for publish actions.</div>`;
        const recentEventsRows = Array.isArray(events) && events.length
            ? events.map((event) => `
                <tr>
                    <td class="px-4 py-2 text-sm text-gray-900">${this.escapeHtml(event.action || event.type || '-')}</td>
                    <td class="px-4 py-2 text-sm text-gray-700">${this.escapeHtml(event.project_id || '-')}</td>
                    <td class="px-4 py-2 text-sm text-gray-700">${this.escapeHtml(event.scan_id || '-')}</td>
                    <td class="px-4 py-2 text-sm text-gray-700">${this.escapeHtml(event.actor || '-')}</td>
                    <td class="px-4 py-2 text-sm text-gray-500">${this.formatDate(event.created_at)}</td>
                </tr>
            `).join('')
            : `
                <tr>
                    <td colspan="5" class="px-4 py-4 text-sm text-gray-500 text-center">No integration events found.</td>
                </tr>
            `;
        const recentJobsRows = Array.isArray(jobs) && jobs.length
            ? jobs.map((job) => `
                <tr>
                    <td class="px-4 py-2 text-sm text-gray-900">${this.escapeHtml(job.provider || '-')}</td>
                    <td class="px-4 py-2 text-sm text-gray-700">${this.escapeHtml(job.job_type || '-')}</td>
                    <td class="px-4 py-2 text-sm text-gray-700">${this.escapeHtml(job.project_ref || '-')}</td>
                    <td class="px-4 py-2 text-sm text-gray-700">${this.escapeHtml(job.status || '-')}</td>
                    <td class="px-4 py-2 text-sm text-gray-700">${this.escapeHtml(String(job.attempt_count ?? 0))}/${this.escapeHtml(String(job.max_attempts ?? 0))}</td>
                    <td class="px-4 py-2 text-sm text-gray-500">${this.formatDate(job.next_attempt_at)}</td>
                </tr>
            `).join('')
            : `
                <tr>
                    <td colspan="6" class="px-4 py-4 text-sm text-gray-500 text-center">No integration jobs found.</td>
                </tr>
            `;

        integrationsTab.innerHTML = `
            ${writeBanner}
            <div class="grid grid-cols-1 xl:grid-cols-2 gap-6">
                <div class="bg-white rounded-lg border border-gray-200">
                    <div class="p-6 border-b border-gray-200">
                        <h3 class="text-lg font-semibold text-gray-900">Publish GitHub Check Run</h3>
                        <p class="text-sm text-gray-700 mt-1">Endpoint: POST /v1/integrations/github/check-runs</p>
                    </div>
                    <form id="integration-github-form" class="p-6 space-y-3">
                        <input id="integration-github-owner" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="Owner (required)" ${disabledAttr}>
                        <input id="integration-github-repository" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="Repository (required)" ${disabledAttr}>
                        <input id="integration-github-head-sha" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="Head SHA (required)" ${disabledAttr}>
                        <input id="integration-github-name" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="Check Name (required)" ${disabledAttr}>
                        <div class="grid grid-cols-2 gap-3">
                            <select id="integration-github-status" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" ${disabledAttr}>
                                <option value="completed">completed</option>
                                <option value="queued">queued</option>
                                <option value="in_progress">in_progress</option>
                            </select>
                            <select id="integration-github-conclusion" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" ${disabledAttr}>
                                <option value="">(none)</option>
                                <option value="success">success</option>
                                <option value="failure">failure</option>
                                <option value="neutral">neutral</option>
                            </select>
                        </div>
                        <input id="integration-github-details-url" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="Details URL (optional)" ${disabledAttr}>
                        <div class="flex items-center justify-between gap-3">
                            <p id="integration-github-feedback" class="text-xs text-gray-500">Ready.</p>
                            <button type="submit" id="integration-github-submit" class="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 text-sm font-medium${disabledClass}" ${disabledAttr}>Publish</button>
                        </div>
                    </form>
                </div>
                <div class="bg-white rounded-lg border border-gray-200">
                    <div class="p-6 border-b border-gray-200">
                        <h3 class="text-lg font-semibold text-gray-900">Publish GitLab Status</h3>
                        <p class="text-sm text-gray-700 mt-1">Endpoint: POST /v1/integrations/gitlab/statuses</p>
                    </div>
                    <form id="integration-gitlab-form" class="p-6 space-y-3">
                        <input id="integration-gitlab-project-id" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="Project ID (required)" ${disabledAttr}>
                        <input id="integration-gitlab-sha" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="Commit SHA (required)" ${disabledAttr}>
                        <div class="grid grid-cols-2 gap-3">
                            <select id="integration-gitlab-state" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" ${disabledAttr}>
                                <option value="pending">pending</option>
                                <option value="running">running</option>
                                <option value="success">success</option>
                                <option value="failed">failed</option>
                                <option value="canceled">canceled</option>
                                <option value="skipped">skipped</option>
                            </select>
                            <input id="integration-gitlab-name" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="Status Name (optional)" ${disabledAttr}>
                        </div>
                        <input id="integration-gitlab-target-url" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="Target URL (optional)" ${disabledAttr}>
                        <input id="integration-gitlab-description" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="Description (optional)" ${disabledAttr}>
                        <div class="flex items-center justify-between gap-3">
                            <p id="integration-gitlab-feedback" class="text-xs text-gray-500">Ready.</p>
                            <button type="submit" id="integration-gitlab-submit" class="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 text-sm font-medium${disabledClass}" ${disabledAttr}>Publish</button>
                        </div>
                    </form>
                </div>
            </div>
            <div class="bg-white rounded-lg border border-gray-200 mt-6">
                <div class="p-6 border-b border-gray-200">
                    <h3 class="text-lg font-semibold text-gray-900">Integration Secrets (Admin)</h3>
                    <p class="text-sm text-gray-700 mt-1">Endpoint: POST /v1/integrations/secrets (values are never returned)</p>
                </div>
                <form id="integration-secrets-form" class="p-6 grid grid-cols-1 md:grid-cols-2 gap-3">
                    <input id="integration-secret-github-webhook" type="password" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="GitHub Webhook Secret" ${secretsDisabledAttr}>
                    <input id="integration-secret-gitlab-webhook" type="password" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="GitLab Webhook Token" ${secretsDisabledAttr}>
                    <input id="integration-secret-github-token" type="password" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="GitHub API Token" ${secretsDisabledAttr}>
                    <input id="integration-secret-gitlab-token" type="password" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="GitLab API Token" ${secretsDisabledAttr}>
                    <input id="integration-secret-github-url" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="GitHub API URL (optional)" ${secretsDisabledAttr}>
                    <input id="integration-secret-gitlab-url" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="GitLab API URL (optional)" ${secretsDisabledAttr}>
                    <div class="md:col-span-2 flex items-center justify-between gap-3">
                        <p id="integration-secrets-feedback" class="text-xs text-gray-500">Provide one or more fields to update runtime integration config.</p>
                        <button type="submit" id="integration-secrets-submit" class="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 text-sm font-medium${secretsDisabledClass}" ${secretsDisabledAttr}>Update Secrets</button>
                    </div>
                </form>
            </div>
            <div class="bg-white rounded-lg border border-gray-200 mt-6">
                <div class="p-6 border-b border-gray-200">
                    <h3 class="text-lg font-semibold text-gray-900">Recent Integration Events</h3>
                    <p class="text-sm text-gray-700 mt-1">Source: /v1/dashboard/activity?type=integration</p>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Reference</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actor</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">${recentEventsRows}</tbody>
                    </table>
                </div>
            </div>
            <div class="bg-white rounded-lg border border-gray-200 mt-6">
                <div class="p-6 border-b border-gray-200">
                    <h3 class="text-lg font-semibold text-gray-900">Integration Job Queue</h3>
                    <p class="text-sm text-gray-700 mt-1">Source: /v1/integrations/jobs</p>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Provider</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project Ref</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Attempts</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Next Attempt</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">${recentJobsRows}</tbody>
                    </table>
                </div>
            </div>
        `;

        this.bindIntegrationForms(canWrite, canSecretsWrite);
    }

    bindIntegrationForms(canWrite, canSecretsWrite) {
        const githubForm = document.getElementById('integration-github-form');
        const gitlabForm = document.getElementById('integration-gitlab-form');
        const secretsForm = document.getElementById('integration-secrets-form');
        if (!githubForm || !gitlabForm || !secretsForm) {
            return;
        }
        if (githubForm.dataset.bound !== '1') {
            githubForm.dataset.bound = '1';
            githubForm.addEventListener('submit', async (event) => {
                event.preventDefault();
                if (!canWrite) return;
                await this.submitGitHubIntegrationForm();
            });
        }
        if (gitlabForm.dataset.bound !== '1') {
            gitlabForm.dataset.bound = '1';
            gitlabForm.addEventListener('submit', async (event) => {
                event.preventDefault();
                if (!canWrite) return;
                await this.submitGitLabIntegrationForm();
            });
        }
        if (secretsForm.dataset.bound !== '1') {
            secretsForm.dataset.bound = '1';
            secretsForm.addEventListener('submit', async (event) => {
                event.preventDefault();
                if (!canSecretsWrite) return;
                await this.submitIntegrationSecretsForm();
            });
        }
    }

    setIntegrationFeedback(kind, message, isError) {
        const target = document.getElementById(`integration-${kind}-feedback`);
        if (!target) return;
        target.textContent = message;
        target.className = isError ? 'text-xs text-red-600' : 'text-xs text-gray-500';
    }

    formatIntegrationError(error, fallbackMessage) {
        const base = String(error?.message || fallbackMessage || 'Integration request failed.');
        const requestID = String(error?.requestID || '').trim();
        if (!requestID) {
            return base;
        }
        return `${base} (request_id=${requestID})`;
    }

    async submitGitHubIntegrationForm() {
        const owner = String(document.getElementById('integration-github-owner')?.value || '').trim();
        const repository = String(document.getElementById('integration-github-repository')?.value || '').trim();
        const headSHA = String(document.getElementById('integration-github-head-sha')?.value || '').trim();
        const name = String(document.getElementById('integration-github-name')?.value || '').trim();
        const status = String(document.getElementById('integration-github-status')?.value || 'completed').trim();
        const conclusion = String(document.getElementById('integration-github-conclusion')?.value || '').trim();
        const detailsURL = String(document.getElementById('integration-github-details-url')?.value || '').trim();
        const submitButton = document.getElementById('integration-github-submit');

        if (!owner || !repository || !headSHA || !name) {
            this.setIntegrationFeedback('github', 'owner, repository, head_sha, and name are required.', true);
            return;
        }

        const payload = { owner, repository, head_sha: headSHA, name, status };
        if (conclusion) payload.conclusion = conclusion;
        if (detailsURL) payload.details_url = detailsURL;

        if (submitButton) submitButton.disabled = true;
        this.setIntegrationFeedback('github', 'Publishing GitHub check run...', false);
        try {
            const result = await this.apiRequest('/v1/integrations/github/check-runs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            this.setIntegrationFeedback('github', `Published successfully (upstream_status=${result?.upstream_status ?? 'n/a'}).`, false);
            this.showSuccess('GitHub check run published.');
            await this.loadIntegrationsData();
        } catch (error) {
            const message = this.formatIntegrationError(error, 'Failed to publish GitHub check run.');
            this.setIntegrationFeedback('github', message, true);
            this.showError(message);
        } finally {
            if (submitButton) submitButton.disabled = false;
        }
    }

    async submitGitLabIntegrationForm() {
        const projectID = String(document.getElementById('integration-gitlab-project-id')?.value || '').trim();
        const sha = String(document.getElementById('integration-gitlab-sha')?.value || '').trim();
        const state = String(document.getElementById('integration-gitlab-state')?.value || 'pending').trim();
        const name = String(document.getElementById('integration-gitlab-name')?.value || '').trim();
        const targetURL = String(document.getElementById('integration-gitlab-target-url')?.value || '').trim();
        const description = String(document.getElementById('integration-gitlab-description')?.value || '').trim();
        const submitButton = document.getElementById('integration-gitlab-submit');

        if (!projectID || !sha || !state) {
            this.setIntegrationFeedback('gitlab', 'project_id, sha, and state are required.', true);
            return;
        }

        const payload = { project_id: projectID, sha, state };
        if (name) payload.name = name;
        if (targetURL) payload.target_url = targetURL;
        if (description) payload.description = description;

        if (submitButton) submitButton.disabled = true;
        this.setIntegrationFeedback('gitlab', 'Publishing GitLab status...', false);
        try {
            const result = await this.apiRequest('/v1/integrations/gitlab/statuses', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            this.setIntegrationFeedback('gitlab', `Published successfully (upstream_status=${result?.upstream_status ?? 'n/a'}).`, false);
            this.showSuccess('GitLab status published.');
            await this.loadIntegrationsData();
        } catch (error) {
            const message = this.formatIntegrationError(error, 'Failed to publish GitLab status.');
            this.setIntegrationFeedback('gitlab', message, true);
            this.showError(message);
        } finally {
            if (submitButton) submitButton.disabled = false;
        }
    }

    async submitIntegrationSecretsForm() {
        const submitButton = document.getElementById('integration-secrets-submit');
        const githubWebhook = String(document.getElementById('integration-secret-github-webhook')?.value || '').trim();
        const gitlabWebhook = String(document.getElementById('integration-secret-gitlab-webhook')?.value || '').trim();
        const githubToken = String(document.getElementById('integration-secret-github-token')?.value || '').trim();
        const gitlabToken = String(document.getElementById('integration-secret-gitlab-token')?.value || '').trim();
        const githubURL = String(document.getElementById('integration-secret-github-url')?.value || '').trim();
        const gitlabURL = String(document.getElementById('integration-secret-gitlab-url')?.value || '').trim();

        const payload = {};
        if (githubWebhook) payload.github_webhook_secret = githubWebhook;
        if (gitlabWebhook) payload.gitlab_webhook_token = gitlabWebhook;
        if (githubToken) payload.github_api_token = githubToken;
        if (gitlabToken) payload.gitlab_api_token = gitlabToken;
        if (githubURL) payload.github_api_url = githubURL;
        if (gitlabURL) payload.gitlab_api_url = gitlabURL;

        if (Object.keys(payload).length === 0) {
            this.setIntegrationFeedback('secrets', 'Provide at least one value to update.', true);
            return;
        }

        if (submitButton) submitButton.disabled = true;
        this.setIntegrationFeedback('secrets', 'Updating integration secrets...', false);
        try {
            const result = await this.apiRequest('/v1/integrations/secrets', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const updated = Array.isArray(result?.updated) ? result.updated.join(', ') : '';
            this.setIntegrationFeedback('secrets', `Updated: ${updated || 'ok'}.`, false);
            this.showSuccess('Integration secrets updated.');
            ['integration-secret-github-webhook', 'integration-secret-gitlab-webhook', 'integration-secret-github-token', 'integration-secret-gitlab-token'].forEach((id) => {
                const input = document.getElementById(id);
                if (input) input.value = '';
            });
        } catch (error) {
            const message = this.formatIntegrationError(error, 'Failed to update integration secrets.');
            this.setIntegrationFeedback('secrets', message, true);
            this.showError(message);
        } finally {
            if (submitButton) submitButton.disabled = false;
        }
    }

    async loadSettingsData() {
        const settingsTab = document.getElementById('settings-tab');
        if (!settingsTab) return;

        let banner = settingsTab.querySelector('[data-settings-readonly-banner]');
        if (!banner) {
            banner = document.createElement('div');
            banner.setAttribute('data-settings-readonly-banner', '1');
            banner.className = 'mb-4 px-4 py-3 rounded-lg border border-amber-200 bg-amber-50 text-sm text-amber-800';
            banner.textContent = 'Settings are managed by server configuration and are read-only in dashboard mode.';
            settingsTab.prepend(banner);
        }

        settingsTab.querySelectorAll('input, select, textarea').forEach(control => {
            control.disabled = true;
            control.classList.add('opacity-70', 'cursor-not-allowed');
            control.setAttribute('aria-disabled', 'true');
        });

        settingsTab.querySelectorAll('[data-settings-disabled="1"]').forEach(button => {
            button.disabled = true;
            button.classList.add('opacity-70', 'cursor-not-allowed');
            button.setAttribute('aria-disabled', 'true');
            button.title = 'Disabled in dashboard runtime';
        });
    }

    async loadUsersTabData() {
        if (!this.isAdmin()) {
            this.renderUsersTab([], 'Admin role is required.');
            return;
        }
        this.hydrateUserActivityEventTypeCatalog();
        try {
            const filters = this.userState.filters || {};
            const page = Number(filters.page || 1);
            const limit = Number(filters.limit || 100);
            const safePage = Number.isFinite(page) && page > 0 ? page : 1;
            const safeLimit = Number.isFinite(limit) && limit > 0 ? Math.min(limit, 200) : 100;
            const offset = (safePage - 1) * safeLimit;
            const result = await this.fetchUsers({
                q: filters.q,
                role: filters.role,
                status: filters.status,
                limit: safeLimit,
                offset: offset,
                sortBy: filters.sortBy,
                sortDir: filters.sortDir
            });
            const users = result.rows;

            this.userState.rows = users;
            this.userState.total = result.total;
            this.userState.limit = result.limit;
            this.userState.offset = result.offset;
            this.userState.hasMore = result.hasMore;
            for (const user of users) {
                const id = String(user?.id || '').trim();
                if (id) {
                    this.userState.byID.set(id, user);
                }
            }

            if (this.userState.selected) {
                const selectedID = String(this.userState.selected.id || '').trim();
                if (selectedID && this.userState.byID.has(selectedID)) {
                    this.userState.selected = this.userState.byID.get(selectedID);
                }
            }
            this.renderUsersTab(users);
        } catch (error) {
            this.renderUsersTab([], error.message || 'Failed to load users');
        }
    }

    renderUsersTab(users, errorMessage = '') {
        const usersTab = document.getElementById('users-tab');
        if (!usersTab) {
            return;
        }

        if (!this.isAdmin()) {
            usersTab.innerHTML = `
                <div class="bg-white rounded-lg border border-amber-200 p-6">
                    <h3 class="text-lg font-semibold text-amber-900">Users</h3>
                    <p class="text-sm text-amber-700 mt-1">Admin access is required.</p>
                </div>
            `;
            return;
        }

        const userList = Array.isArray(users) ? users : [];
        const filters = this.userState.filters || {};
        const sortBy = String(filters.sortBy || 'updated_at').trim().toLowerCase();
        const sortDir = String(filters.sortDir || 'desc').trim().toLowerCase() === 'asc' ? 'asc' : 'desc';
        const totalCount = Number(this.userState.total || userList.length);
        const limit = Number(this.userState.limit || filters.limit || 100);
        const safeLimit = Number.isFinite(limit) && limit > 0 ? limit : 100;
        const offset = Number(this.userState.offset || 0);
        const safeOffset = Number.isFinite(offset) && offset >= 0 ? offset : 0;
        const safePage = Math.max(1, Math.floor(safeOffset / safeLimit) + 1);
        const totalPages = Math.max(1, Math.ceil(totalCount / safeLimit));
        const start = safeOffset;
        const pageRows = userList;
        const selected = this.userState.selected;
        const selectedActivity = Array.isArray(this.userState.selectedActivity) ? this.userState.selectedActivity : [];
        const selectedActivityFilters = this.userState.selectedActivityFilters || { eventType: '', from: '', to: '' };
        const selectedActivityTypeOptions = this.userActivityEventTypeOptions(selectedActivity, selectedActivityFilters.eventType);
        const selectedActivityRows = selectedActivity.length
            ? selectedActivity.map((event) => `
                <tr>
                    <td class="px-3 py-2 text-xs text-gray-700">${this.escapeHtml(this.formatDate(event.created_at))}</td>
                    <td class="px-3 py-2 text-xs text-gray-900">${this.escapeHtml(event.event_type || '-')}</td>
                    <td class="px-3 py-2 text-xs text-gray-700">${this.escapeHtml(event.project_id || '-')}</td>
                    <td class="px-3 py-2 text-xs text-gray-700">${this.escapeHtml(event.scan_id || '-')}</td>
                    <td class="px-3 py-2 text-xs text-gray-500">${this.escapeHtml(event.request_id || '-')}</td>
                </tr>
            `).join('')
            : `
                <tr>
                    <td colspan="5" class="px-3 py-3 text-xs text-gray-500 text-center">No activity events found for this user.</td>
                </tr>
            `;
        const detailPanel = selected
            ? `
                <div class="mx-6 mt-4 mb-2 rounded-lg border border-blue-200 bg-blue-50 p-4">
                    <div class="flex items-center justify-between gap-3">
                        <h4 class="text-sm font-semibold text-blue-900">Selected User Detail</h4>
                        <button type="button" id="users-detail-clear" class="text-xs text-blue-700 hover:text-blue-900 font-medium">Clear</button>
                    </div>
                    <div class="mt-2 grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                        <p><span class="text-gray-600">ID:</span> <span class="font-mono text-gray-900">${this.escapeHtml(selected.id || '-')}</span></p>
                        <p><span class="text-gray-600">Email:</span> <span class="text-gray-900">${this.escapeHtml(selected.email || '-')}</span></p>
                        <p><span class="text-gray-600">Role:</span> <span class="text-gray-900">${this.escapeHtml(selected.role || '-')}</span></p>
                        <p><span class="text-gray-600">Status:</span> <span class="text-gray-900">${this.escapeHtml(selected.status || '-')}</span></p>
                        <p><span class="text-gray-600">Provider:</span> <span class="text-gray-900">${this.escapeHtml(selected.provider || '-')}</span></p>
                        <p><span class="text-gray-600">Last login:</span> <span class="text-gray-900">${this.escapeHtml(this.formatDate(selected.last_login_at))}</span></p>
                    </div>
                    <div class="mt-3 rounded-lg border border-blue-200 bg-white">
                        <div class="px-3 py-2 border-b border-blue-100 flex items-center justify-between">
                            <p class="text-xs font-semibold text-gray-900">Recent Activity</p>
                            <p class="text-[11px] text-gray-500">Showing ${selectedActivity.length} of ${Number(this.userState.selectedActivityTotal || 0)}</p>
                        </div>
                        <div class="px-3 py-2 border-b border-blue-100 bg-blue-50/40">
                            <div class="grid grid-cols-1 md:grid-cols-4 gap-2">
                                <div>
                                    <input id="users-activity-filter-event-type" list="users-activity-event-type-list" type="text" value="${this.escapeHtml(selectedActivityFilters.eventType || '')}" placeholder="event_type (optional)" class="w-full px-2 py-1 border border-gray-300 rounded text-xs">
                                    <datalist id="users-activity-event-type-list">
                                        ${selectedActivityTypeOptions}
                                    </datalist>
                                </div>
                                <input id="users-activity-filter-from" type="datetime-local" value="${this.escapeHtml(selectedActivityFilters.from || '')}" class="px-2 py-1 border border-gray-300 rounded text-xs">
                                <input id="users-activity-filter-to" type="datetime-local" value="${this.escapeHtml(selectedActivityFilters.to || '')}" class="px-2 py-1 border border-gray-300 rounded text-xs">
                                <div class="flex items-center gap-2 justify-start md:justify-end">
                                    <button id="users-activity-filter-apply" type="button" class="px-3 py-1.5 bg-blue-700 text-white rounded text-xs hover:bg-blue-800">Apply</button>
                                    <button id="users-activity-filter-reset" type="button" class="px-3 py-1.5 border border-gray-300 text-gray-700 rounded text-xs hover:bg-gray-50">Reset</button>
                                </div>
                            </div>
                        </div>
                        <div class="overflow-x-auto">
                            <table class="w-full">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th class="px-3 py-2 text-left text-[10px] font-medium text-gray-500 uppercase tracking-wider">Time</th>
                                        <th class="px-3 py-2 text-left text-[10px] font-medium text-gray-500 uppercase tracking-wider">Event</th>
                                        <th class="px-3 py-2 text-left text-[10px] font-medium text-gray-500 uppercase tracking-wider">Project</th>
                                        <th class="px-3 py-2 text-left text-[10px] font-medium text-gray-500 uppercase tracking-wider">Scan</th>
                                        <th class="px-3 py-2 text-left text-[10px] font-medium text-gray-500 uppercase tracking-wider">Request ID</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white divide-y divide-gray-100">
                                    ${selectedActivityRows}
                                </tbody>
                            </table>
                        </div>
                        <div class="px-3 py-2 border-t border-blue-100 flex items-center justify-end">
                            <button id="users-activity-load-more" type="button" class="px-3 py-1.5 border border-gray-300 rounded text-xs ${this.userState.selectedActivityHasMore ? 'text-gray-700 hover:bg-gray-50' : 'text-gray-400 bg-gray-100 cursor-not-allowed'}" ${this.userState.selectedActivityHasMore ? '' : 'disabled aria-disabled="true"'}>Load More</button>
                        </div>
                    </div>
                </div>
            `
            : '';
        const rows = pageRows.length
            ? pageRows.map((user) => {
                const userID = String(user.id || '').trim();
                const rowKey = this.adminUserRowKey(userID);
                const role = String(user.role || 'viewer').toLowerCase();
                const status = String(user.status || 'active').toLowerCase();
                return `
                    <tr>
                        <td class="px-4 py-3 text-sm text-gray-900">${this.escapeHtml(user.email || user.display_name || userID)}</td>
                        <td class="px-4 py-3 text-sm text-gray-700">${this.escapeHtml(userID)}</td>
                        <td class="px-4 py-3">
                            <select id="admin-user-role-${rowKey}" class="px-2 py-1 border border-gray-300 rounded text-sm">
                                <option value="viewer"${role === 'viewer' ? ' selected' : ''}>viewer</option>
                                <option value="operator"${role === 'operator' ? ' selected' : ''}>operator</option>
                                <option value="admin"${role === 'admin' ? ' selected' : ''}>admin</option>
                            </select>
                        </td>
                        <td class="px-4 py-3">
                            <select id="admin-user-status-${rowKey}" class="px-2 py-1 border border-gray-300 rounded text-sm">
                                <option value="active"${status === 'active' ? ' selected' : ''}>active</option>
                                <option value="suspended"${status === 'suspended' ? ' selected' : ''}>suspended</option>
                            </select>
                        </td>
                        <td class="px-4 py-3 text-sm text-gray-700">${this.escapeHtml(this.formatDate(user.last_login_at))}</td>
                        <td class="px-4 py-3 text-sm">
                            <button
                                type="button"
                                class="px-3 py-1 mr-2 border border-gray-300 text-gray-700 rounded hover:bg-gray-50 text-xs font-medium"
                                onclick="window.baselineDashboard && window.baselineDashboard.viewAdminUserDetail(decodeURIComponent('${encodeURIComponent(userID)}'))"
                            >
                                View
                            </button>
                            <button
                                type="button"
                                class="px-3 py-1 bg-orange-600 text-white rounded hover:bg-orange-700 text-xs font-medium"
                                onclick="window.baselineDashboard && window.baselineDashboard.submitAdminUserUpdate(decodeURIComponent('${encodeURIComponent(userID)}'))"
                            >
                                Save
                            </button>
                        </td>
                    </tr>
                `;
            }).join('')
            : `
                <tr>
                    <td colspan="6" class="px-4 py-4 text-sm text-gray-500 text-center">No users found.</td>
                </tr>
            `;

        usersTab.innerHTML = `
            <div class="bg-white rounded-lg border border-gray-200">
                <div class="p-6 border-b border-gray-200">
                    <h3 class="text-lg font-semibold text-gray-900">Users</h3>
                    <p class="text-sm text-gray-700 mt-1">Admin controls for role and status management.</p>
                    <p class="text-xs text-gray-500 mt-1">Backed by <code>/v1/users</code> and <code>/v1/users/{id}</code>.</p>
                    <div class="mt-4 grid grid-cols-1 md:grid-cols-5 gap-3">
                        <input id="users-filter-q" type="text" value="${this.escapeHtml(filters.q || '')}" placeholder="Search user/email..." class="md:col-span-2 px-3 py-2 border border-gray-300 rounded-lg text-sm">
                        <select id="users-filter-role" class="px-3 py-2 border border-gray-300 rounded-lg text-sm">
                            <option value="all"${String(filters.role || 'all') === 'all' ? ' selected' : ''}>All roles</option>
                            <option value="viewer"${String(filters.role || '') === 'viewer' ? ' selected' : ''}>viewer</option>
                            <option value="operator"${String(filters.role || '') === 'operator' ? ' selected' : ''}>operator</option>
                            <option value="admin"${String(filters.role || '') === 'admin' ? ' selected' : ''}>admin</option>
                        </select>
                        <select id="users-filter-status" class="px-3 py-2 border border-gray-300 rounded-lg text-sm">
                            <option value="all"${String(filters.status || 'all') === 'all' ? ' selected' : ''}>All status</option>
                            <option value="active"${String(filters.status || '') === 'active' ? ' selected' : ''}>active</option>
                            <option value="suspended"${String(filters.status || '') === 'suspended' ? ' selected' : ''}>suspended</option>
                        </select>
                        <select id="users-filter-limit" class="px-3 py-2 border border-gray-300 rounded-lg text-sm">
                            <option value="25"${Number(filters.limit || 100) === 25 ? ' selected' : ''}>Limit 25</option>
                            <option value="50"${Number(filters.limit || 100) === 50 ? ' selected' : ''}>Limit 50</option>
                            <option value="100"${Number(filters.limit || 100) === 100 ? ' selected' : ''}>Limit 100</option>
                            <option value="200"${Number(filters.limit || 100) === 200 ? ' selected' : ''}>Limit 200</option>
                        </select>
                    </div>
                    <div class="mt-3 flex items-center gap-2">
                        <button id="users-filter-apply" type="button" class="px-3 py-1.5 bg-orange-600 text-white rounded hover:bg-orange-700 text-xs font-medium">Apply</button>
                        <button id="users-filter-reset" type="button" class="px-3 py-1.5 border border-gray-300 text-gray-700 rounded hover:bg-gray-50 text-xs font-medium">Reset</button>
                        <span class="text-xs text-gray-500">Showing ${totalCount === 0 ? 0 : start + 1}-${Math.min(start + pageRows.length, totalCount)} of ${totalCount} | Sort: ${this.userSortDescriptor(sortBy, sortDir)}</span>
                    </div>
                    <p id="admin-users-feedback" class="mt-2 text-xs ${errorMessage ? 'text-red-600' : 'text-gray-500'}">${this.escapeHtml(errorMessage || 'Review user role/status and click Save per row.')}</p>
                </div>
                ${detailPanel}
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    <button id="users-sort-user" type="button" class="flex items-center gap-1 hover:text-gray-700">
                                        User <span class="text-[10px]">${this.userSortIndicator('user', sortBy, sortDir)}</span>
                                    </button>
                                </th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User ID</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    <button id="users-sort-role" type="button" class="flex items-center gap-1 hover:text-gray-700">
                                        Role <span class="text-[10px]">${this.userSortIndicator('role', sortBy, sortDir)}</span>
                                    </button>
                                </th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    <button id="users-sort-status" type="button" class="flex items-center gap-1 hover:text-gray-700">
                                        Status <span class="text-[10px]">${this.userSortIndicator('status', sortBy, sortDir)}</span>
                                    </button>
                                </th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    <button id="users-sort-last-login" type="button" class="flex items-center gap-1 hover:text-gray-700">
                                        Last Login <span class="text-[10px]">${this.userSortIndicator('last_login_at', sortBy, sortDir)}</span>
                                    </button>
                                </th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">${rows}</tbody>
                    </table>
                </div>
                <div class="px-6 py-3 border-t border-gray-200 flex items-center justify-between">
                    <p class="text-xs text-gray-500">Page ${safePage} of ${totalPages}</p>
                    <div class="flex items-center gap-2">
                        <button id="users-page-prev" type="button" class="px-3 py-1.5 border border-gray-300 rounded text-xs ${safePage <= 1 ? 'text-gray-400 bg-gray-100 cursor-not-allowed' : 'text-gray-700 hover:bg-gray-50'}" ${safePage <= 1 ? 'disabled aria-disabled="true"' : ''}>Previous</button>
                        <button id="users-page-next" type="button" class="px-3 py-1.5 border border-gray-300 rounded text-xs ${!this.userState.hasMore ? 'text-gray-400 bg-gray-100 cursor-not-allowed' : 'text-gray-700 hover:bg-gray-50'}" ${!this.userState.hasMore ? 'disabled aria-disabled="true"' : ''}>Next</button>
                    </div>
                </div>
            </div>
        `;
        this.bindUsersTabControls();
    }

    sortUsersRows(users, sortBy, sortDir) {
        const rows = Array.isArray(users) ? [...users] : [];
        const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });
        rows.sort((left, right) => {
            let comparison = 0;
            switch (sortBy) {
                case 'role':
                    comparison = collator.compare(
                        String(left?.role || '').toLowerCase(),
                        String(right?.role || '').toLowerCase()
                    );
                    break;
                case 'status':
                    comparison = collator.compare(
                        String(left?.status || '').toLowerCase(),
                        String(right?.status || '').toLowerCase()
                    );
                    break;
                case 'last_login_at':
                    comparison = this.getUserSortTime(left?.last_login_at) - this.getUserSortTime(right?.last_login_at);
                    break;
                case 'created_at':
                    comparison = this.getUserSortTime(left?.created_at) - this.getUserSortTime(right?.created_at);
                    break;
                case 'updated_at':
                    comparison = this.getUserSortTime(left?.updated_at) - this.getUserSortTime(right?.updated_at);
                    break;
                case 'user':
                default:
                    comparison = collator.compare(
                        this.getUserSortText(left),
                        this.getUserSortText(right)
                    );
                    break;
            }
            if (comparison === 0) {
                comparison = collator.compare(String(left?.id || ''), String(right?.id || ''));
            }
            return sortDir === 'asc' ? comparison : -comparison;
        });
        return rows;
    }

    getUserSortText(user) {
        return String(user?.email || user?.display_name || user?.id || '').toLowerCase();
    }

    getUserSortTime(value) {
        const parsed = Date.parse(String(value || ''));
        return Number.isNaN(parsed) ? 0 : parsed;
    }

    userSortIndicator(key, activeBy, activeDir) {
        if (String(key) !== String(activeBy)) {
            return '↕';
        }
        return String(activeDir) === 'asc' ? '▲' : '▼';
    }

    userSortDescriptor(sortBy, sortDir) {
        const labels = {
            user: 'user',
            role: 'role',
            status: 'status',
            last_login_at: 'last login',
            created_at: 'created',
            updated_at: 'updated'
        };
        const base = labels[String(sortBy || '').toLowerCase()] || 'updated';
        return `${base} ${String(sortDir) === 'asc' ? 'asc' : 'desc'}`;
    }

    knownUserActivityEventTypes() {
        return [
            'api_key_issued',
            'api_key_revoked',
            'enforcement_failed',
            'github_check_published',
            'github_webhook_received',
            'gitlab_status_published',
            'gitlab_webhook_received',
            'integration_secrets_updated',
            'policy_updated',
            'project_registered',
            'project_updated',
            'ruleset_updated',
            'scan_uploaded',
            'user_updated'
        ];
    }

    async hydrateUserActivityEventTypeCatalog() {
        if (!this.isAdmin() || !this.hasCapability('audit.read')) {
            return;
        }
        if (this.userActivityEventTypeCatalog.length > 0) {
            return;
        }
        if (this.userActivityEventTypesPromise) {
            return;
        }

        this.userActivityEventTypesPromise = (async () => {
            try {
                const payload = await this.apiRequest('/v1/audit/events?limit=200');
                const events = Array.isArray(payload?.events) ? payload.events : [];
                const discovered = [...new Set(
                    events
                        .map((event) => String(event?.event_type || '').trim().toLowerCase())
                        .filter(Boolean)
                )].sort((a, b) => a.localeCompare(b));
                this.userActivityEventTypeCatalog = discovered;
            } catch (error) {
                // Keep fallback list only when discovery fails.
            } finally {
                this.userActivityEventTypesPromise = null;
                if (this.currentTab === 'users') {
                    this.renderUsersTab(this.userState.rows);
                }
            }
        })();
    }

    userActivityEventTypeOptions(events, selectedValue) {
        const set = new Set(this.knownUserActivityEventTypes());
        for (const value of this.userActivityEventTypeCatalog) {
            const clean = String(value || '').trim().toLowerCase();
            if (clean) {
                set.add(clean);
            }
        }
        if (Array.isArray(events)) {
            for (const event of events) {
                const value = String(event?.event_type || '').trim().toLowerCase();
                if (value) {
                    set.add(value);
                }
            }
        }
        const selected = String(selectedValue || '').trim().toLowerCase();
        if (selected) {
            set.add(selected);
        }
        return [...set]
            .sort((a, b) => a.localeCompare(b))
            .map((value) => `<option value="${this.escapeHtml(value)}"></option>`)
            .join('');
    }

    async toggleUsersSort(sortBy) {
        const key = String(sortBy || 'user').trim().toLowerCase();
        const currentBy = String(this.userState.filters.sortBy || 'updated_at').trim().toLowerCase();
        const currentDir = String(this.userState.filters.sortDir || 'desc').trim().toLowerCase();
        if (currentBy === key) {
            this.userState.filters.sortDir = currentDir === 'asc' ? 'desc' : 'asc';
        } else {
            this.userState.filters.sortBy = key;
            this.userState.filters.sortDir = key === 'last_login_at' || key === 'updated_at' || key === 'created_at' ? 'desc' : 'asc';
        }
        this.userState.filters.page = 1;
        await this.loadUsersTabData();
    }

    bindUsersTabControls() {
        const applyButton = document.getElementById('users-filter-apply');
        if (applyButton && applyButton.dataset.bound !== '1') {
            applyButton.dataset.bound = '1';
            applyButton.addEventListener('click', async () => {
                const qField = document.getElementById('users-filter-q');
                const roleField = document.getElementById('users-filter-role');
                const statusField = document.getElementById('users-filter-status');
                const limitField = document.getElementById('users-filter-limit');
                this.userState.filters.q = String(qField?.value || '').trim();
                this.userState.filters.role = String(roleField?.value || 'all').trim().toLowerCase();
                this.userState.filters.status = String(statusField?.value || 'all').trim().toLowerCase();
                this.userState.filters.limit = Number(limitField?.value || 100);
                this.userState.filters.page = 1;
                await this.loadUsersTabData();
            });
        }

        const resetButton = document.getElementById('users-filter-reset');
        if (resetButton && resetButton.dataset.bound !== '1') {
            resetButton.dataset.bound = '1';
            resetButton.addEventListener('click', async () => {
                this.userState.filters = {
                    ...this.userState.filters,
                    q: '',
                    role: 'all',
                    status: 'all',
                    limit: 100,
                    page: 1,
                    sortBy: 'updated_at',
                    sortDir: 'desc'
                };
                this.userState.selected = null;
                await this.loadUsersTabData();
            });
        }

        const prevButton = document.getElementById('users-page-prev');
        if (prevButton && prevButton.dataset.bound !== '1') {
            prevButton.dataset.bound = '1';
            prevButton.addEventListener('click', async () => {
                if ((this.userState.filters.page || 1) > 1) {
                    this.userState.filters.page = (this.userState.filters.page || 1) - 1;
                    await this.loadUsersTabData();
                }
            });
        }

        const nextButton = document.getElementById('users-page-next');
        if (nextButton && nextButton.dataset.bound !== '1') {
            nextButton.dataset.bound = '1';
            nextButton.addEventListener('click', async () => {
                if (this.userState.hasMore) {
                    this.userState.filters.page = (this.userState.filters.page || 1) + 1;
                    await this.loadUsersTabData();
                }
            });
        }

        const sortUserButton = document.getElementById('users-sort-user');
        if (sortUserButton && sortUserButton.dataset.bound !== '1') {
            sortUserButton.dataset.bound = '1';
            sortUserButton.addEventListener('click', async () => {
                await this.toggleUsersSort('user');
            });
        }

        const sortRoleButton = document.getElementById('users-sort-role');
        if (sortRoleButton && sortRoleButton.dataset.bound !== '1') {
            sortRoleButton.dataset.bound = '1';
            sortRoleButton.addEventListener('click', async () => {
                await this.toggleUsersSort('role');
            });
        }

        const sortStatusButton = document.getElementById('users-sort-status');
        if (sortStatusButton && sortStatusButton.dataset.bound !== '1') {
            sortStatusButton.dataset.bound = '1';
            sortStatusButton.addEventListener('click', async () => {
                await this.toggleUsersSort('status');
            });
        }

        const sortLastLoginButton = document.getElementById('users-sort-last-login');
        if (sortLastLoginButton && sortLastLoginButton.dataset.bound !== '1') {
            sortLastLoginButton.dataset.bound = '1';
            sortLastLoginButton.addEventListener('click', async () => {
                await this.toggleUsersSort('last_login_at');
            });
        }

        const clearDetailButton = document.getElementById('users-detail-clear');
        if (clearDetailButton && clearDetailButton.dataset.bound !== '1') {
            clearDetailButton.dataset.bound = '1';
            clearDetailButton.addEventListener('click', () => {
                this.userState.selected = null;
                this.userState.selectedActivity = [];
                this.userState.selectedActivityTotal = 0;
                this.userState.selectedActivityOffset = 0;
                this.userState.selectedActivityHasMore = false;
                this.userState.selectedActivityFilters = { eventType: '', from: '', to: '' };
                this.renderUsersTab(this.userState.rows);
            });
        }

        const activityFilterApplyButton = document.getElementById('users-activity-filter-apply');
        if (activityFilterApplyButton && activityFilterApplyButton.dataset.bound !== '1') {
            activityFilterApplyButton.dataset.bound = '1';
            activityFilterApplyButton.addEventListener('click', async () => {
                const eventTypeField = document.getElementById('users-activity-filter-event-type');
                const fromField = document.getElementById('users-activity-filter-from');
                const toField = document.getElementById('users-activity-filter-to');
                this.userState.selectedActivityFilters = {
                    eventType: String(eventTypeField?.value || '').trim().toLowerCase(),
                    from: String(fromField?.value || '').trim(),
                    to: String(toField?.value || '').trim()
                };
                const selectedID = String(this.userState.selected?.id || '').trim();
                if (selectedID) {
                    await this.viewAdminUserDetail(selectedID);
                } else {
                    this.renderUsersTab(this.userState.rows);
                }
            });
        }

        const activityFilterResetButton = document.getElementById('users-activity-filter-reset');
        if (activityFilterResetButton && activityFilterResetButton.dataset.bound !== '1') {
            activityFilterResetButton.dataset.bound = '1';
            activityFilterResetButton.addEventListener('click', async () => {
                this.userState.selectedActivityFilters = { eventType: '', from: '', to: '' };
                const selectedID = String(this.userState.selected?.id || '').trim();
                if (selectedID) {
                    await this.viewAdminUserDetail(selectedID);
                } else {
                    this.renderUsersTab(this.userState.rows);
                }
            });
        }

        const loadMoreActivityButton = document.getElementById('users-activity-load-more');
        if (loadMoreActivityButton && loadMoreActivityButton.dataset.bound !== '1') {
            loadMoreActivityButton.dataset.bound = '1';
            loadMoreActivityButton.addEventListener('click', async () => {
                await this.loadMoreSelectedUserActivity();
            });
        }
    }

    async viewAdminUserDetail(userID) {
        const id = String(userID || '').trim();
        if (!id || !this.isAdmin()) {
            return;
        }
        try {
            const detailPath = `/v1/users/${encodeURIComponent(id)}`;
            const activityPath = this.buildSelectedUserActivityPath(id, Number(this.userState.selectedActivityLimit || 10), 0);
            const [detail, activity] = await Promise.all([
                this.apiRequest(detailPath),
                this.apiRequest(activityPath)
            ]);
            this.userState.selected = detail && typeof detail === 'object' ? detail : null;
            const firstPageEvents = Array.isArray(activity?.events) ? activity.events : [];
            const firstPageOffset = Number(activity?.offset || 0);
            this.userState.selectedActivity = firstPageEvents;
            this.userState.selectedActivityTotal = Number(activity?.total || firstPageEvents.length);
            this.userState.selectedActivityOffset = firstPageOffset + firstPageEvents.length;
            this.userState.selectedActivityHasMore = activity?.has_more === true;
            this.renderUsersTab(this.userState.rows);
        } catch (error) {
            this.showError(error.message || 'Failed to load user detail.');
        }
    }

    buildSelectedUserActivityPath(userID, limit, offset) {
        const safeUserID = String(userID || '').trim();
        const safeLimit = Number.isFinite(limit) && limit > 0 ? Math.min(limit, 200) : 10;
        const safeOffset = Number.isFinite(offset) && offset >= 0 ? offset : 0;
        const params = new URLSearchParams();
        params.set('limit', String(safeLimit));
        params.set('offset', String(safeOffset));

        const filters = this.userState.selectedActivityFilters || {};
        const eventType = String(filters.eventType || '').trim().toLowerCase();
        if (eventType) {
            params.set('event_type', eventType);
        }

        const fromRFC3339 = this.activityFilterDateToRFC3339(filters.from);
        if (fromRFC3339) {
            params.set('from', fromRFC3339);
        }
        const toRFC3339 = this.activityFilterDateToRFC3339(filters.to);
        if (toRFC3339) {
            params.set('to', toRFC3339);
        }

        return `/v1/users/${encodeURIComponent(safeUserID)}/activity?${params.toString()}`;
    }

    activityFilterDateToRFC3339(raw) {
        const value = String(raw || '').trim();
        if (!value) {
            return '';
        }
        const parsed = new Date(value);
        if (Number.isNaN(parsed.getTime())) {
            return '';
        }
        return parsed.toISOString();
    }

    async loadMoreSelectedUserActivity() {
        const selectedID = String(this.userState.selected?.id || '').trim();
        if (!selectedID || !this.userState.selectedActivityHasMore) {
            return;
        }
        const limit = Number(this.userState.selectedActivityLimit || 10);
        const nextOffset = Number(this.userState.selectedActivityOffset || 0);
        const path = this.buildSelectedUserActivityPath(selectedID, limit, nextOffset);
        try {
            const activity = await this.apiRequest(path);
            const additional = Array.isArray(activity?.events) ? activity.events : [];
            this.userState.selectedActivity = [...this.userState.selectedActivity, ...additional];
            this.userState.selectedActivityTotal = Number(activity?.total || this.userState.selectedActivity.length);
            this.userState.selectedActivityOffset = Number(activity?.offset || nextOffset) + additional.length;
            this.userState.selectedActivityHasMore = activity?.has_more === true;
            this.renderUsersTab(this.userState.rows);
        } catch (error) {
            this.showError(error.message || 'Failed to load more user activity.');
        }
    }

    adminUserRowKey(userID) {
        return String(userID || '').replace(/[^a-zA-Z0-9_-]/g, '_');
    }

    async submitAdminUserUpdate(userID) {
        const id = String(userID || '').trim();
        if (!id) {
            this.showError('Invalid user id.');
            return;
        }
        const rowKey = this.adminUserRowKey(id);
        const roleField = document.getElementById(`admin-user-role-${rowKey}`);
        const statusField = document.getElementById(`admin-user-status-${rowKey}`);
        const feedback = document.getElementById('admin-users-feedback');
        if (!roleField || !statusField) {
            this.showError('User controls are not available.');
            return;
        }
        const role = String(roleField.value || '').trim().toLowerCase();
        const status = String(statusField.value || '').trim().toLowerCase();
        if (feedback) {
            feedback.textContent = `Updating ${id}...`;
            feedback.className = 'mt-2 text-xs text-gray-500';
        }
        try {
            const updatedUser = await this.apiRequest(`/v1/users/${encodeURIComponent(id)}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ role, status })
            });
            if (updatedUser && typeof updatedUser === 'object') {
                this.userState.byID.set(id, updatedUser);
                if (this.userState.selected && String(this.userState.selected.id || '').trim() === id) {
                    this.userState.selected = updatedUser;
                }
            }
            await this.loadUsersData(true);
            if (this.currentTab === 'users') {
                await this.loadUsersTabData();
            }
            const refreshedFeedback = document.getElementById('admin-users-feedback');
            if (refreshedFeedback) {
                refreshedFeedback.textContent = `Updated ${id} successfully.`;
                refreshedFeedback.className = 'mt-2 text-xs text-green-700';
            }
            this.showSuccess(`Updated ${id}.`);
            if (this.currentTab === 'keys') {
                await this.loadApiKeysData();
            }
        } catch (error) {
            if (feedback) {
                feedback.textContent = error.message || `Failed to update ${id}.`;
                feedback.className = 'mt-2 text-xs text-red-600';
            }
            this.showError(error.message || `Failed to update ${id}.`);
        }
    }

    async loadAuditData() {
        if (!this.hasCapability('audit.read')) {
            this.renderAuditTable([]);
            return;
        }
        try {
            const payload = await this.apiRequest('/v1/audit/events?limit=100');
            const events = Array.isArray(payload.events) ? payload.events : [];
            events.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
            this.renderAuditTable(events);
        } catch (error) {
            this.showError(error.message || 'Failed to load audit events');
            this.renderAuditTable([]);
        }
    }

    async generateReport() {
        if (!this.hasCapability('scans.read')) {
            this.showError('Scan read access is required.');
            return;
        }
        if (!this.scanState.all.length) {
            await this.loadScansData();
        }
        const candidate = this.scanState.filtered[0] || this.scanState.all[0];
        if (!candidate || !candidate.id) {
            this.showError('No scans are available to export a report.');
            return;
        }
        await this.downloadScanReport(candidate.id, 'text');
    }

    renderScansTable(scans) {
        const scansTab = document.getElementById('scans-tab');
        if (!scansTab) return;
        const canRunScans = this.hasCapability('scans.run');
        const runScanButton = canRunScans
            ? `<button onclick="openModal('runScanModal')" class="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 text-sm font-medium">Run New Scan</button>`
            : `<button type="button" class="px-4 py-2 border border-gray-300 text-gray-400 bg-gray-100 rounded-lg text-sm font-medium cursor-not-allowed" aria-disabled="true" disabled>Run New Scan</button>`;

        const uniqueProjects = Array.from(new Set(scans.map(scan => scan.project_name))).sort((a, b) => a.localeCompare(b));
        const projectOptions = uniqueProjects
            .map(name => `<option value="${this.escapeHtml(name)}">${this.escapeHtml(name)}</option>`)
            .join('');

        scansTab.innerHTML = `
            <div class="bg-white rounded-lg border border-gray-200">
                <div class="p-6 border-b border-gray-200 flex items-center justify-between gap-4">
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900">Scan History</h3>
                        <p class="text-sm text-gray-700 mt-1">Real scan results from the Baseline API</p>
                    </div>
                    ${runScanButton}
                </div>
                <div class="p-4 border-b border-gray-200 bg-gray-50 flex flex-wrap items-end gap-3">
                    <div>
                        <label class="block text-xs font-medium text-gray-600 mb-1">Status</label>
                        <select id="scans-status-filter" class="px-3 py-2 border border-gray-300 rounded-lg text-sm">
                            <option value="all">All</option>
                            <option value="pass">Pass</option>
                            <option value="fail">Fail</option>
                            <option value="warn">Warn</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-gray-600 mb-1">Project</label>
                        <select id="scans-project-filter" class="px-3 py-2 border border-gray-300 rounded-lg text-sm">
                            <option value="all">All</option>
                            ${projectOptions}
                        </select>
                    </div>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Violations</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Failure Details</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Reports</th>
                            </tr>
                        </thead>
                        <tbody id="scans-table-body" class="bg-white divide-y divide-gray-200"></tbody>
                    </table>
                </div>
                <div class="p-4 border-t border-gray-200 flex items-center justify-between">
                    <p id="scans-page-meta" class="text-sm text-gray-600"></p>
                    <div class="flex items-center gap-2">
                        <button id="scans-prev-page" class="px-3 py-1.5 border border-gray-300 rounded text-sm hover:bg-gray-50">Previous</button>
                        <button id="scans-next-page" class="px-3 py-1.5 border border-gray-300 rounded text-sm hover:bg-gray-50">Next</button>
                    </div>
                </div>
            </div>
        `;

        this.bindScansControls();
        this.applyScansFiltersAndRender();
    }

    bindScansControls() {
        const statusFilter = document.getElementById('scans-status-filter');
        const projectFilter = document.getElementById('scans-project-filter');
        const prevBtn = document.getElementById('scans-prev-page');
        const nextBtn = document.getElementById('scans-next-page');

        if (statusFilter) {
            statusFilter.value = this.scanState.statusFilter;
            statusFilter.addEventListener('change', () => {
                this.scanState.statusFilter = statusFilter.value || 'all';
                this.scanState.page = 1;
                this.applyScansFiltersAndRender();
            });
        }
        if (projectFilter) {
            projectFilter.value = this.scanState.projectFilter;
            projectFilter.addEventListener('change', () => {
                this.scanState.projectFilter = projectFilter.value || 'all';
                this.scanState.page = 1;
                this.applyScansFiltersAndRender();
            });
        }
        if (prevBtn) {
            prevBtn.addEventListener('click', () => {
                if (this.scanState.page > 1) {
                    this.scanState.page -= 1;
                    this.applyScansFiltersAndRender();
                }
            });
        }
        if (nextBtn) {
            nextBtn.addEventListener('click', () => {
                const totalPages = Math.max(1, Math.ceil(this.scanState.filtered.length / this.scanState.pageSize));
                if (this.scanState.page < totalPages) {
                    this.scanState.page += 1;
                    this.applyScansFiltersAndRender();
                }
            });
        }
    }

    applyScansFiltersAndRender() {
        let filtered = [...this.scanState.all];
        if (this.scanState.statusFilter !== 'all') {
            filtered = filtered.filter(scan => this.normalizeScanStatus(scan.status) === this.scanState.statusFilter);
        }
        if (this.scanState.projectFilter !== 'all') {
            filtered = filtered.filter(scan => scan.project_name === this.scanState.projectFilter);
        }
        this.scanState.filtered = filtered;

        const totalPages = Math.max(1, Math.ceil(filtered.length / this.scanState.pageSize));
        if (this.scanState.page > totalPages) {
            this.scanState.page = totalPages;
        }
        const start = (this.scanState.page - 1) * this.scanState.pageSize;
        const end = start + this.scanState.pageSize;
        const pageItems = filtered.slice(start, end);

        const tableBody = document.getElementById('scans-table-body');
        if (tableBody) {
            if (!pageItems.length) {
                tableBody.innerHTML = `
                    <tr>
                        <td colspan="6" class="px-6 py-6 text-sm text-gray-500 text-center">No scans found for the selected filters.</td>
                    </tr>
                `;
            } else {
                tableBody.innerHTML = pageItems.map(scan => {
                    const status = this.normalizeScanStatus(scan.status);
                    const failureDetails = status === 'fail'
                        ? `${scan.blocking_violations} blocking, ${scan.warnings} warnings${scan.first_violation ? ` - ${this.escapeHtml(scan.first_violation)}` : ''}`
                        : '-';
                    return `
                        <tr>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${this.escapeHtml(scan.project_name)}</td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                <span class="px-2 py-1 text-xs rounded-full ${this.statusBadgeClass(status)}">${this.escapeHtml(status.toUpperCase())}</span>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${scan.violations}</td>
                            <td class="px-6 py-4 text-sm text-gray-700">${failureDetails}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${this.formatDate(scan.created_at)}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm">
                                <button type="button" class="scan-report-btn text-orange-600 hover:text-orange-700 mr-2" data-scan-id="${this.escapeHtml(scan.id)}" data-format="json">JSON</button>
                                <button type="button" class="scan-report-btn text-orange-600 hover:text-orange-700 mr-2" data-scan-id="${this.escapeHtml(scan.id)}" data-format="text">Text</button>
                                <button type="button" class="scan-report-btn text-orange-600 hover:text-orange-700" data-scan-id="${this.escapeHtml(scan.id)}" data-format="sarif">SARIF</button>
                            </td>
                        </tr>
                    `;
                }).join('');
            }
        }

        this.bindScanReportButtons();

        const meta = document.getElementById('scans-page-meta');
        if (meta) {
            const from = filtered.length === 0 ? 0 : start + 1;
            const to = Math.min(end, filtered.length);
            meta.textContent = `Showing ${from}-${to} of ${filtered.length} scans`;
        }

        const prevBtn = document.getElementById('scans-prev-page');
        const nextBtn = document.getElementById('scans-next-page');
        if (prevBtn) prevBtn.disabled = this.scanState.page <= 1;
        if (nextBtn) nextBtn.disabled = this.scanState.page >= totalPages;
    }

    bindScanReportButtons() {
        const buttons = document.querySelectorAll('.scan-report-btn');
        buttons.forEach((button) => {
            button.addEventListener('click', async (event) => {
                event.preventDefault();
                const scanID = button.getAttribute('data-scan-id') || '';
                const format = button.getAttribute('data-format') || 'json';
                await this.downloadScanReport(scanID, format);
            });
        });
    }

    async downloadScanReport(scanID, format) {
        const normalizedID = String(scanID || '').trim();
        const normalizedFormat = String(format || 'json').toLowerCase().trim();
        if (!normalizedID) {
            this.showError('Invalid scan ID for report download.');
            return;
        }
        if (!['json', 'text', 'sarif'].includes(normalizedFormat)) {
            this.showError('Unsupported report format.');
            return;
        }

        const acceptHeader = normalizedFormat === 'text' ? 'text/plain' : 'application/json';
        let response;
        let blob;
        try {
            const result = await this.apiClient.requestBlob(
                `/v1/scans/${encodeURIComponent(normalizedID)}/report?format=${encodeURIComponent(normalizedFormat)}`,
                {
                    method: 'GET',
                    headers: {
                        'Accept': acceptHeader
                    }
                }
            );
            response = result.response;
            blob = result.blob;
        } catch (error) {
            if (error && error.status === 401) {
                return;
            }
            if (error && error.message) {
                this.showError(error.message);
                return;
            }
            this.showError('Network error while downloading scan report.');
            return;
        }
        const extension = normalizedFormat === 'text'
            ? 'txt'
            : (normalizedFormat === 'sarif' ? 'sarif' : 'json');
        const downloadName = `baseline-scan-${normalizedID}.${extension}`;

        const downloadURL = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = downloadURL;
        link.download = downloadName;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(downloadURL);
    }

    statusBadgeClass(status) {
        if (status === 'pass') return 'bg-green-100 text-green-800';
        if (status === 'warn') return 'bg-yellow-100 text-yellow-800';
        if (status === 'fail') return 'bg-red-100 text-red-800';
        return 'bg-gray-100 text-gray-800';
    }

    roleBadgeClass(role) {
        if (role === 'admin') return 'bg-purple-100 text-purple-800';
        if (role === 'operator') return 'bg-blue-100 text-blue-800';
        return 'bg-gray-100 text-gray-800';
    }

    renderPoliciesTable(policies) {
        const policiesTab = document.getElementById('policies-tab');
        if (!policiesTab) return;

        if (!Array.isArray(policies) || policies.length === 0) {
            policiesTab.innerHTML = `
                <div class="bg-white rounded-lg border border-gray-200 p-6">
                    <h3 class="text-lg font-semibold text-gray-900">Policy Management</h3>
                    <p class="text-sm text-gray-700 mt-1">No policies found.</p>
                </div>
            `;
            return;
        }

        policiesTab.innerHTML = `
            <div class="bg-white rounded-lg border border-gray-200">
                <div class="p-6 border-b border-gray-200">
                    <h3 class="text-lg font-semibold text-gray-900">Policy Management</h3>
                    <p class="text-sm text-gray-700 mt-1">Live policy versions from backend endpoints</p>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Policy</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Latest Version</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Updated</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Versions</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Links</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            ${policies.map(policy => `
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${this.escapeHtml(policy.name)}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${this.escapeHtml(policy.latest_version || 'N/A')}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${this.formatDate(policy.updated_at)}</td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <span class="px-2 py-1 text-xs rounded-full bg-blue-100 text-blue-800">
                                            ${policy.version_count} total
                                        </span>
                                    </td>
                                    <td class="px-6 py-4 text-sm text-gray-700">
                                        ${this.escapeHtml(policy.description || 'No description')}
                                        <div class="text-xs text-gray-500 mt-1">content keys: ${policy.content_keys}, metadata keys: ${policy.metadata_keys}</div>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm">
                                        <a class="text-orange-600 hover:text-orange-700 mr-2" href="/v1/policies/${encodeURIComponent(policy.name)}/latest" target="_blank" rel="noopener noreferrer">Latest</a>
                                        <a class="text-orange-600 hover:text-orange-700" href="/v1/policies/${encodeURIComponent(policy.name)}/versions" target="_blank" rel="noopener noreferrer">Versions</a>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }

    renderProjectsTable(projects) {
        const projectsTab = document.getElementById('projects-tab');
        if (!projectsTab) return;
        const canWriteProjects = this.hasCapability('projects.write');
        const isAdmin = this.isAdmin();
        const addProjectButton = canWriteProjects
            ? `<button onclick="openModal('addProjectModal')" class="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 text-sm font-medium">Add Project</button>`
            : `<button type="button" class="px-4 py-2 border border-gray-300 text-gray-400 bg-gray-100 rounded-lg text-sm font-medium cursor-not-allowed" aria-disabled="true" disabled>Add Project</button>`;
        const editActionHeader = (canWriteProjects || isAdmin)
            ? `<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>`
            : '';
        const ownerHeader = `<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Owner</th>`;

        if (!Array.isArray(projects) || projects.length === 0) {
            projectsTab.innerHTML = `
                <div class="bg-white rounded-lg border border-gray-200 p-6">
                    <div class="flex items-center justify-between gap-4">
                        <div>
                            <h3 class="text-lg font-semibold text-gray-900">Projects</h3>
                            <p class="text-sm text-gray-700 mt-1">No projects found.</p>
                        </div>
                        ${addProjectButton}
                    </div>
                </div>
            `;
            return;
        }

        projectsTab.innerHTML = `
            <div class="bg-white rounded-lg border border-gray-200">
                <div class="p-6 border-b border-gray-200 flex items-center justify-between gap-4">
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900">Projects</h3>
                        <p class="text-sm text-gray-700 mt-1">Live projects and scan posture from backend APIs</p>
                    </div>
                    ${addProjectButton}
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Repository</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Branch</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Policy Set</th>
                                ${ownerHeader}
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Scans</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Scan</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                ${editActionHeader}
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            ${projects.map(project => `
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${this.escapeHtml(project.name)}</td>
                                    <td class="px-6 py-4 text-sm text-gray-700">${this.escapeHtml(project.repository_url || '-')}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${this.escapeHtml(project.default_branch)}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${this.escapeHtml(project.policy_set)}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${this.escapeHtml(this.describeProjectOwner(project.owner_id))}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${project.scan_count}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${this.formatDate(project.last_scan_at)}</td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <span class="px-2 py-1 text-xs rounded-full ${this.statusBadgeClass(project.last_scan_status)}">${this.escapeHtml(project.last_scan_status.toUpperCase())}</span>
                                    </td>
                                    ${(canWriteProjects || isAdmin) ? `
                                        <td class="px-6 py-4 whitespace-nowrap text-sm">
                                            <div class="flex items-center gap-3">
                                                ${canWriteProjects ? `
                                                    <button
                                                        onclick="window.baselineDashboard && window.baselineDashboard.openEditProjectModal(decodeURIComponent('${encodeURIComponent(project.id)}'))"
                                                        class="text-orange-600 hover:text-orange-700 font-medium"
                                                    >
                                                        Edit
                                                    </button>
                                                ` : ''}
                                                ${canWriteProjects ? `
                                                    <button
                                                        onclick="window.baselineDashboard && window.baselineDashboard.claimProject(decodeURIComponent('${encodeURIComponent(project.id)}'))"
                                                        class="text-gray-600 hover:text-gray-900 font-medium"
                                                    >
                                                        Claim
                                                    </button>
                                                ` : ''}
                                                ${isAdmin ? `
                                                    <button
                                                        onclick="window.baselineDashboard && window.baselineDashboard.openProjectOwnerModal(decodeURIComponent('${encodeURIComponent(project.id)}'))"
                                                        class="text-gray-600 hover:text-gray-900 font-medium"
                                                    >
                                                        Assign owner
                                                    </button>
                                                ` : ''}
                                            </div>
                                        </td>
                                    ` : ''}
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }

    renderApiKeysTable(apiKeys) {
        const keysTab = document.getElementById('keys-tab');
        if (!keysTab) return;
        const canWriteKeys = this.hasCapability('api_keys.write');
        const scope = this.resolveAPIKeyScope();
        const adminScopeControls = this.renderAPIKeyScopeControls();
        const scopeLabel = scope.mode === 'user'
            ? `User scope: ${this.escapeHtml(this.apiKeyScopeUserLabel() || 'unknown')}`
            : scope.mode === 'me'
                ? 'Self scope: your keys only'
                : 'Admin legacy scope: global key inventory';
        const canGenerateInScope = canWriteKeys && (scope.mode !== 'user' || String(this.apiKeyState.targetUserID || '').trim() !== '');
        const generateKeyButton = canGenerateInScope
            ? `<button onclick="openModal('generateKeyModal')" class="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 text-sm font-medium">Generate Key</button>`
            : `<button type="button" class="px-4 py-2 border border-gray-300 text-gray-400 bg-gray-100 rounded-lg text-sm font-medium cursor-not-allowed" aria-disabled="true" disabled>Generate Key</button>`;
        const actionsHeader = canWriteKeys
            ? `<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>`
            : '';
        const ownerHeader = this.isAdmin()
            ? `<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Owner</th>`
            : '';

        if (!Array.isArray(apiKeys) || apiKeys.length === 0) {
            keysTab.innerHTML = `
                <div class="bg-white rounded-lg border border-gray-200 p-6">
                    <div class="flex items-center justify-between gap-4">
                        <div>
                            <h3 class="text-lg font-semibold text-gray-900">API Keys</h3>
                            <p class="text-sm text-gray-700 mt-1">No API keys found.</p>
                        </div>
                        ${generateKeyButton}
                    </div>
                    ${adminScopeControls}
                    <p class="mt-3 text-xs text-gray-500">${scopeLabel}</p>
                </div>
            `;
            this.bindAPIKeyScopeControls();
            return;
        }

        keysTab.innerHTML = `
            <div class="bg-white rounded-lg border border-gray-200">
                <div class="p-6 border-b border-gray-200 flex items-center justify-between gap-4">
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900">API Keys</h3>
                        <p class="text-sm text-gray-700 mt-1">Metadata only. Secrets are never returned after issuance.</p>
                        <p class="text-xs text-gray-500 mt-1">${scopeLabel}</p>
                    </div>
                    ${generateKeyButton}
                </div>
                ${adminScopeControls}
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Key ID</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Prefix</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                                ${ownerHeader}
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                                ${actionsHeader}
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            ${apiKeys.map(key => {
                                const status = key.revoked ? 'revoked' : 'active';
                                const role = String(key.role || 'viewer').toLowerCase();
                                const keyIDEncoded = encodeURIComponent(String(key.id || ''));
                                const disableRevoke = key.revoked;
                                return `
                                    <tr>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${this.escapeHtml(key.name || 'unnamed')}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${this.escapeHtml(key.id || '')}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${this.escapeHtml(key.prefix || '-')}</td>
                                        <td class="px-6 py-4 whitespace-nowrap">
                                            <span class="px-2 py-1 text-xs rounded-full ${this.roleBadgeClass(role)}">${this.escapeHtml(role)}</span>
                                        </td>
                                        ${this.isAdmin() ? `
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                                                ${this.escapeHtml(key.owner_user_id || key.owner_email || key.owner_subject || '-')}
                                            </td>
                                        ` : ''}
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${this.escapeHtml(key.source || '-')}</td>
                                        <td class="px-6 py-4 whitespace-nowrap">
                                            <span class="px-2 py-1 text-xs rounded-full ${status === 'active' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}">${status}</span>
                                        </td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${this.formatDate(key.created_at)}</td>
                                        ${canWriteKeys ? `
                                            <td class="px-6 py-4 whitespace-nowrap text-sm">
                                                ${disableRevoke ? '<span class="text-gray-400">-</span>' : `
                                                    <button
                                                        onclick="window.baselineDashboard && window.baselineDashboard.openRevokeKeyModal(decodeURIComponent('${keyIDEncoded}'))"
                                                        class="text-red-600 hover:text-red-700 font-medium"
                                                    >
                                                        Revoke
                                                    </button>
                                                `}
                                            </td>
                                        ` : ''}
                                    </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
        this.bindAPIKeyScopeControls();
    }

    renderAPIKeyScopeControls() {
        if (!this.isAdmin()) {
            return '';
        }
        const selectedMode = String(this.apiKeyState.mode || 'legacy').toLowerCase();
        const selectedUserID = String(this.apiKeyState.targetUserID || '').trim();
        const optionRows = [];
        optionRows.push(`<option value="legacy"${selectedMode === 'legacy' ? ' selected' : ''}>Admin Legacy (all keys)</option>`);
        optionRows.push(`<option value="me"${selectedMode === 'me' ? ' selected' : ''}>My Keys</option>`);
        for (const user of this.userState.all) {
            const userID = String(user?.id || '').trim();
            if (!userID) {
                continue;
            }
            const value = `user:${userID}`;
            const selected = selectedMode === 'user' && selectedUserID === userID ? ' selected' : '';
            const label = `${user.email || user.display_name || userID} (${user.role || 'viewer'})`;
            optionRows.push(`<option value="${this.escapeHtml(value)}"${selected}>${this.escapeHtml(label)}</option>`);
        }
        return `
            <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
                <label for="api-key-scope-select" class="block text-xs font-medium text-gray-600 mb-1">Key Scope</label>
                <select id="api-key-scope-select" class="w-full max-w-md px-3 py-2 border border-gray-300 rounded-lg text-sm">
                    ${optionRows.join('')}
                </select>
            </div>
        `;
    }

    bindAPIKeyScopeControls() {
        const select = document.getElementById('api-key-scope-select');
        if (!select || select.dataset.bound === '1') {
            return;
        }
        select.dataset.bound = '1';
        select.addEventListener('change', async (event) => {
            const nextValue = String(event.target?.value || '').trim();
            await this.handleAPIKeyScopeChange(nextValue);
        });
    }

    renderAuditTable(events) {
        const auditTab = document.getElementById('audit-tab');
        if (!auditTab) return;

        if (!Array.isArray(events) || events.length === 0) {
            auditTab.innerHTML = `
                <div class="bg-white rounded-lg border border-gray-200 p-6">
                    <h3 class="text-lg font-semibold text-gray-900">Audit Log</h3>
                    <p class="text-sm text-gray-700 mt-1">No audit events found.</p>
                </div>
            `;
            return;
        }

        auditTab.innerHTML = `
            <div class="bg-white rounded-lg border border-gray-200">
                <div class="p-6 border-b border-gray-200">
                    <h3 class="text-lg font-semibold text-gray-900">Audit Log</h3>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Event Type</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Scan</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Details</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            ${events.map(event => `
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${this.formatDate(event.created_at)}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${this.escapeHtml(event.event_type || '-')}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${this.escapeHtml(event.project_id || '-')}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${this.escapeHtml(event.scan_id || '-')}</td>
                                    <td class="px-6 py-4 text-sm text-gray-700">${this.escapeHtml(this.describeAuditEvent(event))}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }

    setCardMetric(card, value, label) {
        if (!card) return;
        const valueNode = card.querySelector('h3');
        const labelNode = card.querySelector('p');
        if (valueNode) valueNode.textContent = String(value);
        if (labelNode) labelNode.textContent = label;
    }

    normalizeScanStatus(status) {
        const normalized = String(status || '').toLowerCase();
        if (normalized === 'passed') return 'pass';
        if (normalized === 'failed') return 'fail';
        if (normalized === 'warning') return 'warn';
        return normalized || 'unknown';
    }

    async apiRequest(path, options = {}) {
        return this.apiClient.requestJSON(path, options);
    }

    describeAuditEvent(event) {
        const summary = this.describeEventLabel({
            action: event.event_type,
            type: String(event.event_type || '').toLowerCase().startsWith('integration_') ? 'integration' : 'audit'
        });
        const parts = [];
        if (event.project_id) {
            parts.push(`project ${event.project_id}`);
        }
        if (event.scan_id) {
            parts.push(`scan ${event.scan_id}`);
        }
        const actor = this.formatActorLabel(event.actor);
        if (actor) {
            parts.push(`actor ${actor}`);
        }
        if (event.request_id) {
            parts.push(`request ${event.request_id}`);
        }
        if (parts.length === 0) {
            return summary;
        }
        return `${summary}: ${parts.join(' | ')}`;
    }

    describeEventLabel(event) {
        const action = String(event?.action || event?.event_type || 'activity').trim().toLowerCase();
        const labels = {
            dashboard_initialized: 'Dashboard initialized',
            project_registered: 'Project registered',
            project_updated: 'Project updated',
            scan_uploaded: 'Scan uploaded',
            scan_pass: 'Scan passed',
            scan_fail: 'Scan failed',
            scan_warn: 'Scan warned',
            enforcement_failed: 'Release blocked',
            api_key_issued: 'API key issued',
            api_key_revoked: 'API key revoked',
            user_updated: 'User updated',
            policy_updated: 'Policy updated',
            ruleset_updated: 'Ruleset updated',
            github_webhook_received: 'GitHub webhook received',
            gitlab_webhook_received: 'GitLab webhook received',
            github_check_published: 'GitHub check published',
            gitlab_status_published: 'GitLab status published',
            integration_job_enqueued: 'Integration job queued',
            integration_job_retry_scheduled: 'Integration retry scheduled',
            integration_job_succeeded: 'Integration job succeeded',
            integration_job_failed: 'Integration job failed',
            integration_secrets_updated: 'Integration secrets updated'
        };
        if (labels[action]) {
            return labels[action];
        }
        return action
            .split('_')
            .filter(Boolean)
            .map(part => part.charAt(0).toUpperCase() + part.slice(1))
            .join(' ') || 'Activity';
    }

    describeActivitySummary(event) {
        const parts = [];
        if (event?.project_id) {
            parts.push(`project ${event.project_id}`);
        }
        if (event?.scan_id) {
            parts.push(`scan ${event.scan_id}`);
        }
        const actor = this.formatActorLabel(event?.actor);
        if (actor) {
            parts.push(`actor ${actor}`);
        }
        if (parts.length === 0) {
            return 'System activity';
        }
        return parts.join(' | ');
    }

    formatActorLabel(rawActor) {
        const actor = String(rawActor || '').trim();
        if (!actor) {
            return '';
        }

        const normalized = actor.toLowerCase();
        const userID = String(this.identity?.userID || '').trim().toLowerCase();
        const subject = String(this.identity?.subject || '').trim().toLowerCase();
        const email = String(this.identity?.email || '').trim().toLowerCase();

        if (normalized === 'anonymous') {
            return 'Anonymous';
        }
        if (normalized === 'env') {
            return 'Environment';
        }
        if (normalized === email || normalized === userID || normalized === subject) {
            return 'You';
        }
        if (normalized.startsWith('session_user:')) {
            const id = actor.slice('session_user:'.length).trim();
            if (id && id.toLowerCase() === userID) {
                return 'You';
            }
            return id ? `User ${id}` : 'Session user';
        }
        if (normalized.startsWith('api_key:')) {
            const keyRef = actor.slice('api_key:'.length).trim();
            return keyRef ? `API key ${keyRef}` : 'API key';
        }
        if (normalized.startsWith('oidc:')) {
            const oidcSubject = actor.slice('oidc:'.length).trim();
            if (oidcSubject && oidcSubject.toLowerCase() === subject) {
                return 'You';
            }
            return oidcSubject ? `OIDC ${oidcSubject}` : 'OIDC user';
        }
        if (actor.includes('@')) {
            if (normalized === email) {
                return 'You';
            }
            return actor;
        }
        return actor;
    }

    updateUserUI(user = {}) {
        const role = String(user.role || this.authz?.role || '').trim().toLowerCase();
        const email = String(user.email || this.identity?.email || '').trim().toLowerCase();
        const subject = String(this.identity?.subject || '').trim();
        const displayName = email
            ? email.split('@')[0]
            : (String(user.name || '').trim() || (role ? role : 'User'));
        const initials = displayName.replace(/[^a-z0-9]/gi, '').slice(0, 2).toUpperCase() || 'OP';

        const userElement = document.getElementById('dashboard-user-name');
        if (userElement) {
            userElement.textContent = displayName;
        }

        const headerAvatar = document.getElementById('dashboard-user-avatar');
        if (headerAvatar) {
            headerAvatar.textContent = initials;
        }

        const profileAvatar = document.getElementById('dashboard-profile-avatar');
        if (profileAvatar) {
            profileAvatar.textContent = initials;
        }

        const profileName = document.getElementById('dashboard-profile-name');
        if (profileName) {
            profileName.textContent = displayName;
        }

        const profileEmail = document.getElementById('dashboard-profile-email');
        if (profileEmail) {
            profileEmail.textContent = email || subject || 'No email available';
        }

        const statusBadge = document.getElementById('dashboard-profile-status-badge');
        if (statusBadge) {
            statusBadge.textContent = this.identity?.userID || email || subject ? 'Active' : 'Checking';
            statusBadge.className = this.identity?.userID || email || subject
                ? 'inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800'
                : 'inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-700';
        }

        const roleBadge = document.getElementById('dashboard-profile-role-badge');
        if (roleBadge) {
            const normalizedRole = role || 'viewer';
            roleBadge.textContent = normalizedRole.charAt(0).toUpperCase() + normalizedRole.slice(1);
            roleBadge.className = normalizedRole === 'admin'
                ? 'inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-orange-100 text-orange-800'
                : normalizedRole === 'operator'
                    ? 'inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800'
                    : 'inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-700';
        }
    }

    setupEventListeners() {
        const searchInput = document.getElementById('dashboard-search');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.handleSearch(e.target.value);
            });
        }

        const docsButton = document.getElementById('api-docs-button');
        if (docsButton) {
            docsButton.addEventListener('click', () => {
                window.open('/openapi.yaml', '_blank', 'noopener,noreferrer');
            });
        }

        const notificationsButton = document.getElementById('notifications-button');
        if (notificationsButton) {
            notificationsButton.addEventListener('click', async () => {
                await this.openNotificationsModal();
            });
        }
    }

    handleSearch(query) {
        const normalized = String(query || '').trim().toLowerCase();
        const currentTabRoot = document.getElementById(`${this.currentTab}-tab`);
        if (!currentTabRoot) {
            return;
        }

        const rows = currentTabRoot.querySelectorAll('tbody tr');
        if (!rows.length) {
            return;
        }

        rows.forEach((row) => {
            const text = (row.textContent || '').toLowerCase();
            row.style.display = normalized === '' || text.includes(normalized) ? '' : 'none';
        });
    }

    async signOut() {
        try {
            await this.apiRequest('/v1/auth/session', {
                method: 'DELETE'
            });
        } catch (_) {
            // Continue redirect even if API logout fails.
        }
        window.location.href = '/signin.html';
    }

    showError(message) {
        this.showToast(message, 'error');
    }

    showSuccess(message) {
        this.showToast(message, 'success');
    }

    showToast(message, kind) {
        const errorDiv = document.createElement('div');
        errorDiv.className = kind === 'success'
            ? 'fixed top-4 right-4 bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded z-50'
            : 'fixed top-4 right-4 bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded z-50';
        errorDiv.textContent = message;
        document.body.appendChild(errorDiv);
        
        setTimeout(() => {
            errorDiv.remove();
        }, 5000);
    }

    escapeHtml(value) {
        return String(value ?? '')
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#39;');
    }

    formatDate(timestamp) {
        if (!timestamp) return 'N/A';
        const date = new Date(timestamp);
        if (Number.isNaN(date.getTime())) return 'N/A';
        return date.toLocaleString();
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.baselineDashboard = new BaselineDashboard();

    // Legacy onclick bindings from static template markup.
    window.generateReport = () => window.baselineDashboard?.generateReport();
});

// Handle responsive sidebar
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('-translate-x-full');
}

// Add mobile responsiveness
if (window.innerWidth < 768) {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.add('-translate-x-full');
    
    // Add mobile menu button
    const mobileMenuButton = document.createElement('button');
    mobileMenuButton.className = 'fixed top-4 left-4 z-50 p-2 bg-white rounded-lg shadow-lg md:hidden';
    mobileMenuButton.innerHTML = `
        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path>
        </svg>
    `;
    mobileMenuButton.addEventListener('click', toggleSidebar);
    document.body.appendChild(mobileMenuButton);
}
