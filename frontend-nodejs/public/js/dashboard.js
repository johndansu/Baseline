import { DashboardAPIClient } from './api-client.js';
import { renderAuditTable as renderDashboardAuditTable } from './dashboard-audit-table.js';
import {
    renderCLITelemetryPanel as renderDashboardCLITelemetryPanel,
    renderCLITraceDetailContent as renderDashboardCLITraceDetailContent
} from './dashboard-cli-telemetry.js';
import { bindAPIKeyActionButtons as bindDashboardAPIKeyActionButtons } from './dashboard-key-actions.js';
import {
    bindGenerateKeyForm as bindDashboardGenerateKeyForm,
    copyIssuedAPIKey as copyDashboardIssuedAPIKey,
    openIssuedKeyModal as openDashboardIssuedKeyModal,
    prepareGenerateKeyModal as prepareDashboardGenerateKeyModal,
    setGenerateKeyFeedback as setDashboardGenerateKeyFeedback,
    submitGenerateKeyForm as submitDashboardGenerateKeyForm
} from './dashboard-key-form.js';
import { renderApiKeysTable as renderDashboardApiKeysTable } from './dashboard-key-table.js';
import {
    bindModalTriggerButtons as bindDashboardModalTriggerButtons,
    closeModal as closeDashboardModal,
    openModal as openDashboardModal
} from './dashboard-modal-actions.js';
import {
    handleDashboardSearch,
    mountDashboardApplication,
    setupDashboardShellEvents,
    signOutDashboard
} from './dashboard-shell.js';
import {
    countUnreadNotifications as countDashboardUnreadNotifications,
    getUnreadNotifications as getDashboardUnreadNotifications,
    groupNotifications as groupDashboardNotifications,
    isNotificationUnread as isDashboardNotificationUnread,
    markAllNotificationsRead as markAllDashboardNotificationsRead,
    renderNotificationCard as renderDashboardNotificationCard,
    renderNotificationSection as renderDashboardNotificationSection,
    renderNotifications as renderDashboardNotifications,
    selectNotifications as selectDashboardNotifications,
    updateNotificationsIndicator as updateDashboardNotificationsIndicator
} from './dashboard-notifications.js';
import {
    countNotificationGroups as countDashboardNotificationGroups,
    isAttentionNotification as isDashboardAttentionNotification,
    isImportantNotification as isDashboardImportantNotification,
    loadReadNotificationIDs as loadDashboardReadNotificationIDs,
    notificationActionLabel as getDashboardNotificationActionLabel,
    notificationStorageKey as getDashboardNotificationStorageKey,
    notificationSummary as getDashboardNotificationSummary,
    notificationTargetLabel as getDashboardNotificationTargetLabel,
    notificationTargetTab as getDashboardNotificationTargetTab,
    notificationTitle as getDashboardNotificationTitle,
    notificationTone as getDashboardNotificationTone,
    persistReadNotificationIDs as persistDashboardReadNotificationIDs
} from './dashboard-notification-meta.js';
import { bindProjectActionButtons as bindDashboardProjectActionButtons } from './dashboard-project-actions.js';
import {
    bindAddProjectForm as bindDashboardAddProjectForm,
    openEditProjectModal as openDashboardEditProjectModal,
    prepareAddProjectModal as prepareDashboardAddProjectModal,
    setAddProjectFeedback as setDashboardAddProjectFeedback,
    submitAddProjectForm as submitDashboardAddProjectForm
} from './dashboard-project-form.js';
import {
    bindProjectOwnerForm as bindDashboardProjectOwnerForm,
    claimProject as claimDashboardProject,
    currentPrincipalOwnerID as getDashboardCurrentPrincipalOwnerID,
    describeProjectOwner as describeDashboardProjectOwner,
    openProjectOwnerModal as openDashboardProjectOwnerModal,
    prepareProjectOwnerModal as prepareDashboardProjectOwnerModal,
    setProjectOwnerFeedback as setDashboardProjectOwnerFeedback,
    submitProjectOwnerForm as submitDashboardProjectOwnerForm
} from './dashboard-project-owner.js';
import {
    openProjectDetailsModal as openDashboardProjectDetailsModal,
    renderProjectDetails as renderDashboardProjectDetails,
    setProjectDetailsContent as setDashboardProjectDetailsContent
} from './dashboard-project-details.js';
import { loadProjectsData as loadDashboardProjectsData } from './dashboard-project-data.js';
import { renderProjectsTable as renderDashboardProjectsTable } from './dashboard-project-table.js';
import { bindScanReportButtons as bindDashboardScanReportButtons } from './dashboard-scan-actions.js';
import { loadScansData as loadDashboardScansData } from './dashboard-scan-data.js';
import {
    applyScansFiltersAndRender as applyDashboardScansFiltersAndRender,
    bindScansControls as bindDashboardScansControls,
    renderScansTable as renderDashboardScansTable
} from './dashboard-scan-controls.js';
import { renderScansPage as renderDashboardScansPage } from './dashboard-scan-table.js';
import {
    adminUserRowKey as getDashboardAdminUserRowKey,
    setSelectedUserStatus as setDashboardSelectedUserStatus,
    submitAdminUserUpdate as submitDashboardAdminUserUpdate
} from './dashboard-user-actions.js';
import {
    activityFilterDateToRFC3339 as toDashboardActivityFilterDate,
    buildSelectedUserActivityPath as buildDashboardSelectedUserActivityPath,
    loadMoreSelectedUserActivity as loadMoreDashboardSelectedUserActivity,
    viewAdminUserDetail as viewDashboardAdminUserDetail
} from './dashboard-user-details.js';
import {
    getUserSortText as getDashboardUserSortText,
    getUserSortTime as getDashboardUserSortTime,
    renderUsersTab as renderDashboardUsersTab,
    sortUsersRows as sortDashboardUsersRows,
    userSortDescriptor as getDashboardUserSortDescriptor,
    userSortIndicator as getDashboardUserSortIndicator
} from './dashboard-users-tab.js';
import {
    getSupabaseSettingsClient as getDashboardSupabaseSettingsClient,
    resetDashboardPreferencesFromSettings as resetDashboardSettingsPreferences,
    saveDashboardPreferencesFromSettings as saveDashboardSettingsPreferences,
    savePasswordSettings as saveDashboardPasswordSettings,
    saveProfileSettings as saveDashboardProfileSettings
} from './dashboard-settings-actions.js';
import { bindSettingsControls as bindDashboardSettingsControls } from './dashboard-settings-bind.js';
import {
    renderCLISessionsList as renderDashboardCLISessionsList,
    renderSettingsActionButton as renderDashboardSettingsActionButton,
    renderSettingsPanel as renderDashboardSettingsPanel
} from './dashboard-settings-render.js';

const BUILTIN_POLICY_CATALOG = [
    { name: 'A1', description: 'Primary branch protection requires pull requests and direct push restrictions.' },
    { name: 'B1', description: 'CI workflows must run on pull requests and execute tests.' },
    { name: 'C1', description: 'Automated tests must exist.' },
    { name: 'D1', description: 'Plaintext secrets and token patterns must not appear in scannable files.' },
    { name: 'E1', description: 'Dependency management files must exist.' },
    { name: 'F1', description: 'README and license requirements must be met.' },
    { name: 'G1', description: 'Risky code patterns are blocked, including unsafe pointer and SQL string building.' },
    { name: 'H1', description: 'Deployment config must exist and Dockerfiles must run as non-root.' },
    { name: 'I1', description: 'Infrastructure-as-code artifacts must exist.' },
    { name: 'J1', description: 'An environment template such as .env.example must exist.' },
    { name: 'K1', description: 'Backup and recovery documentation or scripts must exist.' },
    { name: 'L1', description: 'Logging and monitoring configuration or documentation must exist.' },
    { name: 'R1', description: 'Rollback documentation must exist.' }
];

// Baseline Dashboard JavaScript
class BaselineDashboard {
    constructor() {
        this.autoRefreshIntervalMs = 60000;
        this.autoRefreshTimer = null;
        this.isRefreshing = false;
        this.dashboardStream = null;
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
            displayName: '',
            userID: '',
            email: '',
            subject: '',
            identitySource: ''
        };
        this.supabaseClient = null;
        this.chart = null;
        this.usageRange = 'last_month';
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
            byID: new Map(),
            scansByProject: new Map()
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
        this.settingsState = {
            cliSessions: [],
            selectedCLISessionID: '',
            cliSessionDetails: {}
        };
        this.cliApprovalState = {
            userCode: ''
        };
        this.userActivityEventTypeCatalog = [];
        this.userActivityEventTypesPromise = null;
        this.pendingProjectEditID = '';
        this.pendingProjectDetailsID = '';
        this.pendingProjectOwnerID = '';
        this.pendingKeyRevokeID = '';
        this.lastIssuedAPIKey = '';
        this.lastIssuedAPIKeyMeta = null;
        this.dashboardSummary = {
            metrics: {},
            recentScans: []
        };
        this.cliState = {
            traces: [],
            details: {},
            selectedTraceID: '',
            filters: {
                command: 'all',
                repository: 'all',
                status: 'all',
                project: 'all',
                quick: 'all',
                query: ''
            }
        };
        this.notificationsState = {
            items: [],
            readIDs: new Set()
        };
        this.preferences = this.loadDashboardPreferences();
        this.autoRefreshIntervalMs = this.preferences.refreshIntervalMs;
        this.currentTab = this.preferences.defaultTab;
        this.init();
    }

    handleUnauthorized() {
        if (this.dashboardStream) {
            this.dashboardStream.close();
            this.dashboardStream = null;
        }
        const returnTarget = `${window.location.pathname || '/dashboard'}${window.location.search || ''}${window.location.hash || ''}`;
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
            'integrations.read': false,
            'integrations.write': false,
            'integrations.secrets.write': false
        };
    }

    adminCapabilities() {
        return Object.keys(this.defaultCapabilities()).reduce((acc, capability) => {
            acc[capability] = true;
            return acc;
        }, {});
    }

    settingsStorageKey() {
        const subject = String(this.identity?.subject || this.identity?.userID || this.identity?.email || 'anonymous').trim().toLowerCase();
        return `baseline.dashboard.settings.${subject || 'anonymous'}`;
    }

    loadDashboardPreferences() {
        const defaults = {
            defaultTab: 'overview',
            refreshIntervalMs: 60000
        };
        try {
            const raw = window.localStorage.getItem(this.settingsStorageKey());
            if (!raw) {
                return defaults;
            }
            const parsed = JSON.parse(raw);
            const refreshIntervalMs = Number(parsed?.refreshIntervalMs);
            const defaultTab = String(parsed?.defaultTab || defaults.defaultTab).trim().toLowerCase();
            return {
                defaultTab: defaultTab || defaults.defaultTab,
                refreshIntervalMs: [30000, 60000, 120000].includes(refreshIntervalMs) ? refreshIntervalMs : defaults.refreshIntervalMs
            };
        } catch (_) {
            return defaults;
        }
    }

    persistDashboardPreferences(nextPreferences) {
        this.preferences = {
            defaultTab: String(nextPreferences?.defaultTab || 'overview').trim().toLowerCase() || 'overview',
            refreshIntervalMs: [30000, 60000, 120000].includes(Number(nextPreferences?.refreshIntervalMs))
                ? Number(nextPreferences.refreshIntervalMs)
                : 60000
        };
        this.autoRefreshIntervalMs = this.preferences.refreshIntervalMs;
        try {
            window.localStorage.setItem(this.settingsStorageKey(), JSON.stringify(this.preferences));
        } catch (_) {
            // Ignore storage failures; the UI can still use in-memory settings.
        }
        this.setupAutoRefresh();
    }

    applyRefreshIntervalPreference() {
        const nextInterval = Number(this.preferences?.refreshIntervalMs || 60000);
        this.autoRefreshIntervalMs = [30000, 60000, 120000].includes(nextInterval) ? nextInterval : 60000;
        this.setupAutoRefresh();
    }

    init() {
        this.setupTabNavigation();
        this.initializeChart();
        this.setupEventListeners();
        this.bindOverviewControls();
        this.setupAutoRefresh();
        this.bindModalTriggerButtons(document);
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
        this.setupDashboardStream();
        await this.loadCapabilities();
        if (this.isAdmin()) {
            this.apiKeyState.mode = 'me';
            this.apiKeyState.targetUserID = '';
        } else {
            this.apiKeyState.mode = 'me';
            this.apiKeyState.targetUserID = '';
        }
        this.applyCapabilitiesToNavigation();
        const preferredTab = String(this.preferences?.defaultTab || 'overview').trim().toLowerCase();
        if (preferredTab && preferredTab !== this.currentTab && this.canAccessTab(preferredTab)) {
            this.currentTab = preferredTab;
        }
        if (!this.canAccessTab(this.currentTab)) {
            const fallback = this.firstAllowedTab();
            if (fallback) {
                this.currentTab = fallback;
                this.switchTab(fallback);
                return;
            }
        }
        await this.loadDashboardData();
        this.switchTab(this.currentTab);
        this.handlePendingCLILoginApproval();
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
                displayName: String(payload.display_name || '').trim(),
                userID: String(payload.user_id || '').trim(),
                email: String(payload.email || '').trim().toLowerCase(),
                subject: String(payload.subject || '').trim(),
                identitySource: String(payload.identity_source || '').trim().toLowerCase()
            };
            this.preferences = this.loadDashboardPreferences();
            this.autoRefreshIntervalMs = this.preferences.refreshIntervalMs;
            this.setupAutoRefresh();
            this.notificationsState.readIDs = this.loadReadNotificationIDs();
            this.updateUserUI({
                displayName: String(payload.display_name || ''),
                name: String(payload.display_name || payload.user || ''),
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
            const role = String(payload?.role || 'viewer').toLowerCase() || 'viewer';
            this.authz = {
                role,
                source: String(payload?.source || 'session').toLowerCase() || 'session',
                capabilities: {
                    ...this.defaultCapabilities(),
                    ...fromServer,
                    ...(role === 'admin' ? this.adminCapabilities() : {})
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
            case 'audit':
                return this.hasCapability('audit.read');
            case 'cli':
                return this.isAdmin() && this.hasCapability('audit.read');
            default:
                return false;
        }
    }

    firstAllowedTab() {
        const orderedTabs = ['overview', 'scans', 'policies', 'projects', 'users', 'keys', 'audit', 'cli', 'settings'];
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
            item.classList.remove('bg-blue-50', 'text-blue-700', 'bg-gray-100', 'text-gray-900', 'bg-orange-50', 'text-orange-700');
            item.classList.add('text-gray-600', 'hover:bg-gray-50', 'hover:text-gray-900');
            item.style.backgroundColor = '';
            item.style.color = '';
        });

        const activeItem = document.querySelector(`[data-tab="${tabName}"]`);
        if (activeItem) {
            activeItem.classList.remove('text-gray-600', 'hover:bg-gray-50', 'hover:text-gray-900');
            activeItem.classList.add('bg-orange-50', 'text-orange-700');
            activeItem.style.backgroundColor = '#fff7ed';
            activeItem.style.color = '#c2410c';
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
        
        this.currentTab = tabName;

        // Load tab-specific data
        this.loadTabData(tabName);
    }

    updatePageHeader(tabName) {
        const titles = {
            overview: { title: 'Dashboard', subtitle: 'Monitor policy compliance and scan results' },
            scans: { title: 'Scan History', subtitle: 'View past scan results and enforcement outcomes' },
            policies: { title: 'Policies', subtitle: 'Deterministic production-readiness checks (A1–R1)' },
            projects: { title: 'Projects', subtitle: 'Repositories tracked by Baseline' },
            users: { title: 'Users', subtitle: 'Admin user and role management' },
            keys: { title: 'API Keys', subtitle: 'Manage API authentication keys and tokens' },
            audit: { title: 'Audit Log', subtitle: 'Enforcement activity and event trail' },
            cli: { title: 'CLI Telemetry', subtitle: 'Admin supervision for command activity, failures, and generated artifacts' },
            settings: { title: 'Settings', subtitle: 'Profile, preferences, and dashboard tools' }
        };

        const meta = titles[tabName] || titles.overview;
        document.getElementById('page-title').textContent = meta.title;
        document.getElementById('page-subtitle').textContent = meta.subtitle;
    }

    initializeChart() {
        const ctx = document.getElementById('usageChart');
        if (!ctx) return;
        if (typeof window.Chart !== 'function') {
            console.warn('Chart.js failed to load; usage trends chart is unavailable.');
            return;
        }

        try {
            this.chart = new window.Chart(ctx, {
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
        } catch (error) {
            console.error('Unable to initialize usage trends chart.', error);
            this.chart = null;
        }
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

    setupAutoRefresh() {
        if (this.autoRefreshTimer) {
            window.clearInterval(this.autoRefreshTimer);
        }

        this.autoRefreshTimer = window.setInterval(() => {
            this.refreshVisibleData();
        }, this.autoRefreshIntervalMs);

        if (!this.autoRefreshEventsBound) {
            this.autoRefreshEventsBound = true;
            document.addEventListener('visibilitychange', () => {
                if (document.visibilityState === 'visible') {
                    this.ensureDashboardStream();
                    this.refreshVisibleData();
                } else {
                    this.teardownDashboardStream();
                }
            });

            window.addEventListener('focus', () => {
                this.ensureDashboardStream();
                this.refreshVisibleData();
            });
        }
    }

    teardownDashboardStream() {
        if (this.dashboardStream) {
            this.dashboardStream.close();
            this.dashboardStream = null;
        }
    }

    ensureDashboardStream() {
        if (document.visibilityState === 'hidden') {
            return;
        }
        if (this.dashboardStream) {
            return;
        }
        this.setupDashboardStream();
    }

    setupDashboardStream() {
        if (typeof window.EventSource !== 'function') {
            return;
        }
        if (document.visibilityState === 'hidden') {
            return;
        }
        this.teardownDashboardStream();

        this.dashboardStream = new window.EventSource('/v1/dashboard/stream');
        this.dashboardStream.addEventListener('refresh', () => {
            this.refreshVisibleData();
        });
        this.dashboardStream.addEventListener('ready', () => {
            // stream connected
        });
        this.dashboardStream.onerror = () => {
            this.teardownDashboardStream();
            if (document.visibilityState !== 'hidden') {
                window.setTimeout(() => {
                    this.ensureDashboardStream();
                }, 3000);
            }
        };
    }

    async refreshVisibleData() {
        if (this.isRefreshing || document.visibilityState === 'hidden') {
            return;
        }

        this.isRefreshing = true;
        try {
            await this.loadDashboardData();

            switch (this.currentTab) {
            case 'projects':
                await this.loadProjectsData();
                break;
            case 'scans':
                await this.loadScansData();
                break;
            case 'policies':
                await this.loadPoliciesData();
                break;
            case 'keys':
                await this.loadApiKeysData();
                break;
            case 'audit':
                await this.loadAuditData();
                break;
            case 'cli':
                await this.loadCLITelemetryData();
                break;
            default:
                break;
            }
        } finally {
            this.isRefreshing = false;
        }
    }

    async loadOverviewStats() {
        try {
            const rangeQuery = encodeURIComponent(this.usageRange || 'last_month');
            const data = await this.apiRequest(`/v1/dashboard?activity_range=${rangeQuery}`);
            const metrics = data && typeof data.metrics === 'object' && data.metrics ? data.metrics : {};
            const recentScans = Array.isArray(data?.recent_scans) ? data.recent_scans : [];
            const scanActivity = Array.isArray(data?.scan_activity) ? data.scan_activity : [];
            const topViolations = Array.isArray(data?.top_violations) ? data.top_violations : [];
            this.usageRange = String(data?.activity_range || this.usageRange || 'last_month').trim().toLowerCase();
            const usageRangeSelect = document.getElementById('usage-range-select');
            if (usageRangeSelect && usageRangeSelect.value !== this.usageRange) {
                usageRangeSelect.value = this.usageRange;
            }
            this.dashboardSummary = {
                metrics,
                recentScans,
                scanActivity
            };
            this.updateStatsCards(metrics);
            this.updateQuickStatsPanel(metrics, topViolations);
            try {
                this.updateUsageChart(scanActivity, recentScans);
            } catch (error) {
                console.error('Unable to refresh usage trends chart.', error);
            }
        } catch (error) {
            this.showError(error.message || 'Failed to load dashboard metrics');
        }
    }

    updateStatsCards(metrics) {
        this.renderOverviewStatsCards(metrics);
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

    updateUsageChart(scanActivity, recentScans) {
        const ctx = document.getElementById('usageChart');
        if (!ctx || typeof window.Chart !== 'function') {
            return;
        }
        let activity = Array.isArray(scanActivity) ? scanActivity : [];
        if (!activity.length) {
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            const dayKeys = [];
            for (let i = 6; i >= 0; i -= 1) {
                const day = new Date(today);
                day.setDate(today.getDate() - i);
                dayKeys.push(day.toISOString().slice(0, 10));
            }
            const fallbackCounts = new Map(dayKeys.map((key) => [key, { scans: 0, failing_scans: 0 }]));
            for (const scan of recentScans) {
                const createdAt = new Date(scan?.created_at || '');
                if (Number.isNaN(createdAt.getTime())) {
                    continue;
                }
                const key = createdAt.toISOString().slice(0, 10);
                if (!fallbackCounts.has(key)) {
                    continue;
                }
                const point = fallbackCounts.get(key);
                point.scans += 1;
                const status = String(scan?.status || '').toLowerCase();
                if (status === 'fail' || status === 'failed') {
                    point.failing_scans += 1;
                }
            }
            activity = dayKeys.map((key) => ({
                date: key,
                label: new Date(`${key}T00:00:00Z`).toLocaleDateString(undefined, { weekday: 'short' }),
                scans: fallbackCounts.get(key)?.scans || 0,
                failing_scans: fallbackCounts.get(key)?.failing_scans || 0
            }));
        }

        if (this.chart) {
            this.chart.destroy();
            this.chart = null;
        }

        this.chart = new window.Chart(ctx, {
            type: 'line',
            data: {
                labels: activity.map((point) => point.label || point.date || ''),
                datasets: [{
                    label: 'Scans',
                    data: activity.map((point) => Number(point?.scans || 0)),
                    borderColor: 'rgb(59, 130, 246)',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4
                }, {
                    label: 'Failing Scans',
                    data: activity.map((point) => Number(point?.failing_scans || 0)),
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
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    },
                    x: {
                        ticks: {
                            maxRotation: 0,
                            autoSkip: true,
                            maxTicksLimit: this.usageRange === 'today' ? 8 : this.usageRange === 'last_year' ? 12 : 10
                        }
                    }
                }
            }
        });
    }

    bindOverviewControls() {
        const usageRangeSelect = document.getElementById('usage-range-select');
        if (!usageRangeSelect) {
            return;
        }
        usageRangeSelect.value = this.usageRange;
        usageRangeSelect.addEventListener('change', async (event) => {
            const nextRange = String(event.target?.value || 'last_month').trim().toLowerCase();
            this.usageRange = nextRange || 'last_month';
            await this.loadOverviewStats();
        });
    }

    builtInPolicyCatalog() {
        return BUILTIN_POLICY_CATALOG.map((policy) => ({
            ...policy,
            latest_version: '',
            updated_at: '',
            version_count: 0,
            content_keys: 0,
            metadata_keys: 0,
            source: 'builtin'
        }));
    }

    mergePoliciesWithCatalog(policies) {
        const merged = new Map(this.builtInPolicyCatalog().map((policy) => [policy.name, policy]));
        for (const policy of policies) {
            const name = String(policy?.name || '').trim();
            if (!name) continue;
            merged.set(name, {
                ...merged.get(name),
                ...policy,
                name,
                source: 'published'
            });
        }
        return [...merged.values()].sort((a, b) => a.name.localeCompare(b.name));
    }

    updateQuickStatsPanel(metrics, topViolations) {
        this.renderQuickStatsPanel();
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
        const updatedAt = document.getElementById('quick-stats-updated-at');
        if (updatedAt) {
            updatedAt.textContent = `Updated ${new Date().toLocaleTimeString()}`;
        }
    }

    renderOverviewStatsCards(metrics) {
        const container = document.getElementById('overview-stats-grid');
        if (!container) return;
        const values = {
            scans: Number(metrics?.scans ?? 0),
            failing: Number(metrics?.failing_scans ?? 0),
            blocking: Number(metrics?.blocking_violations ?? 0),
            projects: Number(metrics?.projects ?? 0)
        };
        container.innerHTML = `
            <div id="overview-stat-scans" class="bg-white p-6 rounded-lg border border-gray-200">
                <div class="flex items-center justify-between mb-4">
                    <div class="p-2 rounded-lg">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                        </svg>
                    </div>
                    <span id="overview-stat-scans-badge" class="text-xs font-medium text-gray-500 uppercase tracking-wide">Δ 0</span>
                </div>
                <h3 class="text-2xl font-bold text-gray-900">${values.scans}</h3>
                <p class="text-sm text-gray-700">Total Scans</p>
            </div>
            <div id="overview-stat-failing" class="bg-white p-6 rounded-lg border border-gray-200">
                <div class="flex items-center justify-between mb-4">
                    <div class="p-2 rounded-lg">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                    </div>
                    <span id="overview-stat-failing-badge" class="text-xs font-medium text-gray-500 uppercase tracking-wide">Δ 0</span>
                </div>
                <h3 class="text-2xl font-bold text-gray-900">${values.failing}</h3>
                <p class="text-sm text-gray-700">Failing Scans</p>
            </div>
            <div id="overview-stat-blocking" class="bg-white p-6 rounded-lg border border-gray-200">
                <div class="flex items-center justify-between mb-4">
                    <div class="p-2 rounded-lg">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                        </svg>
                    </div>
                    <span id="overview-stat-blocking-badge" class="text-xs font-medium text-gray-500 uppercase tracking-wide">Δ 0</span>
                </div>
                <h3 class="text-2xl font-bold text-gray-900">${values.blocking}</h3>
                <p class="text-sm text-gray-700">Blocking Violations</p>
            </div>
            <div id="overview-stat-projects" class="bg-white p-6 rounded-lg border border-gray-200">
                <div class="flex items-center justify-between mb-4">
                    <div class="p-2 rounded-lg">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
                        </svg>
                    </div>
                    <span id="overview-stat-projects-badge" class="text-xs font-medium text-gray-500 uppercase tracking-wide">Δ 0</span>
                </div>
                <h3 class="text-2xl font-bold text-gray-900">${values.projects}</h3>
                <p class="text-sm text-gray-700">Projects</p>
            </div>
        `;
    }

    renderQuickStatsPanel() {
        const panel = document.getElementById('quick-stats-panel');
        if (!panel) return;
        panel.innerHTML = `
            <h3 class="text-lg font-semibold text-gray-900 mb-4">Quick Stats</h3>
            <div class="space-y-4">
                <div class="flex justify-between items-center">
                    <span class="text-sm text-gray-700">Scan Success Rate</span>
                    <span id="quick-success-rate-value" class="text-sm font-medium text-gray-900">0%</span>
                </div>
                <div class="w-full bg-gray-200 rounded-full h-2">
                    <div id="quick-success-rate-bar" class="h-2 rounded-full" style="width: 0%; background-color: #ea580c"></div>
                </div>
                <div class="flex justify-between items-center">
                    <span class="text-sm text-gray-700">Failing Scan Rate</span>
                    <span id="quick-fail-rate-value" class="text-sm font-medium text-gray-900">0%</span>
                </div>
                <div class="w-full bg-gray-200 rounded-full h-2">
                    <div id="quick-fail-rate-bar" class="bg-orange-500 h-2 rounded-full" style="width: 0%"></div>
                </div>
                <div class="flex justify-between items-center">
                    <span class="text-sm text-gray-700">Top Violation</span>
                    <span id="quick-top-violation-value" class="text-xs font-medium text-gray-900">None</span>
                </div>
                <div class="w-full bg-gray-200 rounded-full h-2">
                    <div id="quick-top-violation-bar" class="bg-yellow-600 h-2 rounded-full" style="width: 0%"></div>
                </div>
                <div class="text-xs text-gray-600">
                    Blocking violations: <span id="quick-blocking-count" class="font-semibold text-gray-900">0</span>
                </div>
                <div class="text-[11px] text-gray-400" id="quick-stats-updated-at"></div>
            </div>
        `;
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
        updateDashboardNotificationsIndicator(this);
    }

    async openNotificationsModal() {
        openDashboardModal('notificationsModal');
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
        renderDashboardNotifications(this, items);
    }

    renderNotificationSection(title, subtitle, items) {
        return renderDashboardNotificationSection(this, title, subtitle, items);
    }

    renderNotificationCard(item) {
        return renderDashboardNotificationCard(this, item);
    }

    groupNotifications(items) {
        return groupDashboardNotifications(this, items);
    }

    selectNotifications(items) {
        return selectDashboardNotifications(this, items);
    }

    isNotificationUnread(item) {
        return isDashboardNotificationUnread(this, item);
    }

    countUnreadNotifications(items) {
        return countDashboardUnreadNotifications(this, items);
    }

    getUnreadNotifications() {
        return getDashboardUnreadNotifications(this);
    }

    markAllNotificationsRead() {
        markAllDashboardNotificationsRead(this);
    }

    notificationStorageKey() {
        return getDashboardNotificationStorageKey(this);
    }

    loadReadNotificationIDs() {
        return loadDashboardReadNotificationIDs(this);
    }

    persistReadNotificationIDs() {
        return persistDashboardReadNotificationIDs(this);
    }

    isImportantNotification(item) {
        return isDashboardImportantNotification(this, item);
    }

    isAttentionNotification(item) {
        return isDashboardAttentionNotification(this, item);
    }

    countNotificationGroups(items) {
        return countDashboardNotificationGroups(this, items);
    }

    notificationTone(item) {
        return getDashboardNotificationTone(this, item);
    }

    notificationTargetTab(item) {
        return getDashboardNotificationTargetTab(this, item);
    }

    notificationTargetLabel(tab) {
        return getDashboardNotificationTargetLabel(this, tab);
    }

    notificationActionLabel(item, targetTab) {
        return getDashboardNotificationActionLabel(this, item, targetTab);
    }

    notificationTitle(item) {
        return getDashboardNotificationTitle(this, item);
    }

    notificationSummary(item) {
        return getDashboardNotificationSummary(this, item);
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
            case 'audit':
                await this.loadAuditData();
                break;
            case 'cli':
                await this.loadCLITelemetryData();
                break;
            case 'settings':
                await this.loadSettingsData();
                break;
        }
    }

    async loadScansData() {
        return loadDashboardScansData(this);
    }

    bindAddProjectForm() {
        return bindDashboardAddProjectForm(this);
    }

    prepareAddProjectModal() {
        return prepareDashboardAddProjectModal(this);
    }

    setAddProjectFeedback(message, isError) {
        return setDashboardAddProjectFeedback(message, isError);
    }

    async submitAddProjectForm() {
        return submitDashboardAddProjectForm(this);
    }

    openEditProjectModal(projectID) {
        return openDashboardEditProjectModal(this, projectID);
    }

    bindProjectOwnerForm() {
        return bindDashboardProjectOwnerForm(this);
    }

    async prepareProjectOwnerModal() {
        return prepareDashboardProjectOwnerModal(this);
    }

    setProjectOwnerFeedback(message, isError) {
        return setDashboardProjectOwnerFeedback(message, isError);
    }

    async submitProjectOwnerForm() {
        return submitDashboardProjectOwnerForm(this);
    }

    async claimProject(projectID) {
        return claimDashboardProject(this, projectID);
    }

    async openProjectDetailsModal(projectID) {
        return openDashboardProjectDetailsModal(this, projectID);
    }

    setProjectDetailsContent(markup) {
        setDashboardProjectDetailsContent(this, markup);
    }

    renderProjectDetails(project, scans) {
        return renderDashboardProjectDetails(this, project, scans);
    }

    openProjectOwnerModal(projectID) {
        return openDashboardProjectOwnerModal(this, projectID);
    }

    currentPrincipalOwnerID() {
        return getDashboardCurrentPrincipalOwnerID(this);
    }

    describeProjectOwner(ownerID) {
        return describeDashboardProjectOwner(this, ownerID);
    }

    bindGenerateKeyForm() {
        return bindDashboardGenerateKeyForm(this);
    }

    prepareGenerateKeyModal() {
        return prepareDashboardGenerateKeyModal(this);
    }

    setGenerateKeyFeedback(message, isError) {
        return setDashboardGenerateKeyFeedback(message, isError);
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
        return submitDashboardGenerateKeyForm(this);
    }

    openIssuedKeyModal(created) {
        return openDashboardIssuedKeyModal(this, created);
    }

    async copyIssuedAPIKey() {
        return copyDashboardIssuedAPIKey(this);
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
        openDashboardModal('revokeKeyModal');
        this.prepareRevokeKeyModal();
    }

    prepareRevokeKeyModal() {
        if (!this.hasCapability('api_keys.write')) {
            this.showError('API key write access is required.');
            closeDashboardModal('revokeKeyModal');
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

        closeDashboardModal('revokeKeyModal');
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
            closeDashboardModal('runScanModal');
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

            closeDashboardModal('runScanModal');
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

            this.renderPoliciesTable(this.mergePoliciesWithCatalog(enrichedPolicies));
        } catch (error) {
            this.showError(error.message || 'Failed to load policies');
            this.renderPoliciesTable(this.builtInPolicyCatalog());
        }
    }

    async loadProjectsData() {
        return loadDashboardProjectsData(this);
    }

    async loadApiKeysData() {
        try {
            if (this.isAdmin()) {
                await this.loadUsersData();
                if (!this.apiKeyState.mode) {
                    this.apiKeyState.mode = 'me';
                }
                if (this.apiKeyState.mode === 'user' && !String(this.apiKeyState.targetUserID || '').trim()) {
                    this.apiKeyState.mode = 'me';
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

        const mode = String(this.apiKeyState.mode || 'me').trim().toLowerCase();
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
            this.setAPIKeyScope('me');
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

    renderSettingsStatCard(label, value, muted = '') {
        return `
            <div class="rounded-lg border border-gray-200 bg-gray-50 p-4">
                <p class="text-[11px] font-medium uppercase tracking-wide text-gray-500">${this.escapeHtml(label)}</p>
                <p class="mt-1 text-sm font-medium text-gray-900 break-words">${this.escapeHtml(value || '-')}</p>
                ${muted ? `<p class="mt-1 text-xs text-gray-500">${this.escapeHtml(muted)}</p>` : ''}
            </div>
        `;
    }

    renderSettingsActionButton(label, options = {}, primary = false) {
        return renderDashboardSettingsActionButton(this, label, options, primary);
    }

    renderSettingsAccountRow(label, value, hint = '') {
        return `
            <div class="py-3 border-b border-gray-100 last:border-b-0">
                <div class="flex items-start justify-between gap-3">
                    <div>
                        <p class="text-xs font-medium uppercase tracking-wide text-gray-500">${this.escapeHtml(label)}</p>
                        ${hint ? `<p class="mt-1 text-xs text-gray-500">${this.escapeHtml(hint)}</p>` : ''}
                    </div>
                    <p class="text-sm font-medium text-gray-900 text-right break-all">${this.escapeHtml(value)}</p>
                </div>
            </div>
        `;
    }

    renderSettingsPanel() {
        return renderDashboardSettingsPanel(this);
    }

    async loadSettingsData() {
        const settingsTab = document.getElementById('settings-tab');
        if (!settingsTab) return;
        settingsTab.innerHTML = this.renderSettingsPanel();
        this.bindSettingsControls();
        if (this.isAdmin()) {
            await this.loadCLISessionsData();
        }
    }

    bindSettingsControls() {
        bindDashboardSettingsControls(this);
    }

    renderCLISessionsList(isLoading = false, errorMessage = '') {
        const listNode = document.getElementById('settings-cli-sessions-list');
        if (!listNode) {
            return;
        }
        listNode.innerHTML = renderDashboardCLISessionsList(this, this.settingsState.cliSessions, isLoading, errorMessage);
        this.bindSettingsControls();
    }

    async loadCLISessionsData() {
        if (!this.isAdmin()) {
            return;
        }
        const feedback = document.getElementById('settings-cli-sessions-feedback');
        if (feedback) {
            feedback.textContent = 'Loading...';
            feedback.className = 'text-xs text-gray-500';
        }
        this.renderCLISessionsList(true);
        try {
            const payload = await this.apiRequest('/v1/cli/session?limit=100');
            this.settingsState.cliSessions = Array.isArray(payload?.sessions) ? payload.sessions : [];
            this.renderCLISessionsList(false);
            if (feedback) {
                feedback.textContent = `${this.settingsState.cliSessions.length} active`;
                feedback.className = 'text-xs text-gray-500';
            }
        } catch (error) {
            this.settingsState.cliSessions = [];
            this.renderCLISessionsList(false, error.message || 'Failed to load CLI sessions.');
            if (feedback) {
                feedback.textContent = error.message || 'Failed to load CLI sessions.';
                feedback.className = 'text-xs text-red-600';
            }
        }
    }

    async revokeCLISession(sessionID) {
        const normalizedID = String(sessionID || '').trim();
        if (!normalizedID) {
            this.showError('Invalid CLI session.');
            return;
        }
        const feedback = document.getElementById('settings-cli-sessions-feedback');
        if (feedback) {
            feedback.textContent = 'Revoking...';
            feedback.className = 'text-xs text-gray-500';
        }
        try {
            await this.apiRequest(`/v1/cli/session/${encodeURIComponent(normalizedID)}`, {
                method: 'DELETE'
            });
            this.settingsState.cliSessions = this.settingsState.cliSessions.filter(
                (session) => String(session?.session_id || '').trim() !== normalizedID
            );
            this.renderCLISessionsList(false);
            if (feedback) {
                feedback.textContent = 'Revoked';
                feedback.className = 'text-xs text-green-700';
            }
            this.showSuccess('CLI session revoked.');
        } catch (error) {
            if (feedback) {
                feedback.textContent = error.message || 'Failed to revoke CLI session.';
                feedback.className = 'text-xs text-red-600';
            }
            this.showError(error.message || 'Failed to revoke CLI session.');
        }
    }

    async revokeCLISessionsForUser(ownerKey, userLabel = '') {
        const normalizedOwnerKey = String(ownerKey || '').trim();
        if (!normalizedOwnerKey) {
            this.showError('Invalid user for CLI session revoke.');
            return;
        }
        const displayLabel = String(userLabel || '').trim() || normalizedOwnerKey;
        const confirmed = window.confirm(`Revoke all active CLI sessions for ${displayLabel}?`);
        if (!confirmed) {
            return;
        }
        const feedback = document.getElementById('settings-cli-sessions-feedback');
        if (feedback) {
            feedback.textContent = 'Revoking user sessions...';
            feedback.className = 'text-xs text-gray-500';
        }
        try {
            const payload = await this.apiRequest(`/v1/cli/session/owner/${encodeURIComponent(normalizedOwnerKey)}`, {
                method: 'DELETE'
            });
            this.settingsState.cliSessions = this.settingsState.cliSessions.filter(
                (session) => String(session?.owner_key || '').trim() !== normalizedOwnerKey
            );
            this.renderCLISessionsList(false);
            const revokedCount = Number(payload?.revoked_count || 0);
            if (feedback) {
                feedback.textContent = revokedCount > 0 ? `Revoked ${revokedCount} session${revokedCount === 1 ? '' : 's'}` : 'Revoked';
                feedback.className = 'text-xs text-green-700';
            }
            this.showSuccess(`Revoked all CLI sessions for ${displayLabel}.`);
        } catch (error) {
            if (feedback) {
                feedback.textContent = error.message || 'Failed to revoke user CLI sessions.';
                feedback.className = 'text-xs text-red-600';
            }
            this.showError(error.message || 'Failed to revoke user CLI sessions.');
        }
    }

    renderCLISessionDetailContent(payload, isLoading = false, errorMessage = '') {
        const content = document.getElementById('cli-session-detail-content');
        if (!content) {
            return;
        }
        if (isLoading) {
            content.innerHTML = '<p class="text-sm text-gray-700">Loading CLI session detail...</p>';
            return;
        }
        if (errorMessage) {
            content.innerHTML = `<p class="text-sm text-red-600">${this.escapeHtml(errorMessage)}</p>`;
            return;
        }
        const session = payload?.session || {};
        const traces = Array.isArray(payload?.recent_traces) ? payload.recent_traces : [];
        const anomalyFlags = Array.isArray(payload?.anomaly_flags) ? payload.anomaly_flags : [];
        const riskSignals = Array.isArray(payload?.risk_signals) ? payload.risk_signals : [];
        const timeline = Array.isArray(payload?.timeline) ? payload.timeline : [];
        content.innerHTML = `
            <div class="space-y-5">
                <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
                    ${this.renderCLISessionDetailStat('Client', session.client_name || 'CLI client')}
                    ${this.renderCLISessionDetailStat('User', session.user || 'Unknown')}
                    ${this.renderCLISessionDetailStat('Role', session.role || 'viewer')}
                    ${this.renderCLISessionDetailStat('Last used', this.formatDate(session.last_used_at))}
                    ${this.renderCLISessionDetailStat('Repository', session.last_repository || '-')}
                    ${this.renderCLISessionDetailStat('Project', session.last_project_id || '-')}
                    ${this.renderCLISessionDetailStat('Command', session.last_command || '-')}
                    ${this.renderCLISessionDetailStat('Scan', session.last_scan_id || '-')}
                    ${this.renderCLISessionDetailStat('CLI version', session.cli_version || '-')}
                    ${this.renderCLISessionDetailStat('IP', session.last_ip || '-')}
                    ${this.renderCLISessionDetailStat('Host', session.client_host || '-')}
                    ${this.renderCLISessionDetailStat('Refresh expires', this.formatDate(session.refresh_expires_at))}
                </div>
                <div class="rounded-lg border border-gray-200">
                    <div class="px-4 py-3 border-b border-gray-200 bg-gray-50">
                        <h4 class="text-sm font-semibold text-gray-900">Recent trace activity</h4>
                    </div>
                    ${traces.length ? `
                        <div class="divide-y divide-gray-200">
                            ${traces.map((trace) => `
                                <div class="px-4 py-3 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                                    <div class="min-w-0">
                                        <p class="text-sm font-medium text-gray-900">${this.escapeHtml(trace.command || 'command')}</p>
                                        <p class="text-xs text-gray-500 mt-1">
                                            ${this.escapeHtml(trace.trace_id || '')} | ${this.escapeHtml(trace.repository || '-')} | ${this.escapeHtml(trace.project_id || '-')} | ${this.formatDate(trace.started_at)}
                                        </p>
                                    </div>
                                    <div class="flex items-center gap-2">
                                        <span class="text-xs text-gray-500">${this.escapeHtml(String(trace.event_count ?? 0))} events</span>
                                        <button type="button" data-cli-trace-view="${this.escapeHtml(trace.trace_id || '')}" class="inline-flex items-center px-3 py-1.5 rounded-lg border border-orange-200 text-orange-700 hover:bg-orange-50 font-medium text-sm">
                                            View trace
                                        </button>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    ` : `
                        <div class="px-4 py-5 text-sm text-gray-500">No trace activity has been recorded for this CLI session yet.</div>
                    `}
                </div>
                <div class="rounded-lg border border-gray-200">
                    <div class="px-4 py-3 border-b border-gray-200 bg-gray-50">
                        <h4 class="text-sm font-semibold text-gray-900">Risk signals</h4>
                    </div>
                    ${riskSignals.length ? `
                        <div class="divide-y divide-gray-200">
                            ${riskSignals.map((signal) => `
                                <div class="px-4 py-3 flex flex-col gap-1">
                                    <div class="flex flex-wrap items-center gap-2">
                                        <p class="text-sm font-medium text-gray-900">${this.escapeHtml(signal?.title || 'Signal')}</p>
                                        <span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${this.cliSessionTimelineStatusClass(signal?.severity)}">${this.escapeHtml(String(signal?.severity || 'info'))}</span>
                                    </div>
                                    <p class="text-xs text-gray-500">${this.escapeHtml(signal?.detail || '')}</p>
                                </div>
                            `).join('')}
                        </div>
                    ` : `
                        <div class="px-4 py-5 text-sm text-gray-500">No risk signals are active for this CLI session right now.</div>
                    `}
                </div>
                <div class="rounded-lg border border-gray-200">
                    <div class="px-4 py-3 border-b border-gray-200 bg-gray-50">
                        <h4 class="text-sm font-semibold text-gray-900">Anomaly flags</h4>
                    </div>
                    ${anomalyFlags.length ? `
                        <div class="divide-y divide-gray-200">
                            ${anomalyFlags.map((flag) => `
                                <div class="px-4 py-3 flex flex-col gap-1">
                                    <div class="flex flex-wrap items-center gap-2">
                                        <p class="text-sm font-medium text-gray-900">${this.escapeHtml(flag?.title || 'Anomaly')}</p>
                                        <span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${this.cliSessionTimelineStatusClass(flag?.severity)}">${this.escapeHtml(String(flag?.severity || 'info'))}</span>
                                    </div>
                                    <p class="text-xs text-gray-500">${this.escapeHtml(flag?.detail || '')}</p>
                                </div>
                            `).join('')}
                        </div>
                    ` : `
                        <div class="px-4 py-5 text-sm text-gray-500">No anomalous session patterns are active right now.</div>
                    `}
                </div>
                <div class="rounded-lg border border-gray-200">
                    <div class="px-4 py-3 border-b border-gray-200 bg-gray-50">
                        <h4 class="text-sm font-semibold text-gray-900">Session timeline</h4>
                    </div>
                    ${timeline.length ? `
                        <div class="divide-y divide-gray-200">
                            ${timeline.map((item) => {
                                const statusClass = this.cliSessionTimelineStatusClass(item?.status);
                                const detail = this.escapeHtml(item?.detail || '');
                                const at = this.escapeHtml(this.formatDate(item?.at));
                                const title = this.escapeHtml(item?.title || 'Timeline event');
                                return `
                                    <div class="px-4 py-3 flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                                        <div class="min-w-0">
                                            <div class="flex flex-wrap items-center gap-2">
                                                <p class="text-sm font-medium text-gray-900">${title}</p>
                                                <span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${statusClass}">${this.escapeHtml(String(item?.status || 'info'))}</span>
                                            </div>
                                            ${detail ? `<p class="mt-1 text-xs text-gray-500">${detail}</p>` : ''}
                                        </div>
                                        <p class="text-xs text-gray-500 whitespace-nowrap">${at}</p>
                                    </div>
                                `;
                            }).join('')}
                        </div>
                    ` : `
                        <div class="px-4 py-5 text-sm text-gray-500">No session timeline entries are available yet.</div>
                    `}
                </div>
            </div>
        `;
        document.querySelectorAll('#cli-session-detail-content [data-cli-trace-view]').forEach((button) => {
            if (button.dataset.bound === '1') {
                return;
            }
            button.dataset.bound = '1';
            button.addEventListener('click', async () => {
                const traceID = String(button.dataset.cliTraceView || '').trim();
                if (traceID) {
                    await this.openCLITraceDetail(traceID);
                }
            });
        });
    }

    cliSessionTimelineStatusClass(status) {
        switch (String(status || '').trim().toLowerCase()) {
        case 'ok':
            return 'bg-green-100 text-green-700';
        case 'warning':
            return 'bg-yellow-100 text-yellow-800';
        case 'error':
            return 'bg-red-100 text-red-700';
        default:
            return 'bg-gray-100 text-gray-700';
        }
    }

    renderCLISessionDetailStat(label, value) {
        return `
            <div class="rounded-lg border border-gray-200 bg-gray-50 px-4 py-3">
                <p class="text-xs font-semibold uppercase tracking-wide text-gray-500">${this.escapeHtml(label)}</p>
                <p class="mt-1 text-sm font-medium text-gray-900">${this.escapeHtml(value || '-')}</p>
            </div>
        `;
    }

    async openCLISessionDetail(sessionID) {
        const normalizedID = String(sessionID || '').trim();
        if (!normalizedID) {
            this.showError('Invalid CLI session.');
            return;
        }
        this.settingsState.selectedCLISessionID = normalizedID;
        this.renderCLISessionDetailContent(null, true);
        openDashboardModal('cliSessionDetailModal');
        if (this.settingsState.cliSessionDetails[normalizedID]) {
            this.renderCLISessionDetailContent(this.settingsState.cliSessionDetails[normalizedID], false);
            return;
        }
        try {
            const payload = await this.apiRequest(`/v1/cli/session/${encodeURIComponent(normalizedID)}`);
            this.settingsState.cliSessionDetails[normalizedID] = payload;
            if (this.settingsState.selectedCLISessionID !== normalizedID) {
                return;
            }
            this.renderCLISessionDetailContent(payload, false);
        } catch (error) {
            if (this.settingsState.selectedCLISessionID !== normalizedID) {
                return;
            }
            this.renderCLISessionDetailContent(null, false, error.message || 'Failed to load CLI session detail.');
        }
    }

    openCLILoginApprovalModal(prefillCode = '') {
        const input = document.getElementById('cli-login-user-code');
        const feedback = document.getElementById('cli-login-approval-feedback');
        this.cliApprovalState.userCode = String(prefillCode || this.cliApprovalState.userCode || '').trim().toUpperCase();
        if (input) {
            input.value = this.cliApprovalState.userCode;
        }
        if (feedback) {
            feedback.textContent = '';
            feedback.className = 'text-xs text-gray-500';
        }
        this.syncCLILoginApprovalCode();
        openDashboardModal('cliLoginApprovalModal');
    }

    syncCLILoginApprovalCode() {
        const input = document.getElementById('cli-login-user-code');
        const badge = document.getElementById('cli-login-user-code-display');
        const normalized = String(input?.value || this.cliApprovalState.userCode || '').trim().toUpperCase();
        this.cliApprovalState.userCode = normalized;
        if (input && input.value !== normalized) {
            input.value = normalized;
        }
        if (badge) {
            badge.textContent = normalized || 'ENTER CODE BELOW';
        }
    }

    async submitCLILoginApproval() {
        const input = document.getElementById('cli-login-user-code');
        const feedback = document.getElementById('cli-login-approval-feedback');
        const submitButton = document.getElementById('cli-login-approval-submit');
        const userCode = String(input?.value || this.cliApprovalState.userCode || '').trim().toUpperCase();
        if (!userCode) {
            if (feedback) {
                feedback.textContent = 'Enter the code from the terminal first.';
                feedback.className = 'text-xs text-red-600';
            }
            return;
        }
        if (submitButton) {
            submitButton.disabled = true;
        }
        if (feedback) {
            feedback.textContent = 'Approving CLI login...';
            feedback.className = 'text-xs text-gray-500';
        }
        try {
            await this.apiRequest('/v1/cli/session/approve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_code: userCode })
            });
            if (feedback) {
                feedback.textContent = 'CLI session approved. The terminal can continue now.';
                feedback.className = 'text-xs text-green-700';
            }
            this.showSuccess('CLI login approved.');
            this.cliApprovalState.userCode = userCode;
            window.setTimeout(() => {
                closeDashboardModal('cliLoginApprovalModal');
            }, 600);
        } catch (error) {
            if (feedback) {
                feedback.textContent = error.message || 'Failed to approve CLI login.';
                feedback.className = 'text-xs text-red-600';
            }
            this.showError(error.message || 'Failed to approve CLI login.');
        } finally {
            if (submitButton) {
                submitButton.disabled = false;
            }
        }
    }

    handlePendingCLILoginApproval() {
        const params = new URLSearchParams(window.location.search || '');
        const requested = String(params.get('approve_cli_login') || '').trim();
        const userCode = String(params.get('user_code') || '').trim().toUpperCase();
        if (!requested && !userCode) {
            return;
        }
        this.currentTab = 'settings';
        this.switchTab('settings');
        window.setTimeout(() => {
            this.openCLILoginApprovalModal(userCode);
        }, 50);
        params.delete('approve_cli_login');
        params.delete('user_code');
        const nextQuery = params.toString();
        const nextURL = `${window.location.pathname}${nextQuery ? `?${nextQuery}` : ''}${window.location.hash || ''}`;
        window.history.replaceState({}, document.title, nextURL);
    }

    async saveProfileSettings() {
        return saveDashboardProfileSettings(this);
    }

    saveDashboardPreferencesFromSettings() {
        return saveDashboardSettingsPreferences(this);
    }

    resetDashboardPreferencesFromSettings() {
        return resetDashboardSettingsPreferences(this);
    }

    async loadExternalScriptOnce(src, globalKey) {
        if (globalKey && window[globalKey]) {
            return window[globalKey];
        }
        const existing = document.querySelector(`script[src="${src}"]`);
        if (existing) {
            return new Promise((resolve, reject) => {
                const checkReady = () => {
                    if (!globalKey || window[globalKey]) {
                        resolve(globalKey ? window[globalKey] : true);
                    } else {
                        reject(new Error(`Failed to load ${src}`));
                    }
                };
                if (existing.dataset.loaded === '1') {
                    checkReady();
                    return;
                }
                existing.addEventListener('load', () => {
                    existing.dataset.loaded = '1';
                    checkReady();
                }, { once: true });
                existing.addEventListener('error', () => reject(new Error(`Failed to load ${src}`)), { once: true });
            });
        }
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = src;
            script.async = true;
            script.onload = () => {
                script.dataset.loaded = '1';
                if (!globalKey || window[globalKey]) {
                    resolve(globalKey ? window[globalKey] : true);
                    return;
                }
                reject(new Error(`Failed to initialize ${src}`));
            };
            script.onerror = () => reject(new Error(`Failed to load ${src}`));
            document.head.appendChild(script);
        });
    }

    async getSupabaseSettingsClient() {
        return getDashboardSupabaseSettingsClient(this);
    }

    async savePasswordSettings() {
        return saveDashboardPasswordSettings(this);
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
        return renderDashboardUsersTab(this, users, errorMessage);
    }

    sortUsersRows(users, sortBy, sortDir) {
        return sortDashboardUsersRows(this, users, sortBy, sortDir);
    }

    getUserSortText(user) {
        return getDashboardUserSortText(user);
    }

    getUserSortTime(value) {
        return getDashboardUserSortTime(value);
    }

    userSortIndicator(key, activeBy, activeDir) {
        return getDashboardUserSortIndicator(key, activeBy, activeDir);
    }

    userSortDescriptor(sortBy, sortDir) {
        return getDashboardUserSortDescriptor(sortBy, sortDir);
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

        document.querySelectorAll('[data-user-action]').forEach((button) => {
            if (button.dataset.bound === '1') {
                return;
            }
            button.dataset.bound = '1';
            button.addEventListener('click', async () => {
                const action = String(button.getAttribute('data-user-action') || '').trim().toLowerCase();
                const userID = String(button.getAttribute('data-user-id') || '').trim();
                if (!userID) {
                    return;
                }
                if (action === 'view') {
                    await this.viewAdminUserDetail(userID);
                    return;
                }
                if (action === 'save') {
                    const source = String(button.getAttribute('data-user-source') || 'row').trim().toLowerCase();
                    await this.submitAdminUserUpdate(userID, source);
                    return;
                }
                if (action === 'toggle-status') {
                    const nextStatus = String(button.getAttribute('data-user-next-status') || '').trim().toLowerCase();
                    await this.setSelectedUserStatus(userID, nextStatus);
                }
            });
        });
    }

    async viewAdminUserDetail(userID) {
        return viewDashboardAdminUserDetail(this, userID);
    }

    buildSelectedUserActivityPath(userID, limit, offset) {
        return buildDashboardSelectedUserActivityPath(this, userID, limit, offset);
    }

    activityFilterDateToRFC3339(raw) {
        return toDashboardActivityFilterDate(raw);
    }

    async loadMoreSelectedUserActivity() {
        return loadMoreDashboardSelectedUserActivity(this);
    }

    adminUserRowKey(userID) {
        return getDashboardAdminUserRowKey(userID);
    }

    async setSelectedUserStatus(userID, status) {
        return setDashboardSelectedUserStatus(this, userID, status);
    }

    async submitAdminUserUpdate(userID, source = 'row') {
        return submitDashboardAdminUserUpdate(this, userID, source);
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

    async loadCLITelemetryData() {
        if (!this.isAdmin()) {
            const cliTab = document.getElementById('cli-tab');
            if (cliTab) {
                cliTab.innerHTML = `
                    <div class="bg-white rounded-lg border border-gray-200 p-6">
                        <h3 class="text-lg font-semibold text-gray-900">CLI Telemetry</h3>
                        <p class="text-sm text-gray-700 mt-1">Admin role is required.</p>
                    </div>
                `;
            }
            return;
        }
        try {
            const payload = await this.apiRequest('/v1/cli/traces?limit=250');
            this.cliState.traces = Array.isArray(payload?.traces) ? payload.traces : [];
            this.renderCLITelemetryPanel();
        } catch (error) {
            const cliTab = document.getElementById('cli-tab');
            if (cliTab) {
                cliTab.innerHTML = `
                    <div class="bg-white rounded-lg border border-gray-200 p-6">
                        <h3 class="text-lg font-semibold text-gray-900">CLI Telemetry</h3>
                        <p class="text-sm text-red-600 mt-1">${this.escapeHtml(error.message || 'Failed to load CLI telemetry')}</p>
                    </div>
                `;
            }
        }
    }

    async openCLITraceDetail(traceID) {
        const normalizedID = String(traceID || '').trim();
        if (!normalizedID) {
            this.showError('Invalid trace selected.');
            return;
        }
        this.cliState.selectedTraceID = normalizedID;
        this.renderCLITraceDetailContent(null, true);
        openDashboardModal('cliTraceDetailModal');

        if (this.cliState.details[normalizedID]) {
            this.renderCLITraceDetailContent(this.cliState.details[normalizedID]);
            return;
        }

        try {
            const trace = await this.apiRequest(`/v1/cli/traces/${encodeURIComponent(normalizedID)}`);
            this.cliState.details[normalizedID] = trace;
            if (this.cliState.selectedTraceID !== normalizedID) {
                return;
            }
            this.renderCLITraceDetailContent(trace);
        } catch (error) {
            if (this.cliState.selectedTraceID !== normalizedID) {
                return;
            }
            this.renderCLITraceDetailContent(null, false, error.message || 'Failed to load trace detail.');
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
        return renderDashboardScansTable(this, scans);
    }

    renderScansPage(filtered, start, end, pageItems, totalPages) {
        return renderDashboardScansPage(this, filtered, start, end, pageItems, totalPages);
    }

    bindScansControls() {
        return bindDashboardScansControls(this);
    }

    applyScansFiltersAndRender() {
        return applyDashboardScansFiltersAndRender(this);
    }

    bindScanReportButtons() {
        bindDashboardScanReportButtons(this);
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
        const isAdmin = this.isAdmin();

        if (!Array.isArray(policies) || policies.length === 0) {
            policiesTab.innerHTML = `
                <div class="bg-white rounded-lg border border-gray-200 p-6">
                    <h3 class="text-lg font-semibold text-gray-900">Policy Management</h3>
                    <p class="text-sm text-gray-700 mt-1">No policy catalog is available.</p>
                </div>
            `;
            return;
        }

        policiesTab.innerHTML = `
            <div class="bg-white rounded-lg border border-gray-200">
                <div class="p-6 border-b border-gray-200">
                    <h3 class="text-lg font-semibold text-gray-900">Policy Management</h3>
                    <p class="text-sm text-gray-700 mt-1">${isAdmin
                        ? 'Built-in Baseline checks with live version data when policies have been published through the API.'
                        : 'Baseline checks that are evaluated during scans.'}</p>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Policy</th>
                                ${isAdmin ? '<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>' : ''}
                                ${isAdmin ? '<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Latest Version</th>' : ''}
                                ${isAdmin ? '<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Updated</th>' : ''}
                                ${isAdmin ? '<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Versions</th>' : ''}
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                                ${isAdmin ? '<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Links</th>' : ''}
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            ${policies.map(policy => `
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${this.escapeHtml(policy.name)}</td>
                                    ${isAdmin ? `
                                        <td class="px-6 py-4 whitespace-nowrap text-sm">
                                            <span class="px-2 py-1 text-xs rounded-full ${policy.source === 'published' ? 'bg-orange-100 text-orange-800' : 'bg-gray-100 text-gray-700'}">
                                                ${policy.source === 'published' ? 'Configured' : 'Default'}
                                            </span>
                                        </td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${this.escapeHtml(policy.latest_version || 'Not configured')}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${policy.updated_at ? this.formatDate(policy.updated_at) : 'Not configured'}</td>
                                        <td class="px-6 py-4 whitespace-nowrap">
                                            <span class="px-2 py-1 text-xs rounded-full ${policy.version_count > 0 ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-700'}">
                                                ${policy.version_count > 0 ? `${policy.version_count} total` : 'Default only'}
                                            </span>
                                        </td>
                                    ` : ''}
                                    <td class="px-6 py-4 text-sm text-gray-700">
                                        ${this.escapeHtml(policy.description || 'No description')}
                                        ${isAdmin ? `
                                            <div class="text-xs text-gray-500 mt-1">
                                                ${policy.source === 'published'
                                                    ? `content keys: ${policy.content_keys}, metadata keys: ${policy.metadata_keys}`
                                                    : 'API-published policy versions will appear here after configuration.'}
                                            </div>
                                        ` : ''}
                                    </td>
                                    ${isAdmin ? `
                                        <td class="px-6 py-4 whitespace-nowrap text-sm">
                                            ${policy.source === 'published'
                                                ? `
                                                    <a class="text-orange-600 hover:text-orange-700 mr-2" href="/v1/policies/${encodeURIComponent(policy.name)}/latest" target="_blank" rel="noopener noreferrer">Latest</a>
                                                    <a class="text-orange-600 hover:text-orange-700" href="/v1/policies/${encodeURIComponent(policy.name)}/versions" target="_blank" rel="noopener noreferrer">Versions</a>
                                                `
                                                : '<span class="text-gray-400">No configured version</span>'}
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

    renderProjectsTable(projects) {
        renderDashboardProjectsTable(this, projects);
    }

    bindProjectActionButtons(root = document) {
        bindDashboardProjectActionButtons(this, root);
    }

    renderApiKeysTable(apiKeys) {
        renderDashboardApiKeysTable(this, apiKeys);
    }

    bindModalTriggerButtons(root = document) {
        bindDashboardModalTriggerButtons(root);
    }

    bindAPIKeyActionButtons(root = document) {
        bindDashboardAPIKeyActionButtons(this, root);
    }

    renderAPIKeyScopeControls() {
        if (!this.isAdmin()) {
            return '';
        }
        const selectedMode = String(this.apiKeyState.mode || 'me').toLowerCase();
        const selectedUserID = String(this.apiKeyState.targetUserID || '').trim();
        const optionRows = [];
        optionRows.push(`<option value="me"${selectedMode === 'me' ? ' selected' : ''}>My Keys (recommended)</option>`);
        optionRows.push(`<option value="legacy"${selectedMode === 'legacy' ? ' selected' : ''}>Admin Inventory (all keys)</option>`);
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
                <select id="api-key-scope-select" class="w-full max-w-md px-3 py-2 border border-gray-300 rounded-lg text-sm" style="color:#111827;background:#ffffff;">
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
        renderDashboardAuditTable(this, events);
    }

    renderCLITelemetryPanel() {
        renderDashboardCLITelemetryPanel(this);
    }

    renderCLITraceDetailContent(trace, isLoading = false, errorMessage = '') {
        renderDashboardCLITraceDetailContent(this, trace, isLoading, errorMessage);
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
        const details = String(event?.details || '').trim();
        if (details) {
            return details;
        }
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
            cli_started: 'CLI command started',
            cli_completed: 'CLI command completed',
            cli_health: 'CLI health',
            cli_warning: 'CLI warning',
            cli_error: 'CLI error',
            cli_config_changed: 'CLI configuration changed',
            cli_report_generated: 'CLI output generated',
            cli_service_started: 'CLI service started',
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
        const details = String(event?.details || '').trim();
        if (details) {
            return details;
        }
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

    cliEventField(rawDetails, key) {
        const details = String(rawDetails || '').trim();
        const prefix = `${String(key || '').trim().toLowerCase()} `;
        if (!details || prefix.trim() === '') {
            return '';
        }
        for (const part of details.split('|')) {
            const trimmed = String(part || '').trim();
            const lower = trimmed.toLowerCase();
            if (lower.startsWith(prefix)) {
                return trimmed.slice(prefix.length).trim();
            }
        }
        return '';
    }

    cliEventCommand(event) {
        return this.cliEventField(event?.details, 'command');
    }

    cliEventStatus(event) {
        return this.cliEventField(event?.details, 'status');
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
        const configuredName = String(user.displayName || user.display_name || this.identity?.displayName || '').trim();
        const displayName = configuredName || (email
            ? email.split('@')[0]
            : (role ? role : 'User'));
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

        const userButton = document.getElementById('dashboard-user-button');
        const userDropdown = document.getElementById('userDropdown');

        this.identity.displayName = configuredName;
        if (email) {
            this.identity.email = email;
        }
        const normalizedRole = role || 'viewer';

        if (userButton) {
            userButton.className = 'flex items-center gap-2.5 pl-1 pr-3 py-1 rounded-lg border border-gray-300 hover:border-gray-400 transition-colors';
        }

        if (headerAvatar) {
            headerAvatar.className = 'w-7 h-7 rounded-md flex items-center justify-center text-xs font-bold bg-gray-800 text-white';
        }

        if (profileAvatar) {
            profileAvatar.className = 'w-10 h-10 rounded-full bg-gradient-to-br from-gray-700 to-gray-900 flex items-center justify-center text-white text-sm font-bold';
        }

        if (userDropdown) {
            userDropdown.className = 'absolute right-0 mt-2 w-64 bg-white rounded-lg shadow-lg border border-gray-200 hidden z-50';
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
            roleBadge.textContent = normalizedRole.charAt(0).toUpperCase() + normalizedRole.slice(1);
            roleBadge.className = normalizedRole === 'admin'
                ? 'inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-orange-100 text-orange-800'
                : normalizedRole === 'operator'
                    ? 'inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800'
                    : 'inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-700';
        }
    }

    setupEventListeners() {
        return setupDashboardShellEvents(this);
    }

    handleSearch(query) {
        return handleDashboardSearch(this, query);
    }

    async signOut() {
        return signOutDashboard(this);
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

mountDashboardApplication(() => new BaselineDashboard());

