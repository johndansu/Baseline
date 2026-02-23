// Baseline Dashboard JavaScript
class BaselineDashboard {
    constructor() {
        this.currentTab = 'overview';
        this.apiBaseUrl = window.location.origin;
        this.chart = null;
        this.init();
    }

    init() {
        this.setupTabNavigation();
        this.initializeChart();
        this.loadDashboardData();
        this.setupEventListeners();
        // Template mode - set mock user directly
        this.updateUserUI({ email: 'operator@baseline.local' });
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
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                datasets: [{
                    label: 'Scans',
                    data: [12, 19, 15, 25, 22, 30, 28],
                    borderColor: 'rgb(59, 130, 246)',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4
                }, {
                    label: 'Violations',
                    data: [3, 5, 2, 8, 4, 6, 5],
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
        // Template mode - use mock data only
        this.loadMockData();
    }

    async loadOverviewStats() {
        // Template mode - use mock data
        const mockProjects = [
            { name: 'payments-service', scan_count: 28 },
            { name: 'user-service', scan_count: 15 },
            { name: 'analytics-service', scan_count: 31 },
            { name: 'notification-service', scan_count: 40 }
        ];
        this.updateStatsCards(mockProjects);
    }

    updateStatsCards(projects) {
        // Update stats cards with real data
        const totalScansElement = document.querySelector('.text-2xl');
        if (totalScansElement && projects.length > 0) {
            // Calculate total scans from projects
            const totalScans = projects.reduce((sum, project) => sum + (project.scan_count || 0), 0);
            if (totalScans > 0) {
                totalScansElement.textContent = totalScans;
            }
        }
    }

    async loadRecentActivity() {
        // Template mode - use mock data
        const mockEvents = [
            {
                type: 'scan',
                message: 'Scan completed successfully',
                project_name: 'payments-service',
                timestamp: new Date(Date.now() - 2 * 60 * 1000).toISOString()
            },
            {
                type: 'violation',
                message: 'Policy violation detected',
                project_name: 'user-service',
                details: 'D1: Secret detected',
                timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString()
            },
            {
                type: 'project',
                message: 'New project added',
                project_name: 'analytics-service',
                timestamp: new Date(Date.now() - 60 * 60 * 1000).toISOString()
            }
        ];
        this.updateActivityLog(mockEvents);
    }

    updateActivityLog(events) {
        const activityContainer = document.querySelector('#overview-tab .divide-y');
        if (!activityContainer || !events.length) return;

        // Clear existing activity items
        activityContainer.innerHTML = '';

        events.forEach(event => {
            const activityItem = this.createActivityItem(event);
            activityContainer.appendChild(activityItem);
        });
    }

    createActivityItem(event) {
        const div = document.createElement('div');
        div.className = 'p-4 flex items-center justify-between';
        
        const statusColor = event.type === 'violation' ? 'red' : 
                           event.type === 'scan' ? 'green' : 'blue';
        
        div.innerHTML = `
            <div class="flex items-center gap-3">
                <div class="w-2 h-2 bg-${statusColor}-500 rounded-full"></div>
                <div>
                    <p class="text-sm font-medium text-gray-900">${event.message || event.type}</p>
                    <p class="text-xs text-gray-500">${event.project_name || 'System'} • ${event.details || ''}</p>
                </div>
            </div>
            <span class="text-xs text-gray-500">${this.formatDate(event.timestamp)}</span>
        `;
        
        return div;
    }

    async loadTabData(tabName) {
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
        // Template mode - use mock data
        const mockScans = [
            {
                project_name: 'payments-service',
                status: 'passed',
                violations: 0,
                timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()
            },
            {
                project_name: 'user-service',
                status: 'failed',
                violations: 2,
                timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString()
            },
            {
                project_name: 'analytics-service',
                status: 'passed',
                violations: 0,
                timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString()
            }
        ];
        this.renderScansTable(mockScans);
    }

    async loadPoliciesData() {
        // Template mode - use mock data
        const mockPolicies = [
            { id: 'A1', name: 'Primary Branch Protection', enabled: true, severity: 'block' },
            { id: 'B1', name: 'CI Workflows', enabled: true, severity: 'block' },
            { id: 'C1', name: 'Automated Tests', enabled: true, severity: 'block' },
            { id: 'D1', name: 'Secret Detection', enabled: true, severity: 'block' },
            { id: 'E1', name: 'Dependency Management', enabled: true, severity: 'warn' },
            { id: 'F1', name: 'Documentation', enabled: false, severity: 'warn' }
        ];
        this.renderPoliciesTable(mockPolicies);
    }

    async loadProjectsData() {
        // Template mode - use mock data
        const mockProjects = [
            {
                name: 'payments-service',
                repository: 'github.com/company/payments-service',
                last_scan: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
                status: 'healthy'
            },
            {
                name: 'user-service',
                repository: 'github.com/company/user-service',
                last_scan: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
                status: 'warning'
            },
            {
                name: 'analytics-service',
                repository: 'github.com/company/analytics-service',
                last_scan: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
                status: 'healthy'
            },
            {
                name: 'notification-service',
                repository: 'github.com/company/notification-service',
                last_scan: new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString(),
                status: 'healthy'
            }
        ];
        this.renderProjectsTable(mockProjects);
    }

    async loadApiKeysData() {
        // Template mode - use mock data
        const mockApiKeys = [
            {
                name: 'Production API Key',
                key_id: 'bl_prod_1234567890',
                role: 'operator',
                created_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()
            },
            {
                name: 'CI/CD Pipeline Key',
                key_id: 'bl_ci_0987654321',
                role: 'viewer',
                created_at: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString()
            },
            {
                name: 'Development Key',
                key_id: 'bl_dev_5678901234',
                role: 'admin',
                created_at: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()
            }
        ];
        this.renderApiKeysTable(mockApiKeys);
    }

    async loadIntegrationsData() {
        const integrationsTab = document.getElementById('integrations-tab');
        integrationsTab.innerHTML = `
            <div class="bg-white rounded-lg border border-gray-200 p-6">
                <h3 class="text-lg font-semibold text-gray-900 mb-6">Integration Settings</h3>
                
                <div class="space-y-6">
                    <div class="border border-gray-200 rounded-lg p-4">
                        <h4 class="font-medium text-gray-900 mb-2">GitHub Integration</h4>
                        <p class="text-sm text-gray-600 mb-4">Connect GitHub repositories for automatic scanning</p>
                        <button class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Configure GitHub</button>
                    </div>
                    
                    <div class="border border-gray-200 rounded-lg p-4">
                        <h4 class="font-medium text-gray-900 mb-2">GitLab Integration</h4>
                        <p class="text-sm text-gray-600 mb-4">Connect GitLab projects for automatic scanning</p>
                        <button class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Configure GitLab</button>
                    </div>
                    
                    <div class="border border-gray-200 rounded-lg p-4">
                        <h4 class="font-medium text-gray-900 mb-2">Webhook Endpoints</h4>
                        <p class="text-sm text-gray-600 mb-4">Configure webhook endpoints for real-time notifications</p>
                        <button class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Manage Webhooks</button>
                    </div>
                </div>
            </div>
        `;
    }

    async loadAuditData() {
        // Template mode - use mock data
        const mockEvents = [
            {
                type: 'scan_completed',
                user: 'system',
                timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
                message: 'Scan completed for payments-service'
            },
            {
                type: 'policy_violation',
                user: 'system',
                timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
                message: 'D1 violation detected in user-service',
                details: 'Secret pattern found in config file'
            },
            {
                type: 'api_key_created',
                user: 'operator@baseline.local',
                timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
                message: 'New API key created'
            },
            {
                type: 'project_added',
                user: 'operator@baseline.local',
                timestamp: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString(),
                message: 'Project analytics-service added to monitoring'
            }
        ];
        this.renderAuditTable(mockEvents);
    }

    async loadSettingsData() {
        const settingsTab = document.getElementById('settings-tab');
        settingsTab.innerHTML = `
            <div class="bg-white rounded-lg border border-gray-200 p-6">
                <h3 class="text-lg font-semibold text-gray-900 mb-6">Settings</h3>
                
                <div class="space-y-6">
                    <div>
                        <h4 class="font-medium text-gray-900 mb-2">API Configuration</h4>
                        <div class="space-y-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">API Server URL</label>
                                <input type="text" value="${this.apiBaseUrl}" class="w-full px-3 py-2 border border-gray-300 rounded-lg" readonly>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">Database Path</label>
                                <input type="text" value=".baseline/baseline.db" class="w-full px-3 py-2 border border-gray-300 rounded-lg" readonly>
                            </div>
                        </div>
                    </div>
                    
                    <div>
                        <h4 class="font-medium text-gray-900 mb-2">Authentication</h4>
                        <div class="space-y-4">
                            <div class="flex items-center justify-between">
                                <span class="text-sm text-gray-700">Session Authentication</span>
                                <span class="px-2 py-1 bg-green-100 text-green-800 text-xs rounded-full">Enabled</span>
                            </div>
                            <div class="flex items-center justify-between">
                                <span class="text-sm text-gray-700">API Key Authentication</span>
                                <span class="px-2 py-1 bg-green-100 text-green-800 text-xs rounded-full">Enabled</span>
                            </div>
                        </div>
                    </div>
                    
                    <div>
                        <h4 class="font-medium text-gray-900 mb-2">Actions</h4>
                        <div class="space-y-3">
                            <button class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Export Configuration</button>
                            <button class="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">View Logs</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderScansTable(scans) {
        const scansTab = document.getElementById('scans-tab');
        scansTab.innerHTML = `
            <div class="bg-white rounded-lg border border-gray-200">
                <div class="p-6 border-b border-gray-200">
                    <h3 class="text-lg font-semibold text-gray-900">Scan History</h3>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Violations</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            ${scans.map(scan => `
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${scan.project_name || 'Unknown'}</td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <span class="px-2 py-1 text-xs rounded-full ${scan.status === 'passed' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}">
                                            ${scan.status || 'Unknown'}
                                        </span>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${scan.violations || 0}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${this.formatDate(scan.timestamp)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }

    renderPoliciesTable(policies) {
        const policiesTab = document.getElementById('policies-tab');
        policiesTab.innerHTML = `
            <div class="bg-white rounded-lg border border-gray-200">
                <div class="p-6 border-b border-gray-200">
                    <h3 class="text-lg font-semibold text-gray-900">Policy Management</h3>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Policy ID</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            ${policies.map(policy => `
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${policy.id}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${policy.name}</td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <span class="px-2 py-1 text-xs rounded-full ${policy.enabled ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}">
                                            ${policy.enabled ? 'Enabled' : 'Disabled'}
                                        </span>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <span class="px-2 py-1 text-xs rounded-full ${policy.severity === 'block' ? 'bg-red-100 text-red-800' : 'bg-yellow-100 text-yellow-800'}">
                                            ${policy.severity}
                                        </span>
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
        // Don't overwrite - the HTML has the new design
        console.log('Projects data loaded:', projects.length, 'projects');
    }

    renderApiKeysTable(apiKeys) {
        // Don't overwrite - the HTML has the new design
        console.log('API Keys loaded:', apiKeys.length, 'keys');
    }

    renderAuditTable(events) {
        const auditTab = document.getElementById('audit-tab');
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
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Event</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Details</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            ${events.map(event => `
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${this.formatDate(event.timestamp)}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${event.type}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${event.user || 'System'}</td>
                                    <td class="px-6 py-4 text-sm text-gray-900">${event.message || event.details}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }

    updateUserUI(user) {
        // Update user display in header
        const userElement = document.querySelector('.flex.items-center.gap-2.px-3.py-2 span');
        if (userElement && user.email) {
            userElement.textContent = user.email.split('@')[0]; // Show username part
        }
    }

    loadMockData() {
        // Load all mock data for template/demo
        this.updateStatsCards([
            { name: 'payments-service', scan_count: 28 },
            { name: 'user-service', scan_count: 15 },
            { name: 'analytics-service', scan_count: 31 },
            { name: 'notification-service', scan_count: 40 }
        ]);
        
        this.updateActivityLog([
            {
                type: 'scan',
                message: 'Scan completed successfully',
                project_name: 'payments-service',
                timestamp: new Date(Date.now() - 2 * 60 * 1000).toISOString()
            },
            {
                type: 'violation',
                message: 'Policy violation detected',
                project_name: 'user-service',
                details: 'D1: Secret detected',
                timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString()
            },
            {
                type: 'project',
                message: 'New project added',
                project_name: 'analytics-service',
                timestamp: new Date(Date.now() - 60 * 60 * 1000).toISOString()
            }
        ]);
    }

    updateUserUI(user) {
        // Update user display in header
        const userElement = document.querySelector('.flex.items-center.gap-2.px-3.py-2 span');
        if (userElement && user.email) {
            userElement.textContent = user.email.split('@')[0]; // Show username part
        }
    }

    setupEventListeners() {
        // Search functionality
        const searchInput = document.querySelector('input[placeholder="Search policies, scans..."]');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.handleSearch(e.target.value);
            });
        }

        // CLI button - find button containing "CLI" text
        const cliButton = Array.from(document.querySelectorAll('button')).find(btn => 
            btn.textContent && btn.textContent.includes('CLI')
        );
        if (cliButton) {
            cliButton.addEventListener('click', () => {
                this.openCliModal();
            });
        }

        // Notifications button - find button with red dot
        const notifButton = Array.from(document.querySelectorAll('button')).find(btn => 
            btn.querySelector('.bg-red-500.rounded-full')
        );
        if (notifButton) {
            notifButton.addEventListener('click', () => {
                this.showNotifications();
            });
        }
    }

    handleSearch(query) {
        // Implement search functionality
        console.log('Searching for:', query);
        // This would filter the current tab's data based on the query
    }

    openCliModal() {
        // Open CLI quick actions modal
        alert('CLI Quick Actions - This would open a modal with CLI commands');
    }

    showNotifications() {
        // Show notifications panel
        alert('Notifications - This would show recent notifications');
    }

    showError(message) {
        // Show error message to user
        const errorDiv = document.createElement('div');
        errorDiv.className = 'fixed top-4 right-4 bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded z-50';
        errorDiv.textContent = message;
        document.body.appendChild(errorDiv);
        
        setTimeout(() => {
            errorDiv.remove();
        }, 5000);
    }

    formatDate(timestamp) {
        if (!timestamp) return 'N/A';
        const date = new Date(timestamp);
        return date.toLocaleString();
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new BaselineDashboard();
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
