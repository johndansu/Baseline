export function setupDashboardShellEvents(dashboard) {
    const searchInput = document.getElementById('dashboard-search');
    if (searchInput) {
        searchInput.addEventListener('input', (event) => {
            handleDashboardSearch(dashboard, event.target?.value);
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
            await dashboard.openNotificationsModal();
        });
    }

    const userButton = document.getElementById('dashboard-user-button');
    const userDropdown = document.getElementById('userDropdown');
    if (userButton && userDropdown) {
        userButton.addEventListener('click', (event) => {
            event.preventDefault();
            event.stopPropagation();
            userDropdown.classList.toggle('hidden');
        });

        document.addEventListener('click', (event) => {
            if (!userDropdown.classList.contains('hidden')) {
                const target = event.target;
                if (!userDropdown.contains(target) && !userButton.contains(target)) {
                    userDropdown.classList.add('hidden');
                }
            }
        });
    }

    document.querySelectorAll('[data-profile-tab]').forEach((link) => {
        link.addEventListener('click', async (event) => {
            event.preventDefault();
            const tabName = link.getAttribute('data-profile-tab');
            if (userDropdown) {
                userDropdown.classList.add('hidden');
            }
            if (tabName) {
                await dashboard.switchTab(tabName);
            }
        });
    });

    const signOutButton = document.getElementById('dashboard-signout-button');
    if (signOutButton) {
        signOutButton.addEventListener('click', async (event) => {
            event.preventDefault();
            if (userDropdown) {
                userDropdown.classList.add('hidden');
            }
            await signOutDashboard(dashboard);
        });
    }
}

export function handleDashboardSearch(dashboard, query) {
    const normalized = String(query || '').trim().toLowerCase();
    const currentTabRoot = document.getElementById(`${dashboard.currentTab}-tab`);
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

export async function signOutDashboard(dashboard) {
    try {
        await dashboard.apiRequest('/v1/auth/session', {
            method: 'DELETE'
        });
    } catch (_) {
        // Continue redirect even if API logout fails.
    }
    clearPersistedBrowserAuthState();
    window.location.href = '/signin.html';
}

function clearPersistedBrowserAuthState() {
    const clearStore = (store) => {
        if (!store) {
            return;
        }
        const keysToRemove = [];
        for (let i = 0; i < store.length; i += 1) {
            const key = store.key(i);
            if (!key) {
                continue;
            }
            const normalized = String(key).toLowerCase();
            if (
                normalized === 'supabase.auth.token' ||
                (normalized.startsWith('sb-') && normalized.includes('auth-token')) ||
                normalized.includes('supabase.auth.token')
            ) {
                keysToRemove.push(key);
            }
        }
        keysToRemove.forEach((key) => {
            try {
                store.removeItem(key);
            } catch (_) {
                // Ignore storage cleanup failures.
            }
        });
    };

    clearStore(window.localStorage);
    clearStore(window.sessionStorage);
}

function toggleResponsiveSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) {
        sidebar.classList.toggle('-translate-x-full');
    }
}

function setupResponsiveSidebar() {
    if (window.innerWidth >= 768) {
        return;
    }

    const sidebar = document.getElementById('sidebar');
    if (!sidebar) {
        return;
    }
    sidebar.classList.add('-translate-x-full');

    const mobileMenuButton = document.createElement('button');
    mobileMenuButton.className = 'fixed top-4 left-4 z-50 p-2 bg-white rounded-lg shadow-lg md:hidden';
    mobileMenuButton.innerHTML = `
        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path>
        </svg>
    `;
    mobileMenuButton.addEventListener('click', toggleResponsiveSidebar);
    document.body.appendChild(mobileMenuButton);
}

export function mountDashboardApplication(createDashboard) {
    document.addEventListener('DOMContentLoaded', () => {
        window.baselineDashboard = createDashboard();
        setupResponsiveSidebar();
    });
}
