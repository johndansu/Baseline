import { closeModal } from './dashboard-modal-actions.js';

export function updateNotificationsIndicator(dashboard) {
    const indicator = document.getElementById('notifications-indicator');
    if (!indicator) return;
    const unread = getUnreadNotifications(dashboard);
    if (unread.length > 0) {
        indicator.classList.remove('hidden');
    } else {
        indicator.classList.add('hidden');
    }
}

export function renderNotifications(dashboard, items) {
    const list = document.getElementById('notifications-list');
    const summary = document.getElementById('notifications-summary');
    const markReadButton = document.getElementById('notifications-mark-read-button');
    if (!list) return;

    if (markReadButton && markReadButton.dataset.bound !== '1') {
        markReadButton.dataset.bound = '1';
        markReadButton.addEventListener('click', () => {
            markAllNotificationsRead(dashboard);
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

    const grouped = groupNotifications(dashboard, items);

    if (summary) {
        const unreadCount = countUnreadNotifications(dashboard, items);
        const chips = [];
        chips.push(`<span class="inline-flex items-center px-2.5 py-1 rounded-full bg-gray-100 border border-gray-200 text-gray-700">${items.length} updates</span>`);
        if (unreadCount > 0) {
            chips.push(`<span class="inline-flex items-center px-2.5 py-1 rounded-full bg-gray-900 text-black">${unreadCount} unread</span>`);
        }
        summary.innerHTML = chips.join('');
    }

    if (markReadButton) {
        markReadButton.disabled = countUnreadNotifications(dashboard, items) === 0;
    }

    list.innerHTML = `
        ${renderNotificationSection(dashboard, 'Needs review', 'Items that may need your attention soon.', grouped.attention)}
        ${renderNotificationSection(dashboard, 'Latest updates', 'Recent changes across your projects and access.', grouped.changes)}
    `;

    list.querySelectorAll('[data-notification-tab]').forEach((button) => {
        if (button.dataset.bound === '1') {
            return;
        }
        button.dataset.bound = '1';
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-notification-tab') || 'overview';
            closeModal('notificationsModal');
            dashboard.switchTab(targetTab);
        });
    });
}

export function renderNotificationSection(dashboard, title, subtitle, items) {
    const body = Array.isArray(items) && items.length > 0
        ? items.map((item) => renderNotificationCard(dashboard, item)).join('')
        : `<div class="p-3 rounded-xl border border-dashed border-gray-200 bg-gray-50 text-sm text-gray-500">Nothing to show here.</div>`;

    return `
        <section class="space-y-2">
            <div>
                <h4 class="text-sm font-semibold text-gray-900">${dashboard.escapeHtml(title)}</h4>
                <p class="text-xs text-gray-500 mt-0.5">${dashboard.escapeHtml(subtitle)}</p>
            </div>
            <div class="space-y-2">
                ${body}
            </div>
        </section>
    `;
}

export function renderNotificationCard(dashboard, item) {
    const tone = dashboard.notificationTone(item);
    const targetTab = dashboard.notificationTargetTab(item);
    const actionLabel = dashboard.notificationActionLabel(item, targetTab);
    const unread = isNotificationUnread(dashboard, item);
    return `
        <div class="rounded-xl border ${tone.border} bg-white overflow-hidden ${unread ? 'ring-1 ring-offset-0 ring-gray-200' : ''}">
            <button
                type="button"
                data-notification-tab="${dashboard.escapeHtml(targetTab)}"
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
                                    <p class="text-sm font-semibold text-gray-900">${dashboard.escapeHtml(dashboard.notificationTitle(item))}</p>
                                    ${unread ? '<span class="inline-flex items-center justify-center w-2.5 h-2.5 rounded-full bg-amber-500" aria-label="Unread notification" title="Unread"></span>' : ''}
                                </div>
                                <p class="text-xs text-gray-600 mt-1">${dashboard.escapeHtml(dashboard.notificationSummary(item))}</p>
                            </div>
                            <span class="text-[11px] font-medium whitespace-nowrap text-gray-400">${dashboard.formatDate(item.created_at || item.timestamp)}</span>
                        </div>
                        <div class="mt-2 flex items-center justify-between gap-3">
                            <span class="text-[11px] text-gray-500">${dashboard.escapeHtml(dashboard.notificationTargetLabel(targetTab))}</span>
                            <span class="inline-flex items-center text-[11px] font-medium text-gray-700">${dashboard.escapeHtml(actionLabel)}</span>
                        </div>
                    </div>
                </div>
            </button>
        </div>
    `;
}

export function groupNotifications(dashboard, items) {
    const groups = { attention: [], changes: [] };
    for (const item of items) {
        if (dashboard.isAttentionNotification(item)) {
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

export function selectNotifications(dashboard, items) {
    if (!Array.isArray(items)) {
        return [];
    }
    const actionable = items.filter((item) => dashboard.isImportantNotification(item));
    return actionable.slice(0, 8);
}

export function isNotificationUnread(dashboard, item) {
    const id = String(item?.id || '').trim();
    if (!id) {
        return false;
    }
    return !dashboard.notificationsState.readIDs.has(id);
}

export function countUnreadNotifications(dashboard, items) {
    return (Array.isArray(items) ? items : []).filter((item) => isNotificationUnread(dashboard, item)).length;
}

export function getUnreadNotifications(dashboard) {
    const important = selectNotifications(dashboard, dashboard.notificationsState.items);
    return important.filter((item) => isNotificationUnread(dashboard, item));
}

export function markAllNotificationsRead(dashboard) {
    const important = selectNotifications(dashboard, dashboard.notificationsState.items);
    if (!important.length) {
        return;
    }
    important.forEach((item) => {
        const id = String(item?.id || '').trim();
        if (id) {
            dashboard.notificationsState.readIDs.add(id);
        }
    });
    dashboard.persistReadNotificationIDs();
    updateNotificationsIndicator(dashboard);
    renderNotifications(dashboard, important);
}
