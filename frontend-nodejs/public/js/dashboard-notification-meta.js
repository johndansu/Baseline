export function notificationStorageKey(dashboard) {
    const identityKey = String(dashboard.identity?.userID || dashboard.identity?.email || dashboard.identity?.subject || dashboard.authz?.role || 'anonymous')
        .trim()
        .toLowerCase();
    return `baseline.notifications.read.${identityKey}`;
}

export function loadReadNotificationIDs(dashboard) {
    try {
        const raw = window.localStorage.getItem(notificationStorageKey(dashboard));
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

export function persistReadNotificationIDs(dashboard) {
    try {
        const importantIDs = new Set(
            dashboard.selectNotifications(dashboard.notificationsState.items)
                .map((item) => String(item?.id || '').trim())
                .filter(Boolean)
        );
        const retained = Array.from(dashboard.notificationsState.readIDs).filter((id) => importantIDs.has(id));
        window.localStorage.setItem(notificationStorageKey(dashboard), JSON.stringify(retained));
        dashboard.notificationsState.readIDs = new Set(retained);
    } catch (_) {
        // Ignore storage failures.
    }
}

export function isImportantNotification(dashboard, item) {
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

export function isAttentionNotification(_dashboard, item) {
    const action = String(item?.action || item?.event_type || '').toLowerCase();
    return action.includes('fail') || action.includes('blocked') || action.includes('warn') || action.includes('retry');
}

export function countNotificationGroups(_dashboard, items) {
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

export function notificationTone(_dashboard, item) {
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

export function notificationTargetTab(dashboard, item) {
    const action = String(item?.action || item?.event_type || '').toLowerCase();
    const itemType = String(item?.type || '').toLowerCase();
    if (itemType === 'integration' || action.startsWith('integration_') || action.startsWith('github_') || action.startsWith('gitlab_')) {
        return 'audit';
    }
    if (action.startsWith('scan_') || action === 'scan_uploaded' || action === 'enforcement_failed') {
        return dashboard.hasCapability('scans.read') ? 'scans' : 'audit';
    }
    if (action.startsWith('project_')) {
        return dashboard.hasCapability('projects.read') ? 'projects' : 'audit';
    }
    if (action.startsWith('api_key_')) {
        return dashboard.hasCapability('api_keys.read') ? 'keys' : 'audit';
    }
    if (action === 'policy_updated' || action === 'ruleset_updated') {
        return 'policies';
    }
    if (action === 'user_updated' && dashboard.isAdmin()) {
        return 'users';
    }
    return 'audit';
}

export function notificationTargetLabel(_dashboard, tab) {
    const labels = {
        overview: 'overview',
        scans: 'scan history',
        projects: 'projects',
        policies: 'policies',
        users: 'users',
        keys: 'API keys',
        audit: 'audit log',
        settings: 'settings'
    };
    return labels[tab] || 'details';
}

export function notificationActionLabel(dashboard, item, targetTab) {
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
        return 'Open audit log';
    }
    return `Open ${notificationTargetLabel(dashboard, targetTab)}`;
}

export function notificationTitle(dashboard, item) {
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
    return titles[action] || dashboard.describeEventLabel(item);
}

export function notificationSummary(dashboard, item) {
    const action = String(item?.action || item?.event_type || '').toLowerCase();
    const projectID = String(item?.project_id || '').trim();
    const scanID = String(item?.scan_id || '').trim();
    const actor = dashboard.formatActorLabel(item?.actor);

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
            return join('Someone\'s access or profile details changed', actor ? `updated by ${actor}` : '');
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
            return dashboard.describeActivitySummary(item);
    }
}
