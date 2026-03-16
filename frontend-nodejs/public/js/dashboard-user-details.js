export async function viewAdminUserDetail(dashboard, userID) {
    const id = String(userID || '').trim();
    if (!id || !dashboard.isAdmin()) {
        return;
    }
    try {
        const detailPath = `/v1/users/${encodeURIComponent(id)}`;
        const activityPath = buildSelectedUserActivityPath(
            dashboard,
            id,
            Number(dashboard.userState.selectedActivityLimit || 10),
            0
        );
        const [detail, activity] = await Promise.all([
            dashboard.apiRequest(detailPath),
            dashboard.apiRequest(activityPath)
        ]);
        dashboard.userState.selected = detail && typeof detail === 'object' ? detail : null;
        const firstPageEvents = Array.isArray(activity?.events) ? activity.events : [];
        const firstPageOffset = Number(activity?.offset || 0);
        dashboard.userState.selectedActivity = firstPageEvents;
        dashboard.userState.selectedActivityTotal = Number(activity?.total || firstPageEvents.length);
        dashboard.userState.selectedActivityOffset = firstPageOffset + firstPageEvents.length;
        dashboard.userState.selectedActivityHasMore = activity?.has_more === true;
        dashboard.renderUsersTab(dashboard.userState.rows);
    } catch (error) {
        dashboard.showError(error.message || 'Failed to load user detail.');
    }
}

export function buildSelectedUserActivityPath(dashboard, userID, limit, offset) {
    const safeUserID = String(userID || '').trim();
    const safeLimit = Number.isFinite(limit) && limit > 0 ? Math.min(limit, 200) : 10;
    const safeOffset = Number.isFinite(offset) && offset >= 0 ? offset : 0;
    const params = new URLSearchParams();
    params.set('limit', String(safeLimit));
    params.set('offset', String(safeOffset));

    const filters = dashboard.userState.selectedActivityFilters || {};
    const eventType = String(filters.eventType || '').trim().toLowerCase();
    if (eventType) {
        params.set('event_type', eventType);
    }

    const fromRFC3339 = activityFilterDateToRFC3339(filters.from);
    if (fromRFC3339) {
        params.set('from', fromRFC3339);
    }
    const toRFC3339 = activityFilterDateToRFC3339(filters.to);
    if (toRFC3339) {
        params.set('to', toRFC3339);
    }

    return `/v1/users/${encodeURIComponent(safeUserID)}/activity?${params.toString()}`;
}

export function activityFilterDateToRFC3339(raw) {
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

export async function loadMoreSelectedUserActivity(dashboard) {
    const selectedID = String(dashboard.userState.selected?.id || '').trim();
    if (!selectedID || !dashboard.userState.selectedActivityHasMore) {
        return;
    }
    const limit = Number(dashboard.userState.selectedActivityLimit || 10);
    const nextOffset = Number(dashboard.userState.selectedActivityOffset || 0);
    const path = buildSelectedUserActivityPath(dashboard, selectedID, limit, nextOffset);
    try {
        const activity = await dashboard.apiRequest(path);
        const additional = Array.isArray(activity?.events) ? activity.events : [];
        dashboard.userState.selectedActivity = [...dashboard.userState.selectedActivity, ...additional];
        dashboard.userState.selectedActivityTotal = Number(activity?.total || dashboard.userState.selectedActivity.length);
        dashboard.userState.selectedActivityOffset = Number(activity?.offset || nextOffset) + additional.length;
        dashboard.userState.selectedActivityHasMore = activity?.has_more === true;
        dashboard.renderUsersTab(dashboard.userState.rows);
    } catch (error) {
        dashboard.showError(error.message || 'Failed to load more user activity.');
    }
}
