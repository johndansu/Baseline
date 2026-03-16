export function renderCLITelemetryPanel(dashboard) {
    const cliTab = document.getElementById('cli-tab');
    if (!cliTab) return;

    const traces = Array.isArray(dashboard.cliState?.traces) ? dashboard.cliState.traces : [];
    const filters = dashboard.cliState?.filters || {};
    const filtered = filterCLITraces(dashboard, traces, filters);
    const commands = Array.from(new Set(traces.map((trace) => String(trace.command || '').trim()).filter(Boolean))).sort();
    const repositories = Array.from(new Set(traces.map((trace) => String(trace.repository || '').trim()).filter(Boolean))).sort();
    const statuses = Array.from(new Set(traces.map((trace) => String(trace.status || '').trim()).filter(Boolean))).sort();
    const projects = Array.from(new Set(traces.map((trace) => String(trace.project_id || '').trim()).filter(Boolean))).sort();
    const summary = summarizeCLITraces(filtered);
    const grouping = summarizeCLITraceGroups(filtered);
    const trends = summarizeCLITraceTrends(filtered);
    const quick = String(filters.quick || 'all').trim().toLowerCase();

    cliTab.innerHTML = `
        <div class="space-y-6">
            <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
                ${renderSummaryCard('Runs', summary.total)}
                ${renderSummaryCard('Healthy', summary.ok)}
                ${renderSummaryCard('Warnings', summary.warnings)}
                ${renderSummaryCard('Errors', summary.errors)}
                ${renderSummaryCard('Avg Duration', formatDuration(summary.averageDuration))}
            </div>
            <div class="bg-white rounded-lg border border-gray-200">
                <div class="p-6 border-b border-gray-200 flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900">CLI Trace Runs</h3>
                        <p class="text-sm text-gray-700 mt-1">Admin-only trace visibility for executed CLI commands, branches, helper steps, and outcomes.</p>
                    </div>
                    <div class="flex flex-wrap items-center gap-2">
                        ${renderQuickToggle('All runs', 'all', quick)}
                        ${renderQuickToggle('Warnings only', 'warning', quick)}
                        ${renderQuickToggle('Errors only', 'error', quick)}
                        <button type="button" id="cli-trace-clear-filters" class="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 text-sm font-medium">
                            Clear filters
                        </button>
                        <button type="button" id="cli-trace-export" class="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 text-sm font-medium" style="background-color:#ea580c;color:#ffffff;">
                            Export JSON
                        </button>
                    </div>
                </div>
                <div class="p-6 border-b border-gray-200 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
                    <div>
                        <label for="cli-filter-command" class="block text-xs font-semibold uppercase tracking-wide text-gray-500 mb-2">Command</label>
                        <select id="cli-filter-command" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm">
                            <option value="all">All commands</option>
                            ${commands.map((command) => `<option value="${dashboard.escapeHtml(command)}"${filters.command === command ? ' selected' : ''}>${dashboard.escapeHtml(command)}</option>`).join('')}
                        </select>
                    </div>
                    <div>
                        <label for="cli-filter-repository" class="block text-xs font-semibold uppercase tracking-wide text-gray-500 mb-2">Repository</label>
                        <select id="cli-filter-repository" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm">
                            <option value="all">All repositories</option>
                            ${repositories.map((repository) => `<option value="${dashboard.escapeHtml(repository)}"${filters.repository === repository ? ' selected' : ''}>${dashboard.escapeHtml(repository)}</option>`).join('')}
                        </select>
                    </div>
                    <div>
                        <label for="cli-filter-status" class="block text-xs font-semibold uppercase tracking-wide text-gray-500 mb-2">Status</label>
                        <select id="cli-filter-status" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm">
                            <option value="all">All statuses</option>
                            ${statuses.map((status) => `<option value="${dashboard.escapeHtml(status)}"${filters.status === status ? ' selected' : ''}>${dashboard.escapeHtml(status)}</option>`).join('')}
                        </select>
                    </div>
                    <div>
                        <label for="cli-filter-project" class="block text-xs font-semibold uppercase tracking-wide text-gray-500 mb-2">Project</label>
                        <select id="cli-filter-project" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm">
                            <option value="all">All projects</option>
                            ${projects.map((project) => `<option value="${dashboard.escapeHtml(project)}"${filters.project === project ? ' selected' : ''}>${dashboard.escapeHtml(project)}</option>`).join('')}
                        </select>
                    </div>
                    <div>
                        <label for="cli-filter-query" class="block text-xs font-semibold uppercase tracking-wide text-gray-500 mb-2">Search</label>
                        <input id="cli-filter-query" type="text" value="${dashboard.escapeHtml(filters.query || '')}" placeholder="trace, repo, message..." class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm">
                    </div>
                </div>
                ${renderTrendSection(trends)}
                ${renderGroupingSection(dashboard, grouping)}
                ${renderCLITraceTable(dashboard, filtered)}
            </div>
        </div>
    `;

    bindCLITelemetryControls(dashboard, filtered);
}

export function renderCLITraceDetailContent(dashboard, trace, isLoading = false, errorMessage = '') {
    const content = document.getElementById('cli-trace-detail-content');
    if (!content) {
        return;
    }
    if (isLoading) {
        content.innerHTML = `
            <div class="space-y-3">
                <h3 class="text-lg font-semibold text-gray-900">Trace Details</h3>
                <p class="text-sm text-gray-700">Loading trace detail...</p>
            </div>
        `;
        return;
    }
    if (errorMessage) {
        content.innerHTML = `
            <div class="space-y-3">
                <h3 class="text-lg font-semibold text-gray-900">Trace Details</h3>
                <p class="text-sm text-red-600">${dashboard.escapeHtml(errorMessage)}</p>
            </div>
        `;
        return;
    }
    if (!trace || !trace.summary) {
        content.innerHTML = `
            <div class="space-y-3">
                <h3 class="text-lg font-semibold text-gray-900">Trace Details</h3>
                <p class="text-sm text-gray-700">Trace detail is not available.</p>
            </div>
        `;
        return;
    }

    const summary = trace.summary || {};
    const events = Array.isArray(trace.events) ? trace.events : [];
    const title = `${String(summary.command || 'command').trim() || 'command'} trace`;

    content.innerHTML = `
        <div class="space-y-3">
            <div class="flex items-start justify-between gap-3">
                <div>
                    <h3 class="text-base font-semibold text-gray-900">${dashboard.escapeHtml(title)}</h3>
                    <p class="mt-1 text-sm text-gray-700">${dashboard.escapeHtml(summary.message || 'Detailed execution trace')}</p>
                </div>
                <button type="button" id="cli-trace-detail-export" class="px-3 py-1.5 bg-orange-600 text-white rounded-lg hover:bg-orange-700 text-sm font-medium shrink-0" style="background-color:#ea580c;color:#ffffff;">
                    Export Trace
                </button>
            </div>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                ${renderDetailStat(dashboard, 'Trace ID', summary.trace_id)}
                ${renderDetailStat(dashboard, 'Status', summary.status || 'unknown')}
                ${renderDetailStat(dashboard, 'Started', dashboard.formatDate(summary.started_at))}
                ${renderDetailStat(dashboard, 'Duration', formatDuration(summary.duration_ms))}
                ${renderDetailStat(dashboard, 'Repository', summary.repository || '-')}
                ${renderDetailStat(dashboard, 'Project', summary.project_id || '-')}
                ${renderDetailStat(dashboard, 'Scan', summary.scan_id || '-')}
                ${renderDetailStat(dashboard, 'Events', String(summary.event_count ?? events.length))}
            </div>
            <div class="rounded-lg border border-gray-200">
                <div class="px-3 py-2.5 border-b border-gray-200 bg-gray-50">
                    <h4 class="text-sm font-semibold text-gray-900">Event Timeline</h4>
                </div>
                <div class="max-h-[32vh] overflow-y-auto">
                    ${renderTraceEvents(dashboard, events)}
                </div>
            </div>
        </div>
    `;

    const exportButton = document.getElementById('cli-trace-detail-export');
    if (exportButton) {
        exportButton.addEventListener('click', () => {
            exportTraceDetail(trace);
        });
    }
}

function renderSummaryCard(label, value) {
    return `
        <div class="bg-white rounded-lg border border-gray-200 p-4">
            <p class="text-xs font-semibold uppercase tracking-wide text-gray-500">${label}</p>
            <p class="mt-2 text-2xl font-bold text-gray-900">${value}</p>
        </div>
    `;
}

function renderCLITraceTable(dashboard, traces) {
    if (!traces.length) {
        return `
            <div class="p-6">
                <p class="text-sm text-gray-700">No CLI traces matched the current filters.</p>
            </div>
        `;
    }

    return `
        <div class="overflow-x-auto">
            <table class="w-full">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Started</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Command</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Repository</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Duration</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Events</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    ${traces.map((trace) => `
                        <tr>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${dashboard.formatDate(trace.started_at)}</td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                <div class="text-sm font-medium text-gray-900">${dashboard.escapeHtml(trace.command || '-')}</div>
                                <div class="text-xs text-gray-500">${dashboard.escapeHtml(trace.trace_id || '')}</div>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm">${renderStatusBadge(dashboard, trace.status)}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${dashboard.escapeHtml(trace.repository || '-')}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${dashboard.escapeHtml(trace.project_id || '-')}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${dashboard.escapeHtml(formatDuration(trace.duration_ms))}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${dashboard.escapeHtml(String(trace.event_count ?? 0))}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm">
                                <button type="button" data-cli-trace-view="${dashboard.escapeHtml(trace.trace_id || '')}" class="inline-flex items-center px-3 py-1.5 rounded-lg border border-orange-200 text-orange-700 hover:bg-orange-50 font-medium">
                                    View trace
                                </button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function renderGroupingSection(dashboard, grouping) {
    if (!grouping.repositories.length && !grouping.projects.length) {
        return '';
    }

    return `
        <div class="p-6 border-b border-gray-200 space-y-4">
            <div class="grid grid-cols-1 xl:grid-cols-2 gap-4">
                <div class="rounded-lg border border-gray-200 bg-gray-50">
                    <div class="px-4 py-3 border-b border-gray-200">
                        <h4 class="text-sm font-semibold text-gray-900">Repositories</h4>
                        <p class="text-xs text-gray-500 mt-1">Where trace activity is clustering.</p>
                    </div>
                    ${renderGroupTable(dashboard, grouping.repositories, 'repository')}
                </div>
                <div class="rounded-lg border border-gray-200 bg-gray-50">
                    <div class="px-4 py-3 border-b border-gray-200">
                        <h4 class="text-sm font-semibold text-gray-900">Projects</h4>
                        <p class="text-xs text-gray-500 mt-1">Which connected projects are producing the most trace runs.</p>
                    </div>
                    ${renderGroupTable(dashboard, grouping.projects, 'project')}
                </div>
            </div>
        </div>
    `;
}

function renderTrendSection(trends) {
    return `
        <div class="p-6 border-b border-gray-200">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                ${renderTrendCard('Errors today', trends.errorsToday, trends.errorsDelta, 'error')}
                ${renderTrendCard('Warnings today', trends.warningsToday, trends.warningsDelta, 'warning')}
                ${renderTrendCard('Runs today', trends.runsToday, trends.runsDelta, 'neutral')}
            </div>
        </div>
    `;
}

function renderStatusBadge(dashboard, status) {
    const normalized = String(status || 'unknown').trim().toLowerCase();
    let className = 'inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-700';
    if (normalized === 'ok' || normalized === 'pass' || normalized === 'success') {
        className = 'inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800';
    } else if (normalized === 'warning' || normalized === 'warn') {
        className = 'inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800';
    } else if (normalized === 'error' || normalized === 'failed' || normalized === 'fail') {
        className = 'inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800';
    }
    return `<span class="${className}">${dashboard.escapeHtml(normalized || 'unknown')}</span>`;
}

function renderGroupTable(dashboard, groups, kind) {
    if (!groups.length) {
        return `
            <div class="p-4">
                <p class="text-sm text-gray-700">No ${kind} grouping is available for the current filters.</p>
            </div>
        `;
    }

    return `
        <div class="divide-y divide-gray-200">
            ${groups.slice(0, 6).map((group) => `
                <button type="button" data-cli-group-kind="${kind}" data-cli-group-value="${dashboard.escapeHtml(group.name)}" class="w-full px-4 py-3 flex items-center justify-between gap-3 text-left hover:bg-white transition-colors">
                    <div class="min-w-0">
                        <p class="text-sm font-medium text-gray-900 truncate">${dashboard.escapeHtml(group.name)}</p>
                        <p class="text-xs text-gray-500 mt-1">
                            ${group.errors} errors | ${group.warnings} warnings | ${group.ok} healthy
                        </p>
                    </div>
                    <div class="text-right shrink-0">
                        <p class="text-sm font-semibold text-gray-900">${group.total}</p>
                        <p class="text-xs text-gray-500">runs</p>
                    </div>
                </button>
            `).join('')}
        </div>
    `;
}

function bindCLITelemetryControls(dashboard, filtered) {
    bindSelectFilter('cli-filter-command', dashboard, 'command');
    bindSelectFilter('cli-filter-repository', dashboard, 'repository');
    bindSelectFilter('cli-filter-status', dashboard, 'status');
    bindSelectFilter('cli-filter-project', dashboard, 'project');

    document.querySelectorAll('[data-cli-quick-filter]').forEach((button) => {
        if (button.dataset.bound === '1') {
            return;
        }
        button.dataset.bound = '1';
        button.addEventListener('click', () => {
            dashboard.cliState.filters.quick = String(button.dataset.cliQuickFilter || 'all').trim().toLowerCase();
            renderCLITelemetryPanel(dashboard);
        });
    });

    const queryFilter = document.getElementById('cli-filter-query');
    if (queryFilter) {
        queryFilter.addEventListener('input', () => {
            dashboard.cliState.filters.query = queryFilter.value;
            renderCLITelemetryPanel(dashboard);
        });
    }

    const exportButton = document.getElementById('cli-trace-export');
    if (exportButton) {
        exportButton.addEventListener('click', () => {
            const payload = JSON.stringify({ exported_at: new Date().toISOString(), traces: filtered }, null, 2);
            const blob = new Blob([payload], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const anchor = document.createElement('a');
            anchor.href = url;
            anchor.download = 'baseline-cli-traces.json';
            document.body.appendChild(anchor);
            anchor.click();
            document.body.removeChild(anchor);
            URL.revokeObjectURL(url);
        });
    }

    const clearFiltersButton = document.getElementById('cli-trace-clear-filters');
    if (clearFiltersButton) {
        clearFiltersButton.addEventListener('click', () => {
            dashboard.cliState.filters = {
                command: 'all',
                repository: 'all',
                status: 'all',
                project: 'all',
                quick: 'all',
                query: ''
            };
            renderCLITelemetryPanel(dashboard);
        });
    }

    document.querySelectorAll('[data-cli-trace-view]').forEach((button) => {
        if (button.dataset.bound === '1') {
            return;
        }
        button.dataset.bound = '1';
        button.addEventListener('click', () => {
            const traceID = String(button.dataset.cliTraceView || '').trim();
            if (!traceID) {
                return;
            }
            dashboard.openCLITraceDetail(traceID);
        });
    });

    document.querySelectorAll('[data-cli-group-kind]').forEach((button) => {
        if (button.dataset.bound === '1') {
            return;
        }
        button.dataset.bound = '1';
        button.addEventListener('click', () => {
            const kind = String(button.dataset.cliGroupKind || '').trim().toLowerCase();
            const value = String(button.dataset.cliGroupValue || '').trim();
            if (!value) {
                return;
            }
            if (kind === 'repository') {
                dashboard.cliState.filters.repository = value;
            } else if (kind === 'project') {
                dashboard.cliState.filters.project = value;
            }
            renderCLITelemetryPanel(dashboard);
        });
    });
}

function bindSelectFilter(id, dashboard, key) {
    const element = document.getElementById(id);
    if (!element) {
        return;
    }
    element.addEventListener('change', () => {
        dashboard.cliState.filters[key] = element.value;
        renderCLITelemetryPanel(dashboard);
    });
}

function filterCLITraces(dashboard, traces, filters) {
    const command = String(filters.command || 'all').trim().toLowerCase();
    const repository = String(filters.repository || 'all').trim().toLowerCase();
    const status = String(filters.status || 'all').trim().toLowerCase();
    const project = String(filters.project || 'all').trim().toLowerCase();
    const quick = String(filters.quick || 'all').trim().toLowerCase();
    const query = String(filters.query || '').trim().toLowerCase();

    return traces.filter((trace) => {
        const traceCommand = String(trace.command || '').trim().toLowerCase();
        const traceRepository = String(trace.repository || '').trim().toLowerCase();
        const traceStatus = String(trace.status || '').trim().toLowerCase();
        const traceProject = String(trace.project_id || '').trim().toLowerCase();
        const traceQuick = classifyQuickStatus(traceStatus);
        if (command !== 'all' && traceCommand !== command) {
            return false;
        }
        if (repository !== 'all' && traceRepository !== repository) {
            return false;
        }
        if (status !== 'all' && traceStatus !== status) {
            return false;
        }
        if (project !== 'all' && traceProject !== project) {
            return false;
        }
        if (quick !== 'all' && traceQuick !== quick) {
            return false;
        }
        if (!query) {
            return true;
        }
        const haystack = [
            trace.trace_id,
            trace.command,
            trace.repository,
            trace.project_id,
            trace.scan_id,
            trace.status,
            trace.message,
            trace.version
        ].join(' ').toLowerCase();
        return haystack.includes(query);
    });
}

function summarizeCLITraces(traces) {
    let ok = 0;
    let warnings = 0;
    let errors = 0;
    let totalDuration = 0;

    for (const trace of traces) {
        const status = String(trace.status || '').trim().toLowerCase();
        totalDuration += Number(trace.duration_ms || 0);
        if (status === 'ok' || status === 'pass' || status === 'success') {
            ok += 1;
        } else if (status === 'warning' || status === 'warn') {
            warnings += 1;
        } else if (status === 'error' || status === 'fail' || status === 'failed') {
            errors += 1;
        }
    }

    return {
        total: traces.length,
        ok,
        warnings,
        errors,
        averageDuration: traces.length ? Math.round(totalDuration / traces.length) : 0
    };
}

function summarizeCLITraceGroups(traces) {
    return {
        repositories: summarizeCLITraceGroupSet(traces, (trace) => String(trace.repository || '').trim() || 'Unknown repository'),
        projects: summarizeCLITraceGroupSet(traces, (trace) => String(trace.project_id || '').trim() || 'Unattached project')
    };
}

function summarizeCLITraceTrends(traces) {
    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const startOfYesterday = new Date(startOfToday);
    startOfYesterday.setDate(startOfYesterday.getDate() - 1);

    let runsToday = 0;
    let runsYesterday = 0;
    let errorsToday = 0;
    let errorsYesterday = 0;
    let warningsToday = 0;
    let warningsYesterday = 0;

    for (const trace of traces) {
        const startedAt = new Date(trace.started_at);
        if (Number.isNaN(startedAt.getTime())) {
            continue;
        }
        const status = String(trace.status || '').trim().toLowerCase();
        const isError = status === 'error' || status === 'fail' || status === 'failed';
        const isWarning = status === 'warning' || status === 'warn';

        if (startedAt >= startOfToday) {
            runsToday += 1;
            if (isError) errorsToday += 1;
            if (isWarning) warningsToday += 1;
            continue;
        }
        if (startedAt >= startOfYesterday && startedAt < startOfToday) {
            runsYesterday += 1;
            if (isError) errorsYesterday += 1;
            if (isWarning) warningsYesterday += 1;
        }
    }

    return {
        runsToday,
        runsDelta: runsToday - runsYesterday,
        errorsToday,
        errorsDelta: errorsToday - errorsYesterday,
        warningsToday,
        warningsDelta: warningsToday - warningsYesterday
    };
}

function summarizeCLITraceGroupSet(traces, getLabel) {
    const groups = new Map();
    for (const trace of traces) {
        const name = getLabel(trace);
        const key = name.toLowerCase();
        if (!groups.has(key)) {
            groups.set(key, {
                name,
                total: 0,
                ok: 0,
                warnings: 0,
                errors: 0
            });
        }
        const entry = groups.get(key);
        entry.total += 1;
        const status = String(trace.status || '').trim().toLowerCase();
        if (status === 'warning' || status === 'warn') {
            entry.warnings += 1;
        } else if (status === 'error' || status === 'failed' || status === 'fail') {
            entry.errors += 1;
        } else {
            entry.ok += 1;
        }
    }
    return Array.from(groups.values()).sort((left, right) => {
        if (right.total !== left.total) {
            return right.total - left.total;
        }
        if (right.errors !== left.errors) {
            return right.errors - left.errors;
        }
        return left.name.localeCompare(right.name);
    });
}

function renderQuickToggle(label, value, activeValue) {
    const isActive = value === activeValue;
    const className = isActive
        ? 'inline-flex items-center px-3 py-2 rounded-lg border text-sm font-medium bg-orange-600 text-white border-orange-600'
        : 'inline-flex items-center px-3 py-2 rounded-lg border text-sm font-medium bg-white text-gray-700 border-gray-300 hover:bg-gray-50';
    return `<button type="button" data-cli-quick-filter="${value}" class="${className}">${label}</button>`;
}

function classifyQuickStatus(status) {
    const normalized = String(status || '').trim().toLowerCase();
    if (normalized === 'warning' || normalized === 'warn') {
        return 'warning';
    }
    if (normalized === 'error' || normalized === 'failed' || normalized === 'fail') {
        return 'error';
    }
    return 'all';
}

function renderDetailStat(dashboard, label, value) {
    return `
        <div class="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2">
            <p class="text-[11px] font-medium uppercase tracking-wide text-gray-500">${dashboard.escapeHtml(label)}</p>
            <p class="mt-1 text-sm font-medium text-gray-900 break-words">${dashboard.escapeHtml(String(value || '-'))}</p>
        </div>
    `;
}

function renderTraceEvents(dashboard, events) {
    if (!events.length) {
        return `
            <div class="p-4">
                <p class="text-sm text-gray-700">No trace events were recorded.</p>
            </div>
        `;
    }

    return `
        <div class="divide-y divide-gray-200">
            ${events.map((event) => `
                <div class="p-2.5 space-y-2">
                    <div class="flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
                        <div class="space-y-1">
                            <div class="flex flex-wrap items-center gap-2">
                                <span class="text-sm font-semibold text-gray-900">${dashboard.escapeHtml(event.type || 'event')}</span>
                                ${event.status ? renderStatusBadge(dashboard, event.status) : ''}
                            </div>
                            <p class="text-xs text-gray-500">
                                ${dashboard.escapeHtml(composeEventLocation(event))}
                            </p>
                        </div>
                        <span class="text-xs text-gray-500">${dashboard.formatDate(event.created_at)}</span>
                    </div>
                    ${event.message ? `<p class="text-sm text-gray-700">${dashboard.escapeHtml(event.message)}</p>` : ''}
                    ${renderEventAttributes(dashboard, event.attributes)}
                </div>
            `).join('')}
        </div>
    `;
}

function composeEventLocation(event) {
    const parts = [];
    if (event.component) {
        parts.push(event.component);
    }
    if (event.function) {
        parts.push(event.function);
    }
    if (event.branch) {
        parts.push(`branch ${event.branch}`);
    }
    if (event.span_id) {
        parts.push(`span ${event.span_id}`);
    }
    return parts.join(' • ') || 'Trace event';
}

function renderEventAttributes(dashboard, attributes) {
    const pairs = Object.entries(attributes || {});
    if (!pairs.length) {
        return '';
    }
    return `
        <div class="flex flex-wrap gap-2">
            ${pairs.map(([key, value]) => `
                <span class="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-1 text-xs font-medium text-gray-700">
                    ${dashboard.escapeHtml(key)}=${dashboard.escapeHtml(String(value))}
                </span>
            `).join('')}
        </div>
    `;
}

function exportTraceDetail(trace) {
    const payload = JSON.stringify(trace, null, 2);
    const blob = new Blob([payload], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `baseline-cli-trace-${String(trace?.summary?.trace_id || 'trace').trim() || 'trace'}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
}

function formatDuration(durationMS) {
    const value = Number(durationMS || 0);
    if (!Number.isFinite(value) || value <= 0) {
        return '0ms';
    }
    if (value < 1000) {
        return `${Math.round(value)}ms`;
    }
    if (value < 60000) {
        return `${(value / 1000).toFixed(value >= 10000 ? 0 : 1)}s`;
    }
    return `${(value / 60000).toFixed(1)}m`;
}

function renderTrendCard(label, value, delta, tone) {
    let toneClasses = 'bg-gray-50 border-gray-200 text-gray-900';
    if (tone === 'error') {
        toneClasses = 'bg-red-50 border-red-200 text-red-900';
    } else if (tone === 'warning') {
        toneClasses = 'bg-yellow-50 border-yellow-200 text-yellow-900';
    }
    const deltaPrefix = delta > 0 ? '+' : '';
    const deltaClass = delta > 0
        ? (tone === 'error' ? 'text-red-700' : tone === 'warning' ? 'text-yellow-700' : 'text-blue-700')
        : delta < 0
            ? 'text-green-700'
            : 'text-gray-500';

    return `
        <div class="rounded-lg border p-4 ${toneClasses}">
            <p class="text-xs font-semibold uppercase tracking-wide">${label}</p>
            <div class="mt-2 flex items-end justify-between gap-3">
                <p class="text-2xl font-bold">${value}</p>
                <p class="text-xs font-medium ${deltaClass}">vs yesterday ${deltaPrefix}${delta}</p>
            </div>
        </div>
    `;
}
