export async function loadScansData(dashboard) {
    try {
        const [scanPayload, projectPayload] = await Promise.all([
            dashboard.apiRequest('/v1/scans'),
            dashboard.apiRequest('/v1/projects')
        ]);

        const projects = Array.isArray(projectPayload.projects) ? projectPayload.projects : [];
        const projectNamesByID = new Map();
        projects.forEach((project) => {
            if (project && project.id) {
                projectNamesByID.set(project.id, project.name || project.id);
            }
        });

        const scans = Array.isArray(scanPayload.scans) ? scanPayload.scans : [];
        dashboard.scanState.all = scans
            .map((scan) => {
                const violations = Array.isArray(scan.violations) ? scan.violations : [];
                const blockingViolations = violations.filter((v) => String(v.severity || '').toLowerCase() === 'block').length;
                const warnings = violations.filter((v) => String(v.severity || '').toLowerCase() === 'warn').length;
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
        dashboard.scanState.page = 1;
        dashboard.scanState.statusFilter = 'all';
        dashboard.scanState.projectFilter = 'all';
        dashboard.renderScansTable(dashboard.scanState.all);
    } catch (error) {
        dashboard.showError(error.message || 'Failed to load scan history');
        dashboard.scanState.all = [];
        dashboard.renderScansTable([]);
    }
}
