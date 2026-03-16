export async function loadProjectsData(dashboard) {
    try {
        const [projectPayload, scanPayload] = await Promise.all([
            dashboard.apiRequest('/v1/projects'),
            dashboard.apiRequest('/v1/scans')
        ]);

        const projects = Array.isArray(projectPayload.projects) ? projectPayload.projects : [];
        const scans = Array.isArray(scanPayload.scans) ? scanPayload.scans : [];

        const scansByProject = new Map();
        scans.forEach((scan) => {
            const projectID = String(scan.project_id || '');
            if (!projectID) return;
            if (!scansByProject.has(projectID)) {
                scansByProject.set(projectID, []);
            }
            scansByProject.get(projectID).push(scan);
        });

        const normalizedProjects = projects.map((project) => {
            const projectScans = scansByProject.get(project.id) || [];
            projectScans.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
            const latestScan = projectScans[0] || null;
            const latestStatus = dashboard.normalizeScanStatus(latestScan?.status || '');

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

        dashboard.projectState.all = normalizedProjects;
        dashboard.projectState.byID = new Map(normalizedProjects.map((project) => [project.id, project]));
        dashboard.projectState.scansByProject = scansByProject;
        dashboard.renderProjectsTable(normalizedProjects);
    } catch (error) {
        dashboard.showError(error.message || 'Failed to load projects');
        dashboard.projectState.all = [];
        dashboard.projectState.byID = new Map();
        dashboard.projectState.scansByProject = new Map();
        dashboard.renderProjectsTable([]);
    }
}
