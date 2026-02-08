# GitHub Branch Protection Setup for Production

## Current Issue
GitHub is blocking pushes due to branch protection rules that need to be configured.

## Solution: Configure Branch Protection

### 1. Go to GitHub Settings
URL: https://github.com/johndansu/Baseline/settings/branches

### 2. Create Branch Protection Rule
- Click "Add branch protection rule"
- Branch name pattern: `main`

### 3. Enable Required Status Checks
Check these boxes:
- [x] Require status checks to pass before merging
- [x] Require branches to be up to date before merging

### 4. Add Required Status Checks
Add these checks:
- `baseline-check` (from GitHub Actions)
- `baseline-scan` (from GitHub Actions)
- `CI/CD Pipeline` (existing workflow)

### 5. Enable Pull Request Requirements
Check these boxes:
- [x] Require pull request reviews before merging
- [x] Require at least 1 approving review
- [x] Dismiss stale PR approvals when new commits are pushed

### 6. Restrict Pushes
Check these boxes:
- [x] Restrict pushes (Admins + Maintainers only)
- [x] Allow force pushes: UNCHECKED
- [x] Allow deletions: UNCHECKED

### 7. Save Changes
Click "Create" to save the branch protection rule.

## Result
This ensures:
- All PRs must pass Baseline checks before merging
- Code review is required for all changes
- Main branch is protected from direct pushes
- Quality gates are enforced automatically

## After Configuration
Once branch protection is configured, you can push the production binary:
```bash
git push origin main
```

## Alternative: Create Pull Request
If branch protection blocks direct pushes:
1. Create feature branch: `git checkout -b update-production-binary`
2. Push branch: `git push origin update-production-binary`
3. Create PR on GitHub
4. Merge after CI/CD checks pass
