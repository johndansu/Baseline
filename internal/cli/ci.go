package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	clitrace "github.com/baseline/baseline/internal/cli/trace"
	"github.com/baseline/baseline/internal/types"
)

type ciSetupOptions struct {
	Help     bool
	Provider string
	Mode     string
	Force    bool
}

type ciProviderSpec struct {
	Provider     string
	DisplayName  string
	WorkflowPath string
	Content      string
}

type ciProjectProfile struct {
	Kind            string
	GoVersion       string
	InstallStepName string
	InstallStep     string
	RunCommand      string
	CheckSteps      []ciNamedStep
	Languages       []string
	GitLabPackages  []string
	NeedsDotNet     bool
	Frameworks      []string
}

type ciNamedStep struct {
	Name string
	Run  string
}

type packageJSONManifest struct {
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// HandleCI manages CI workflow scaffolding commands.
func HandleCI(args []string) {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("ci", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runCICommand(traceCtx, args)
	}))
}

func runCICommand(traceCtx *clitrace.Context, args []string) tracedCommandResult {
	if len(args) == 0 {
		printCIUsage()
		return tracedCommandResult{
			ExitCode:     types.ExitSuccess,
			TraceStatus:  "help",
			TraceMessage: "ci usage shown",
		}
	}
	if len(args) == 1 && hasHelpFlag(args) {
		printCIUsage()
		return tracedCommandResult{
			ExitCode:     types.ExitSuccess,
			TraceStatus:  "help",
			TraceMessage: "ci usage shown",
		}
	}

	switch strings.TrimSpace(strings.ToLower(args[0])) {
	case "setup":
		return runCISetupCommand(traceCtx, args[1:])
	default:
		fmt.Printf("CI FAILED: unknown subcommand %s\n\n", args[0])
		printCIUsage()
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "ci subcommand invalid",
		}
	}
}

func runCISetupCommand(traceCtx *clitrace.Context, args []string) tracedCommandResult {
	opts, err := parseCISetupArgs(args)
	if err != nil {
		fmt.Printf("CI SETUP FAILED: %v\n\n", err)
		printCISetupUsage()
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "ci setup arguments invalid",
		}
	}
	if opts.Help {
		printCISetupUsage()
		return tracedCommandResult{
			ExitCode:     types.ExitSuccess,
			TraceStatus:  "help",
			TraceMessage: "ci setup usage shown",
		}
	}

	gitSpan := traceCtx.HelperEnter("cli", "requireGitRepo", "checking git repository", nil)
	if err := requireGitRepo(); err != nil {
		traceCtx.Error("cli", "requireGitRepo", err, nil)
		traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "error", "git repository check failed", nil)
		fmt.Printf("CI SETUP FAILED: %v\n", err)
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "git repository check failed",
		}
	}
	traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "ok", "git repository check passed", nil)

	cwdSpan := traceCtx.HelperEnter("cli", "os.Getwd", "resolving current directory", nil)
	cwd, err := os.Getwd()
	if err != nil {
		traceCtx.Error("cli", "os.Getwd", err, nil)
		traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "error", "current directory resolution failed", nil)
		fmt.Printf("CI SETUP FAILED: Unable to get current directory: %v\n", err)
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "current directory lookup failed",
		}
	}
	traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "ok", "resolved current directory", map[string]string{
		"repository": filepath.Base(cwd),
	})
	traceCtx.SetMetadata("repository", filepath.Base(cwd))

	spec, err := buildCIProviderSpec(opts, cwd)
	if err != nil {
		fmt.Printf("CI SETUP FAILED: %v\n", err)
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "unsupported ci provider",
			Attributes: map[string]string{
				"provider": opts.Provider,
			},
		}
	}

	if _, err := os.Stat(spec.WorkflowPath); err == nil && !opts.Force {
		fmt.Printf("CI SETUP FAILED: %s already exists. Re-run with --force to overwrite it.\n", spec.WorkflowPath)
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "workflow file already exists",
			Attributes: map[string]string{
				"provider":      opts.Provider,
				"workflow_path": spec.WorkflowPath,
			},
		}
	}

	mkdirSpan := traceCtx.HelperEnter("fs", "os.MkdirAll", "creating workflow directory", nil)
	if err := os.MkdirAll(filepath.Dir(spec.WorkflowPath), 0755); err != nil {
		traceCtx.Error("fs", "os.MkdirAll", err, nil)
		traceCtx.HelperExit(mkdirSpan, "fs", "os.MkdirAll", "error", "unable to create workflow directory", nil)
		fmt.Printf("CI SETUP FAILED: Unable to create workflow directory: %v\n", err)
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "unable to create workflow directory",
		}
	}
	traceCtx.HelperExit(mkdirSpan, "fs", "os.MkdirAll", "ok", "workflow directory created", nil)

	writeSpan := traceCtx.HelperEnter("fs", "os.WriteFile", "writing CI workflow file", nil)
	if err := os.WriteFile(spec.WorkflowPath, []byte(spec.Content), 0644); err != nil {
		traceCtx.Error("fs", "os.WriteFile", err, nil)
		traceCtx.HelperExit(writeSpan, "fs", "os.WriteFile", "error", "unable to write workflow file", nil)
		fmt.Printf("CI SETUP FAILED: Unable to write workflow file: %v\n", err)
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "unable to write workflow file",
		}
	}
	traceCtx.HelperExit(writeSpan, "fs", "os.WriteFile", "ok", "workflow file written", nil)

	fmt.Printf("Created %s workflow: %s\n", spec.DisplayName, spec.WorkflowPath)
	fmt.Printf("Baseline will run `%s` in %s.\n", "baseline "+opts.Mode, spec.DisplayName)
	fmt.Printf("Review and commit the workflow file to activate CI enforcement.\n")

	return tracedCommandResult{
		ExitCode:     types.ExitSuccess,
		TraceStatus:  "ok",
		TraceMessage: "ci workflow scaffolded",
		Attributes: map[string]string{
			"repository":    filepath.Base(cwd),
			"provider":      opts.Provider,
			"mode":          opts.Mode,
			"workflow_path": spec.WorkflowPath,
		},
	}
}

func parseCISetupArgs(args []string) (ciSetupOptions, error) {
	opts := ciSetupOptions{
		Provider: "github",
		Mode:     "enforce",
	}
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		switch arg {
		case "--help", "-h":
			opts.Help = true
		case "--force":
			opts.Force = true
		case "--provider":
			i++
			if i >= len(args) {
				return opts, fmt.Errorf("missing value for --provider")
			}
			opts.Provider = strings.ToLower(strings.TrimSpace(args[i]))
		case "--mode":
			i++
			if i >= len(args) {
				return opts, fmt.Errorf("missing value for --mode")
			}
			opts.Mode = strings.ToLower(strings.TrimSpace(args[i]))
		default:
			return opts, fmt.Errorf("unknown flag %s", arg)
		}
	}

	if opts.Provider == "" {
		return opts, fmt.Errorf("provider must not be empty")
	}
	opts.Provider = normalizeCIProvider(opts.Provider)
	if opts.Provider == "" {
		return opts, fmt.Errorf("unsupported provider (expected github, gitlab, or azure)")
	}
	switch opts.Mode {
	case "enforce", "check":
	default:
		return opts, fmt.Errorf("unsupported mode %q (expected enforce or check)", opts.Mode)
	}
	return opts, nil
}

func normalizeCIProvider(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "github", "github-actions", "gha":
		return "github"
	case "gitlab", "gitlab-ci":
		return "gitlab"
	case "azure", "azure-devops", "ado":
		return "azure"
	default:
		return ""
	}
}

func detectCIProjectProfile(cwd string) ciProjectProfile {
	profile := ciProjectProfile{
		Kind:            "generic",
		GoVersion:       "1.26.1",
		InstallStepName: "Install Baseline CLI",
		InstallStep:     "go install github.com/baseline/baseline/cmd/baseline@latest",
		RunCommand:      "baseline",
	}

	goModPath := filepath.Join(cwd, "go.mod")
	cmdMainPath := filepath.Join(cwd, "cmd", "baseline", "main.go")
	if _, err := os.Stat(goModPath); err == nil {
		if _, err := os.Stat(cmdMainPath); err == nil {
			if content, err := os.ReadFile(goModPath); err == nil && strings.Contains(string(content), "module github.com/baseline/baseline") {
				profile.Kind = "baseline_source"
				profile.GoVersion = "go.mod"
				profile.InstallStepName = "Build Baseline CLI"
				profile.InstallStep = "go build -o baseline ./cmd/baseline"
				profile.RunCommand = "./baseline"
			}
		}
	}

	profile.CheckSteps, profile.Languages, profile.GitLabPackages, profile.NeedsDotNet, profile.Frameworks = detectCIProjectChecks(cwd)

	return profile
}

func detectCIProjectChecks(cwd string) ([]ciNamedStep, []string, []string, bool, []string) {
	var steps []ciNamedStep
	var languages []string
	var frameworks []string
	pkgSet := map[string]struct{}{}
	langSet := map[string]struct{}{}
	frameworkSet := map[string]struct{}{}
	needsDotNet := false

	addLanguage := func(language string) {
		if _, exists := langSet[language]; exists {
			return
		}
		langSet[language] = struct{}{}
		languages = append(languages, language)
	}
	addPackages := func(packages ...string) {
		for _, pkg := range packages {
			if strings.TrimSpace(pkg) == "" {
				continue
			}
			pkgSet[pkg] = struct{}{}
		}
	}
	addFramework := func(framework string) {
		if _, exists := frameworkSet[framework]; exists {
			return
		}
		frameworkSet[framework] = struct{}{}
		frameworks = append(frameworks, framework)
	}
	has := func(path string) bool {
		_, err := os.Stat(filepath.Join(cwd, path))
		return err == nil
	}
	hasAnyGlob := func(pattern string) bool {
		matches, err := filepath.Glob(filepath.Join(cwd, pattern))
		return err == nil && len(matches) > 0
	}

	if has("go.mod") {
		addLanguage("go")
		steps = append(steps, ciNamedStep{Name: "Run Go tests", Run: "go test ./..."})
	}
	if has("package.json") {
		addLanguage("node")
		addPackages("nodejs", "npm")
		manifest := loadPackageJSONManifest(filepath.Join(cwd, "package.json"))
		frameworkSteps, detectedFrameworks := detectNodeFrameworkSteps(manifest, has("package-lock.json"), has("yarn.lock"), has("pnpm-lock.yaml"))
		for _, framework := range detectedFrameworks {
			addFramework(framework)
		}
		if len(frameworkSteps) > 0 {
			steps = append(steps, frameworkSteps...)
		} else {
			switch {
			case has("pnpm-lock.yaml"):
				steps = append(steps,
					ciNamedStep{Name: "Install Node dependencies", Run: "corepack enable && pnpm install --frozen-lockfile"},
					ciNamedStep{Name: "Run Node tests", Run: "pnpm test"},
				)
			case has("yarn.lock"):
				steps = append(steps,
					ciNamedStep{Name: "Install Node dependencies", Run: "corepack enable && yarn install --frozen-lockfile"},
					ciNamedStep{Name: "Run Node tests", Run: "yarn test"},
				)
			case has("package-lock.json"):
				steps = append(steps,
					ciNamedStep{Name: "Install Node dependencies", Run: "npm ci"},
					ciNamedStep{Name: "Run Node tests", Run: "npm test"},
				)
			default:
				steps = append(steps,
					ciNamedStep{Name: "Install Node dependencies", Run: "npm install"},
					ciNamedStep{Name: "Run Node tests", Run: "npm test"},
				)
			}
		}
	}
	if has("requirements.txt") || has("pyproject.toml") || has("Pipfile") || has("Pipfile.lock") || has("poetry.lock") {
		addLanguage("python")
		addPackages("python3", "python3-pip", "python3-venv")
		switch {
		case has("poetry.lock"):
			steps = append(steps,
				ciNamedStep{Name: "Install Poetry", Run: "python -m pip install poetry"},
				ciNamedStep{Name: "Install Python dependencies", Run: "poetry install"},
				ciNamedStep{Name: "Run Python tests", Run: "poetry run pytest"},
			)
		case has("Pipfile") || has("Pipfile.lock"):
			steps = append(steps,
				ciNamedStep{Name: "Install Pipenv", Run: "python -m pip install pipenv"},
				ciNamedStep{Name: "Install Python dependencies", Run: "pipenv install --dev"},
				ciNamedStep{Name: "Run Python tests", Run: "pipenv run pytest"},
			)
		case has("requirements.txt"):
			steps = append(steps,
				ciNamedStep{Name: "Install Python dependencies", Run: "python -m pip install -r requirements.txt pytest"},
				ciNamedStep{Name: "Run Python tests", Run: "pytest"},
			)
		default:
			steps = append(steps,
				ciNamedStep{Name: "Install Python dependencies", Run: "python -m pip install . pytest"},
				ciNamedStep{Name: "Run Python tests", Run: "pytest"},
			)
		}
	}
	if has("pom.xml") {
		addLanguage("java")
		addPackages("openjdk-21-jdk", "maven")
		steps = append(steps, ciNamedStep{Name: "Run Maven tests", Run: "mvn -B test"})
	} else if has("build.gradle") || has("build.gradle.kts") {
		addLanguage("java")
		addPackages("openjdk-21-jdk", "gradle")
		if has("gradlew") {
			steps = append(steps, ciNamedStep{Name: "Run Gradle tests", Run: "chmod +x ./gradlew && ./gradlew test"})
		} else {
			steps = append(steps, ciNamedStep{Name: "Run Gradle tests", Run: "gradle test"})
		}
	}
	if has("Cargo.toml") || has("cargo.toml") {
		addLanguage("rust")
		addPackages("rustc", "cargo")
		steps = append(steps, ciNamedStep{Name: "Run Rust tests", Run: "cargo test"})
	}
	if hasAnyGlob("*.csproj") || hasAnyGlob("*.sln") {
		addLanguage("dotnet")
		needsDotNet = true
		steps = append(steps, ciNamedStep{Name: "Run .NET tests", Run: "dotnet test"})
	}
	if has("Gemfile") {
		addLanguage("ruby")
		addPackages("ruby-full", "build-essential")
		steps = append(steps,
			ciNamedStep{Name: "Install Ruby dependencies", Run: "bundle install"},
			ciNamedStep{Name: "Run Ruby tests", Run: "bundle exec rspec"},
		)
	}
	if has("composer.json") {
		addLanguage("php")
		addPackages("php-cli", "composer")
		steps = append(steps,
			ciNamedStep{Name: "Install PHP dependencies", Run: "composer install --no-interaction --prefer-dist"},
			ciNamedStep{Name: "Run PHP tests", Run: "vendor/bin/phpunit"},
		)
	}

	var packages []string
	for pkg := range pkgSet {
		packages = append(packages, pkg)
	}
	return steps, languages, packages, needsDotNet, frameworks
}

func loadPackageJSONManifest(path string) packageJSONManifest {
	var manifest packageJSONManifest
	content, err := os.ReadFile(path)
	if err != nil {
		return manifest
	}
	_ = json.Unmarshal(content, &manifest)
	if manifest.Scripts == nil {
		manifest.Scripts = map[string]string{}
	}
	if manifest.Dependencies == nil {
		manifest.Dependencies = map[string]string{}
	}
	if manifest.DevDependencies == nil {
		manifest.DevDependencies = map[string]string{}
	}
	return manifest
}

func detectNodeFrameworkSteps(manifest packageJSONManifest, hasNPM, hasYarn, hasPNPM bool) ([]ciNamedStep, []string) {
	var steps []ciNamedStep
	var frameworks []string
	hasDep := func(name string) bool {
		_, ok := manifest.Dependencies[name]
		if ok {
			return true
		}
		_, ok = manifest.DevDependencies[name]
		return ok
	}
	addFramework := func(name string) {
		for _, existing := range frameworks {
			if existing == name {
				return
			}
		}
		frameworks = append(frameworks, name)
	}
	addScriptStep := func(scriptName, label string) {
		if _, ok := manifest.Scripts[scriptName]; ok {
			steps = append(steps, ciNamedStep{Name: label, Run: nodePackageScriptCommand(scriptName, hasNPM, hasYarn, hasPNPM)})
		}
	}

	installCommand := "npm install"
	switch {
	case hasPNPM:
		installCommand = "corepack enable && pnpm install --frozen-lockfile"
	case hasYarn:
		installCommand = "corepack enable && yarn install --frozen-lockfile"
	case hasNPM:
		installCommand = "npm ci"
	}
	steps = append(steps, ciNamedStep{Name: "Install Node dependencies", Run: installCommand})

	switch {
	case hasDep("next"):
		addFramework("nextjs")
		addScriptStep("lint", "Run Next.js lint")
		addScriptStep("typecheck", "Run Next.js typecheck")
		addScriptStep("build", "Build Next.js app")
		addScriptStep("test", "Run Next.js tests")
	case hasDep("@nestjs/core"):
		addFramework("nestjs")
		addScriptStep("lint", "Run NestJS lint")
		addScriptStep("build", "Build NestJS app")
		addScriptStep("test", "Run NestJS tests")
	case hasDep("@angular/core"):
		addFramework("angular")
		addScriptStep("lint", "Run Angular lint")
		addScriptStep("build", "Build Angular app")
		addScriptStep("test", "Run Angular tests")
	case hasDep("nuxt"):
		addFramework("nuxt")
		addScriptStep("lint", "Run Nuxt lint")
		addScriptStep("build", "Build Nuxt app")
		addScriptStep("test", "Run Nuxt tests")
	case hasDep("@sveltejs/kit"):
		addFramework("sveltekit")
		addScriptStep("lint", "Run SvelteKit lint")
		addScriptStep("check", "Run SvelteKit check")
		addScriptStep("build", "Build SvelteKit app")
		addScriptStep("test", "Run SvelteKit tests")
	case hasDep("@remix-run/react"):
		addFramework("remix")
		addScriptStep("lint", "Run Remix lint")
		addScriptStep("typecheck", "Run Remix typecheck")
		addScriptStep("build", "Build Remix app")
		addScriptStep("test", "Run Remix tests")
	case hasDep("astro"):
		addFramework("astro")
		addScriptStep("lint", "Run Astro lint")
		addScriptStep("build", "Build Astro app")
		addScriptStep("test", "Run Astro tests")
	case hasDep("vite"):
		addFramework("vite")
		addScriptStep("lint", "Run Vite lint")
		addScriptStep("typecheck", "Run Vite typecheck")
		addScriptStep("build", "Build Vite app")
		addScriptStep("test", "Run Vite tests")
	case hasDep("react") || hasDep("react-dom"):
		addFramework("react")
		addScriptStep("lint", "Run React lint")
		addScriptStep("typecheck", "Run React typecheck")
		addScriptStep("build", "Build React app")
		addScriptStep("test", "Run React tests")
	case hasDep("vue"):
		addFramework("vue")
		addScriptStep("lint", "Run Vue lint")
		addScriptStep("typecheck", "Run Vue typecheck")
		addScriptStep("build", "Build Vue app")
		addScriptStep("test", "Run Vue tests")
	default:
		addScriptStep("test", "Run Node tests")
	}

	if len(steps) == 1 {
		addScriptStep("test", "Run Node tests")
	}

	return steps, frameworks
}

func nodePackageScriptCommand(scriptName string, hasNPM, hasYarn, hasPNPM bool) string {
	switch {
	case hasPNPM:
		return "pnpm " + scriptName
	case hasYarn:
		return "yarn " + scriptName
	default:
		return "npm run " + scriptName
	}
}

func buildCIProviderSpec(opts ciSetupOptions, cwd string) (ciProviderSpec, error) {
	profile := detectCIProjectProfile(cwd)
	command := profile.RunCommand + " " + opts.Mode
	switch opts.Provider {
	case "github":
		return ciProviderSpec{
			Provider:     "github",
			DisplayName:  "GitHub Actions",
			WorkflowPath: filepath.Join(".github", "workflows", "baseline.yml"),
			Content:      renderGitHubActionsWorkflow(command, profile),
		}, nil
	case "gitlab":
		return ciProviderSpec{
			Provider:     "gitlab",
			DisplayName:  "GitLab CI",
			WorkflowPath: ".gitlab-ci.yml",
			Content:      renderGitLabCIWorkflow(command, profile),
		}, nil
	case "azure":
		return ciProviderSpec{
			Provider:     "azure",
			DisplayName:  "Azure Pipelines",
			WorkflowPath: "azure-pipelines.yml",
			Content:      renderAzurePipelineWorkflow(command, profile),
		}, nil
	default:
		return ciProviderSpec{}, fmt.Errorf("unsupported provider %q", opts.Provider)
	}
}

func renderGitHubActionsWorkflow(command string, profile ciProjectProfile) string {
	goSetup := "          go-version: '1.26.1'"
	if profile.GoVersion == "go.mod" {
		goSetup = "          go-version-file: go.mod"
	}
	var builder strings.Builder
	builder.WriteString("name: Baseline\n\n")
	builder.WriteString("on:\n  pull_request:\n  push:\n    branches:\n      - main\n\njobs:\n  baseline:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps:\n")
	builder.WriteString("      - name: Check out repository\n        uses: actions/checkout@v4\n\n")
	builder.WriteString("      - name: Set up Go\n        uses: actions/setup-go@v5\n        with:\n")
	builder.WriteString(goSetup + "\n\n")
	builder.WriteString(renderGitHubLanguageSetup(profile))
	builder.WriteString(fmt.Sprintf("      - name: %s\n        run: %s\n\n", profile.InstallStepName, profile.InstallStep))
	builder.WriteString(renderGitHubProjectChecks(profile))
	builder.WriteString(fmt.Sprintf("      - name: Run Baseline\n        run: %s\n", command))
	return builder.String()
}

func renderGitLabCIWorkflow(command string, profile ciProjectProfile) string {
	var builder strings.Builder
	builder.WriteString("stages:\n  - baseline\n\n")
	builder.WriteString("baseline:\n  stage: baseline\n  image: golang:1.26\n  rules:\n    - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n")
	beforeScript := renderGitLabBeforeScript(profile)
	if beforeScript != "" {
		builder.WriteString("  before_script:\n")
		builder.WriteString(beforeScript)
	}
	builder.WriteString("  script:\n")
	builder.WriteString(fmt.Sprintf("    - %s\n", profile.InstallStep))
	for _, step := range profile.CheckSteps {
		builder.WriteString(fmt.Sprintf("    - %s\n", step.Run))
	}
	builder.WriteString(fmt.Sprintf("    - %s\n", command))
	return builder.String()
}

func renderAzurePipelineWorkflow(command string, profile ciProjectProfile) string {
	goVersion := "1.26.1"
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf(`trigger:
  branches:
    include:
      - main

pr:
  branches:
    include:
      - main

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self

  - task: GoTool@0
    inputs:
      version: '%s'

`, goVersion))
	builder.WriteString(renderAzureLanguageSetup(profile))
	builder.WriteString(fmt.Sprintf("  - script: %s\n    displayName: %s\n\n", profile.InstallStep, profile.InstallStepName))
	for _, step := range profile.CheckSteps {
		builder.WriteString(fmt.Sprintf("  - script: %s\n    displayName: %s\n\n", step.Run, step.Name))
	}
	builder.WriteString(fmt.Sprintf("  - script: %s\n    displayName: Run Baseline\n", command))
	return builder.String()
}

func renderGitHubLanguageSetup(profile ciProjectProfile) string {
	var builder strings.Builder
	for _, language := range profile.Languages {
		switch language {
		case "node":
			builder.WriteString("      - name: Set up Node.js\n        uses: actions/setup-node@v4\n        with:\n          node-version: '22'\n\n")
		case "python":
			builder.WriteString("      - name: Set up Python\n        uses: actions/setup-python@v5\n        with:\n          python-version: '3.12'\n\n")
		case "java":
			builder.WriteString("      - name: Set up Java\n        uses: actions/setup-java@v4\n        with:\n          distribution: temurin\n          java-version: '21'\n\n")
		case "dotnet":
			builder.WriteString("      - name: Set up .NET\n        uses: actions/setup-dotnet@v4\n        with:\n          dotnet-version: '8.0.x'\n\n")
		case "ruby":
			builder.WriteString("      - name: Set up Ruby\n        uses: ruby/setup-ruby@v1\n        with:\n          ruby-version: '3.3'\n\n")
		case "php":
			builder.WriteString("      - name: Set up PHP\n        uses: shivammathur/setup-php@v2\n        with:\n          php-version: '8.3'\n          tools: composer\n\n")
		case "rust":
			builder.WriteString("      - name: Set up Rust\n        uses: dtolnay/rust-toolchain@stable\n\n")
		}
	}
	return builder.String()
}

func renderGitHubProjectChecks(profile ciProjectProfile) string {
	var builder strings.Builder
	for _, step := range profile.CheckSteps {
		builder.WriteString(fmt.Sprintf("      - name: %s\n        run: %s\n\n", step.Name, step.Run))
	}
	return builder.String()
}

func renderGitLabBeforeScript(profile ciProjectProfile) string {
	var builder strings.Builder
	if len(profile.GitLabPackages) > 0 {
		builder.WriteString(fmt.Sprintf("    - apt-get update && apt-get install -y %s\n", strings.Join(profile.GitLabPackages, " ")))
	}
	if profile.NeedsDotNet {
		builder.WriteString("    - curl -fsSL https://dot.net/v1/dotnet-install.sh -o dotnet-install.sh\n")
		builder.WriteString("    - bash dotnet-install.sh --channel 8.0\n")
		builder.WriteString("    - export PATH=\"$PATH:$HOME/.dotnet\"\n")
	}
	return builder.String()
}

func renderAzureLanguageSetup(profile ciProjectProfile) string {
	var builder strings.Builder
	for _, language := range profile.Languages {
		switch language {
		case "node":
			builder.WriteString("  - task: NodeTool@0\n    inputs:\n      versionSpec: '22.x'\n\n")
		case "python":
			builder.WriteString("  - task: UsePythonVersion@0\n    inputs:\n      versionSpec: '3.12'\n\n")
		case "java":
			builder.WriteString("  - task: JavaToolInstaller@0\n    inputs:\n      versionSpec: '21'\n      jdkArchitectureOption: x64\n      jdkSourceOption: PreInstalled\n\n")
		case "dotnet":
			builder.WriteString("  - task: UseDotNet@2\n    inputs:\n      packageType: sdk\n      version: '8.0.x'\n\n")
		case "ruby":
			builder.WriteString("  - script: ruby --version\n    displayName: Verify Ruby runtime\n\n")
		case "php":
			builder.WriteString("  - script: php --version && composer --version\n    displayName: Verify PHP runtime\n\n")
		case "rust":
			builder.WriteString("  - script: rustup default stable || true\n    displayName: Prepare Rust toolchain\n\n")
		}
	}
	return builder.String()
}

func printCIUsage() {
	fmt.Println("Usage: baseline ci <subcommand>")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  setup   Generate CI workflow scaffolding")
}

func printCISetupUsage() {
	fmt.Println("Usage: baseline ci setup [--provider github|gitlab|azure] [--mode enforce|check] [--force]")
	fmt.Println()
	fmt.Println("Creates a CI workflow file for the selected provider.")
	fmt.Println("Default mode is `enforce`, which blocks the pipeline on violations.")
}
