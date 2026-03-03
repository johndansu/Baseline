(function () {
  function initDashboardTabs() {
    var links = Array.prototype.slice.call(document.querySelectorAll(".menu a[data-tab]"));
    if (!links.length) return;

    var tabs = {
      overview: document.getElementById("overview"),
      product: document.getElementById("product"),
      workflow: document.getElementById("workflow"),
      access: document.getElementById("access"),
    };
    var clock = document.getElementById("clock");

    function firstTab() {
      var names = Object.keys(tabs).filter(function (name) {
        return !!tabs[name];
      });
      return names.length ? names[0] : null;
    }

    function currentTab() {
      var fallback = firstTab();
      if (!fallback) return null;
      var key = (window.location.hash || ("#" + fallback)).slice(1).toLowerCase();
      return tabs[key] ? key : fallback;
    }

    function activate(key) {
      if (!key) return;
      Object.keys(tabs).forEach(function (name) {
        if (tabs[name]) {
          tabs[name].classList.toggle("active", name === key);
        }
      });
      links.forEach(function (link) {
        link.classList.toggle("active", link.getAttribute("data-tab") === key);
      });
    }

    function updateClock() {
      if (!clock) return;
      clock.textContent = "Local preview time: " + new Date().toLocaleString();
    }

    window.addEventListener("hashchange", function () {
      activate(currentTab());
    });

    links.forEach(function (link) {
      link.addEventListener("click", function () {
        activate(currentTab());
      });
    });

    activate(currentTab());
    updateClock();
    window.setInterval(updateClock, 1000);
  }

  function formatCounter(value, mode, decimals) {
    if (mode === "kplus") {
      return Math.max(0, Math.round(value / 1000)) + "K+";
    }
    if (mode === "plus") {
      return Math.max(0, Math.round(value)) + "+";
    }
    if (mode === "percent") {
      return Math.max(0, value).toFixed(decimals) + "%";
    }
    return String(Math.max(0, Math.round(value)));
  }

  function animateCounter(el) {
    var finalText = el.textContent.trim();
    var mode = "number";
    if (finalText.indexOf("K+") >= 0) mode = "kplus";
    else if (finalText.indexOf("%") >= 0) mode = "percent";
    else if (finalText.indexOf("+") >= 0) mode = "plus";

    var target = Number(el.getAttribute("data-target"));
    if (!Number.isFinite(target)) {
      var parsed = Number(finalText.replace(/[^0-9.]/g, ""));
      target = Number.isFinite(parsed) ? parsed : 0;
    }
    if (mode === "percent") {
      var percentTarget = Number(finalText.replace(/[^0-9.]/g, ""));
      if (Number.isFinite(percentTarget)) target = percentTarget;
    }

    var decimals = 0;
    if (mode === "percent") {
      var decimalPart = finalText.split(".")[1] || "";
      decimals = decimalPart.replace(/[^0-9]/g, "").length > 0 ? 1 : 0;
    }

    var durationMs = 1200;
    var start = null;

    function step(ts) {
      if (start === null) start = ts;
      var progress = Math.min((ts - start) / durationMs, 1);
      var eased = 1 - Math.pow(1 - progress, 3);
      var value = target * eased;
      el.textContent = formatCounter(value, mode, decimals);

      if (progress < 1) {
        window.requestAnimationFrame(step);
      } else {
        el.textContent = finalText;
      }
    }

    window.requestAnimationFrame(step);
  }

  function initLandingPage() {
    var counters = Array.prototype.slice.call(document.querySelectorAll(".stat-number"));
    var revealTargets = Array.prototype.slice.call(
      document.querySelectorAll(
        ".section-shell, .reveal-card, .diff-column, .metric-card, .principle-card, .testimonial-card, .features-grid .card, .workflow-steps .step, .cta-section"
      )
    );

    if (revealTargets.length) {
      revealTargets.forEach(function (el, index) {
        el.classList.add("reveal");
        el.style.transitionDelay = Math.min(index * 45, 260) + "ms";
      });
    }

    if (window.IntersectionObserver) {
      var revealObserver = new IntersectionObserver(
        function (entries, observer) {
          entries.forEach(function (entry) {
            if (entry.isIntersecting) {
              entry.target.classList.add("is-visible");
              observer.unobserve(entry.target);
            }
          });
        },
        { threshold: 0.14, rootMargin: "0px 0px -30px 0px" }
      );

      revealTargets.forEach(function (el) {
        revealObserver.observe(el);
      });

      if (counters.length) {
        var counterObserver = new IntersectionObserver(
          function (entries, observer) {
            entries.forEach(function (entry) {
              if (entry.isIntersecting) {
                animateCounter(entry.target);
                observer.unobserve(entry.target);
              }
            });
          },
          { threshold: 0.4 }
        );

        counters.forEach(function (counter) {
          counterObserver.observe(counter);
        });
      }
      return;
    }

    revealTargets.forEach(function (el) {
      el.classList.add("is-visible");
    });
    counters.forEach(animateCounter);
  }

  function initExperienceEnhancements() {
    var progressBar = document.getElementById("scrollProgress");
    if (progressBar) {
      var updateProgress = function () {
        var scrollTop = window.scrollY || window.pageYOffset || 0;
        var maxScroll = Math.max(
          (document.documentElement.scrollHeight || 0) - window.innerHeight,
          1
        );
        var progress = Math.min((scrollTop / maxScroll) * 100, 100);
        progressBar.style.width = progress + "%";
      };

      updateProgress();
      window.addEventListener("scroll", updateProgress, { passive: true });
      window.addEventListener("resize", updateProgress);
    }

    var consoleRows = Array.prototype.slice.call(document.querySelectorAll(".console-row"));
    if (consoleRows.length) {
      consoleRows.forEach(function (row, index) {
        window.setTimeout(function () {
          row.classList.add("is-live");
        }, 220 + index * 170);
      });
    }

    var magnetic = document.querySelector(".magnetic");
    var motionOk = window.matchMedia && window.matchMedia("(prefers-reduced-motion: no-preference)").matches;
    if (magnetic && motionOk) {
      magnetic.addEventListener("pointermove", function (event) {
        var rect = magnetic.getBoundingClientRect();
        var x = event.clientX - rect.left;
        var y = event.clientY - rect.top;
        var rx = ((y / rect.height) - 0.5) * -6;
        var ry = ((x / rect.width) - 0.5) * 8;
        magnetic.style.transform = "perspective(900px) rotateX(" + rx.toFixed(2) + "deg) rotateY(" + ry.toFixed(2) + "deg)";
      });
      magnetic.addEventListener("pointerleave", function () {
        magnetic.style.transform = "";
      });
    }

    var simButtons = Array.prototype.slice.call(document.querySelectorAll(".sim-btn[data-scene]"));
    var scenePanels = Array.prototype.slice.call(document.querySelectorAll(".scene-panel[data-scene]"));

    if (simButtons.length && scenePanels.length) {
      var activeScene = simButtons[0].getAttribute("data-scene");
      var rotationTimer = null;

      var activateScene = function (scene) {
        activeScene = scene;
        simButtons.forEach(function (button) {
          var active = button.getAttribute("data-scene") === scene;
          button.classList.toggle("active", active);
          button.setAttribute("aria-selected", active ? "true" : "false");
        });
        scenePanels.forEach(function (panel) {
          panel.classList.toggle("active", panel.getAttribute("data-scene") === scene);
        });
      };

      var scheduleRotation = function () {
        if (rotationTimer) window.clearInterval(rotationTimer);
        rotationTimer = window.setInterval(function () {
          if (document.hidden) return;
          var currentIndex = simButtons.findIndex(function (button) {
            return button.getAttribute("data-scene") === activeScene;
          });
          var nextIndex = (currentIndex + 1) % simButtons.length;
          activateScene(simButtons[nextIndex].getAttribute("data-scene"));
        }, 5600);
      };

      simButtons.forEach(function (button) {
        button.addEventListener("click", function () {
          activateScene(button.getAttribute("data-scene"));
          scheduleRotation();
        });
      });

      activateScene(activeScene);
      scheduleRotation();
    }

    var navLinks = Array.prototype.slice.call(document.querySelectorAll(".landing-nav a[href^=\"#\"]"));
    navLinks.forEach(function (link) {
      link.addEventListener("click", function (event) {
        var href = link.getAttribute("href");
        if (!href || href.length < 2) return;
        var target = document.getElementById(href.slice(1));
        if (!target) return;
        event.preventDefault();
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });
  }

  function formatCurrency(value) {
    return "$" + Math.round(value).toLocaleString();
  }

  function initRoiEstimator() {
    var team = document.getElementById("roiTeamSize");
    var incidents = document.getElementById("roiIncidents");
    var downtime = document.getElementById("roiDowntime");
    if (!team || !incidents || !downtime) return;

    var teamValue = document.getElementById("roiTeamSizeValue");
    var incidentsValue = document.getElementById("roiIncidentsValue");
    var downtimeValue = document.getElementById("roiDowntimeValue");
    var monthlyValue = document.getElementById("roiMonthly");
    var yearlyValue = document.getElementById("roiYearly");
    var summary = document.getElementById("roiSummary");

    var update = function () {
      var teamSize = Number(team.value) || 0;
      var incidentCount = Number(incidents.value) || 0;
      var downtimeHours = Number(downtime.value) || 0;

      if (teamValue) teamValue.textContent = String(teamSize);
      if (incidentsValue) incidentsValue.textContent = String(incidentCount);
      if (downtimeValue) downtimeValue.textContent = String(downtimeHours);

      // Anchored assumptions:
      // - Uptime Institute 2024: 54% of outages > $100k and 16% > $1M.
      // - BLS (May 2022): software developer annual wage benchmark: $132,930.
      var softwareDevAnnualWage = 132930;
      var loadedLaborMultiplier = 1.35;
      var loadedHourlyRate = (softwareDevAnnualWage / 2080) * loadedLaborMultiplier;

      var responseTeamSize = Math.min(14, Math.max(2, Math.round(teamSize * 0.08)));
      var laborCost = incidentCount * downtimeHours * responseTeamSize * loadedHourlyRate;

      var weightedSignificantIncidentCost =
        (0.46 * 50000) +  // representative cost when outage is below $100k
        (0.38 * 300000) + // representative cost in the $100k-$1M band
        (0.16 * 1200000); // representative cost when outage exceeds $1M

      var organizationScale = Math.min(2.2, Math.max(0.4, teamSize / 80));
      var durationScale = Math.min(3.0, Math.max(0.5, downtimeHours / 2));
      var outageCost = incidentCount * weightedSignificantIncidentCost * organizationScale * durationScale;

      var preventableShare = 0.80;
      var realizationFactor = 0.55;
      var projectedReduction = preventableShare * realizationFactor;

      var monthlyRiskCost = outageCost + laborCost;
      var monthlySavings = monthlyRiskCost * projectedReduction;
      var annualSavings = monthlySavings * 12;

      if (monthlyValue) monthlyValue.textContent = formatCurrency(monthlySavings) + " / month";
      if (yearlyValue) yearlyValue.textContent = formatCurrency(annualSavings) + " / year";
      if (summary) {
        if (incidentCount === 0) {
          summary.textContent = "No significant incidents selected. Increase the incident slider to estimate risk-reduction value.";
        } else {
          summary.textContent =
            "Estimated from " +
            incidentCount +
            " significant incidents/month, " +
            downtimeHours +
            "h average incident duration, and a response team of ~" +
            responseTeamSize +
            " engineers per incident.";
        }
      }
    };

    [team, incidents, downtime].forEach(function (input) {
      input.addEventListener("input", update);
      input.addEventListener("change", update);
    });

    update();
  }

  initDashboardTabs();
  initLandingPage();
  initExperienceEnhancements();
  initRoiEstimator();
})();
