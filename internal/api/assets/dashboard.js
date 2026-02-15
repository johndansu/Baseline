(function () {
  var links = Array.prototype.slice.call(document.querySelectorAll(".sidebar nav a[data-tab]"));
  var panels = {
    overview: document.getElementById("overview"),
    product: document.getElementById("product"),
    workflow: document.getElementById("workflow"),
    next: document.getElementById("next"),
  };
  var clock = document.getElementById("clock");

  function activeFromHash() {
    var key = (window.location.hash || "#overview").slice(1).toLowerCase();
    return panels[key] ? key : "overview";
  }

  function setTab(key) {
    Object.keys(panels).forEach(function (name) {
      panels[name].classList.toggle("active", name === key);
    });
    links.forEach(function (link) {
      link.classList.toggle("active", link.getAttribute("data-tab") === key);
    });
  }

  function tick() {
    if (!clock) return;
    clock.textContent = "Local time: " + new Date().toLocaleString();
  }

  window.addEventListener("hashchange", function () {
    setTab(activeFromHash());
  });

  links.forEach(function (link) {
    link.addEventListener("click", function () {
      setTab(activeFromHash());
    });
  });

  setTab(activeFromHash());
  tick();
  window.setInterval(tick, 1000);
})();
