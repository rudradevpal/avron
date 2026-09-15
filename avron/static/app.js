/* PII Gateway console. No framework, no external requests. */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const app = $("#app");
const modalRoot = $("#modal-root");

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );

let toastTimer;
function toast(message, bad) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.toggle("err", !!bad);
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 3400);
}

async function api(path, options = {}) {
  const res = await fetch("/api" + path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  if (res.status === 401) {
    state.user = null;
    renderLogin();
    throw new Error("Session expired");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || data.error || "Request failed");
  return data;
}

const state = { user: null, view: "overview", cache: {}, timer: null, gen: 0 };

/* Table helper. Every cell carries its column label so the CSS can turn
   rows into cards on a phone instead of a sideways-scrolling mess. */
function table(cols, rows, emptyText) {
  if (!rows.length) return `<div class="empty">${esc(emptyText || "Nothing here yet.")}</div>`;
  const head = cols
    .map((c) => `<th class="${c.num ? "num" : ""}">${esc(c.label)}</th>`)
    .join("");
  const body = rows
    .map(
      (r) =>
        "<tr>" +
        cols
          .map(
            (c) =>
              `<td class="${c.num ? "num" : ""}" data-label="${esc(c.label)}">${c.cell(r)}</td>`
          )
          .join("") +
        "</tr>"
    )
    .join("");
  return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

const pill = (kind, text) =>
  `<span class="pill ${kind}"><span class="bullet"></span>${esc(text)}</span>`;

/* ================================================================ login */
function renderLogin(message) {
  clearInterval(state.timer);
  app.replaceChildren($("#tpl-login").content.cloneNode(true));
  if (message) $("#login-error").innerHTML = `<div class="notice bad">${esc(message)}</div>`;
  $("#login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = new FormData(e.target);
    try {
      await api("/login", {
        method: "POST",
        body: { username: form.get("username"), password: form.get("password") },
      });
      await boot();
    } catch (err) {
      $("#login-error").innerHTML = `<div class="notice bad">${esc(err.message)}</div>`;
    }
  });
}

/* ================================================================ shell */
const VIEWS = [
  ["Traffic", [["overview", "Overview"], ["routes", "Endpoints"], ["playground", "Playground"], ["analytics", "Analytics"]]],
  ["Detection", [["detection", "Entities"], ["patterns", "Patterns"], ["test", "Scan text"]]],
  ["Setup", [["llm", "Detection model"], ["network", "Egress"], ["users", "Users"], ["activity", "Audit log"]]],
  ["You", [["keys", "API keys"], ["account", "Your account"]]],
];

// Everything outside the "You" group changes shared configuration.
const ADMIN_ONLY = new Set(
  VIEWS.filter(([g]) => g !== "You").flatMap(([, items]) => items.map(([id]) => id))
);
const isAdmin = () => state.user?.role === "admin";
const FLAT = VIEWS.flatMap(([, items]) => items);

function renderShell() {
  app.replaceChildren($("#tpl-shell").content.cloneNode(true));
  const nav = $("#nav");
  VIEWS.forEach(([group, items]) => {
    const visible = items.filter(([id]) => isAdmin() || !ADMIN_ONLY.has(id));
    if (!visible.length) return;
    const g = document.createElement("div");
    g.className = "group";
    g.textContent = group;
    nav.appendChild(g);
    visible.forEach(([id, label]) => {
      const b = document.createElement("button");
      b.textContent = label;
      b.dataset.view = id;
      b.addEventListener("click", () => {
        $("#sidebar").classList.remove("open");
        go(id);
      });
      nav.appendChild(b);
    });
  });
  $("#who").innerHTML =
    esc(state.user.username) +
    (isAdmin() ? ' <span class="tag">admin</span>' : "");
  $("#who-mobile").textContent = state.user.username;
  $("#menu-btn").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
  $("#signout").addEventListener("click", async () => {
    await api("/logout", { method: "POST" });
    state.user = null;
    renderLogin("You have signed out.");
  });
  if (ADMIN_ONLY.has(state.view) && !isAdmin()) state.view = "keys";
  go(state.view);
}

function go(view) {
  clearInterval(state.timer);
  state.view = view;
  // Each render gets a ticket. A slow view that resolves after you have moved
  // on must not paint over whatever is on screen now.
  const ticket = ++state.gen;
  $$("#nav button").forEach((b) => b.setAttribute("aria-current", String(b.dataset.view === view)));

  // Swap in a fresh container. A slow view that finishes after you have moved
  // on then paints into a detached node nobody can see, instead of over the
  // screen you are looking at.
  const el = document.createElement("main");
  el.className = "main";
  el.id = "view";
  $("#view").replaceWith(el);
  el.innerHTML = `<div class="panel"><div class="skeleton"><i></i><i></i><i></i><i></i></div></div>`;
  const VIEW_FN = {
    overview: viewOverview,
    routes: viewRoutes,
    playground: viewPlayground,
    analytics: viewAnalytics,
    detection: viewDetection,
    patterns: viewPatterns,
    test: viewTest,
    llm: viewLlm,
    network: viewNetwork,
    keys: viewKeys,
    users: viewUsers,
    activity: viewActivity,
    account: viewAccount,
  };
  const fn = VIEW_FN[view];
  if (typeof fn !== "function") {
    // A nav entry without a handler would otherwise leave the skeleton up
    // forever with only a console error to show for it.
    el.innerHTML = `<div class="notice bad">No screen is wired up for "${esc(view)}".</div>`;
    return;
  }
  fn(el).catch((err) => {
    if (ticket !== state.gen) return;
    el.innerHTML = `<div class="notice bad">${esc(err.message)}</div>`;
  });
}

const head = (title, sub) =>
  `<div class="view-head"><h2>${esc(title)}</h2><p>${esc(sub)}</p></div>`;

/* ============================================================= overview */
async function viewOverview(el) {
  const [stats, health] = await Promise.all([api("/stats"), fetch("/health").then((r) => r.json())]);
  const t = stats.totals;
  el.innerHTML =
    head("Overview", "Traffic through the proxy and the current state of the engine.") +
    `<div class="grid four" style="margin-bottom:18px">
      <div class="metric"><b>${t.requests}</b><span>Requests proxied</span></div>
      <div class="metric info"><b>${t.masked}</b><span>Values masked</span></div>
      <div class="metric ${t.errors ? "bad" : ""}"><b>${t.errors}</b><span>Upstream errors</span></div>
      <div class="metric"><b>${stats.routes}</b><span>Endpoints configured</span></div>
    </div>
    <div class="grid two" style="margin-bottom:18px">
      <div class="panel" style="margin:0">
        <div class="panel-head"><h3>Engine</h3><span class="hint">reloaded ${stats.engine_version}×</span></div>
        <div class="panel-body">
          <div style="display:flex;justify-content:space-between;padding:5px 0"><span class="field-note" style="margin:0">Entities enabled</span><b>${health.entities_enabled.length}</b></div>
          <div style="display:flex;justify-content:space-between;padding:5px 0"><span class="field-note" style="margin:0">Score threshold</span><b>${health.score_threshold}</b></div>
        </div>
      </div>
      <div class="panel" style="margin:0">
        <div class="panel-head"><h3>Detection model</h3>
          ${health.llm.enabled ? pill("ok", "on") : pill("idle", "off")}</div>
        <div class="panel-body">
          <div style="display:flex;justify-content:space-between;padding:5px 0;gap:12px"><span class="field-note" style="margin:0">Model</span><code>${esc(health.llm.model)}</code></div>
          <div style="display:flex;justify-content:space-between;padding:5px 0;gap:12px"><span class="field-note" style="margin:0">Endpoint</span><code style="overflow:hidden;text-overflow:ellipsis">${esc(health.llm.base_url || "not set")}</code></div>
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-head"><h3>Recent hours</h3></div>
      ${table(
        [
          { label: "Day", cell: (r) => esc(r.day) },
          { label: "Hour", cell: (r) => `${r.hour}:00` },
          { label: "Route", cell: (r) => `<code>${esc(r.route)}</code>` },
          { label: "Requests", num: true, cell: (r) => r.requests },
          { label: "Masked", num: true, cell: (r) => r.masked },
          { label: "Errors", num: true, cell: (r) => (r.errors ? `<span style="color:var(--bad)">${r.errors}</span>` : "0") },
        ],
        stats.recent,
        "No traffic yet. Point a client at an endpoint to see it here."
      )}
    </div>`;
}

/* =============================================================== routes */
async function viewRoutes(el) {
  const routes = await api("/routes");
  const [strategies, provs] = await Promise.all([api("/strategies"), api("/providers")]);
  state.cache.strategies = strategies;
  state.cache.providers = provs;
  const provLabel = (k) => (provs.find((p) => p.key === k) || {}).label || k;
  el.innerHTML =
    head("Endpoints", "Each endpoint is a path on this gateway. Give it one provider or several, and choose how traffic is shared between them.") +
    `<div class="actions" style="margin-bottom:14px"><button class="btn" id="add-route">Add an endpoint</button></div>` +
    (routes.length
      ? routes
          .map(
            (r) => `<div class="panel">
        <div class="panel-head">
          <h3>${r.enabled ? pill("ok", "live") : pill("idle", "off")}<code>${esc(r.prefix)}</code>
            ${r.label ? `<span class="hint">${esc(r.label)}</span>` : ""}</h3>
          <div class="actions">
            <span class="tag">${esc(r.strategy.replace("_", " "))}</span>
            <button class="btn ghost small" data-edit="${r.id}">Edit</button>
            <button class="btn danger small" data-del="${r.id}">Delete</button>
          </div>
        </div>
        <div data-health="${r.id}">${table(
              [
                { label: "Provider", cell: (u) => (u.enabled ? "" : pill("idle", "off") + " ") + esc(u.name || "—") + `<div class="field-note" style="margin:2px 0 0">${esc(provLabel(u.provider_type))}</div>` },
                { label: "Address", cell: (u) => `<code>${esc(u.url)}</code>` },
                { label: "Model", cell: (u) => `<code>${esc(u.model_override || "client's choice")}</code>` },
                { label: "Order", num: true, cell: (u) => u.priority },
                { label: "Weight", num: true, cell: (u) => u.weight },
                { label: "In flight", num: true, cell: (u) => `<span data-f="${u.id}-inflight">–</span>` },
                { label: "Ok", num: true, cell: (u) => `<span data-f="${u.id}-ok">–</span>` },
                { label: "Failed", num: true, cell: (u) => `<span data-f="${u.id}-fail">–</span>` },
                { label: "State", cell: (u) => `<span data-f="${u.id}-state">${pill("idle", "waiting")}</span>` },
              ],
              r.upstreams,
              "No providers on this endpoint."
            )}</div>
        <div class="panel-body" style="padding:11px 16px;border-top:1px solid var(--line-soft)">
          <span class="field-note" style="margin:0">Masks ${esc(r.mask_roles.join(", "))} · detection model ${
              r.use_llm === null ? "follows the global setting" : r.use_llm ? "always on" : "always off"
            } · up to ${r.retries + 1} attempt(s) per request</span>
        </div>
      </div>`
          )
          .join("")
      : `<div class="panel"><div class="empty">No endpoints yet. Add one to start proxying.</div></div>`);

  $("#add-route").addEventListener("click", () => routeModal(null));
  $$("[data-edit]", el).forEach((b) =>
    b.addEventListener("click", () => routeModal(routes.find((r) => r.id == b.dataset.edit)))
  );
  $$("[data-del]", el).forEach((b) =>
    b.addEventListener("click", async () => {
      if (!confirm("Delete this endpoint? Clients using it will get a 404.")) return;
      await api("/routes/" + b.dataset.del, { method: "DELETE" });
      toast("Endpoint deleted");
      go("routes");
    })
  );

  const refresh = async () => {
    for (const r of routes) {
      let h;
      try { h = await api(`/routes/${r.id}/health`); } catch { return; }
      h.upstreams.forEach((u) => {
        const set = (k, v) => {
          const cell = el.querySelector(`[data-f="${u.id}-${k}"]`);
          if (cell) cell.innerHTML = v;
        };
        set("inflight", u.inflight);
        set("ok", u.ok);
        set("fail", u.fail ? `<span style="color:var(--bad)">${u.fail}</span>` : "0");
        set("state",
          u.cooldown ? pill("bad", `sidelined ${u.cooldown}s`)
          : u.inflight ? pill("info", "busy")
          : u.avg_ms ? pill("ok", `${u.avg_ms} ms`)
          : pill("idle", "idle"));
      });
    }
  };
  refresh();
  state.timer = setInterval(refresh, 4000);
}

function upstreamRow(u = {}, index = 0) {
  return `<div class="upstream" data-uid="${u.id || ""}">
    <div class="upstream-head">
      <strong>${esc(u.name || "New provider")}</strong>
      <div class="actions">
        <button type="button" class="btn ghost small" data-test>Test</button>
        <button type="button" class="btn danger small" data-remove>Remove</button>
      </div>
    </div>
    <div class="grid two">
      <label class="field"><span>Provider</span>
        <select name="u_type">${(state.cache.providers || [])
          .map((pv) => `<option value="${esc(pv.key)}" ${(u.provider_type || "openai") === pv.key ? "selected" : ""}>${esc(pv.label)}</option>`)
          .join("")}</select>
        <div class="field-note" data-pnote></div></label>
      <label class="field"><span>Name</span>
        <input type="text" name="u_name" value="${esc(u.name || "")}" placeholder="Production"></label>
    </div>
    <label class="field"><span>Address</span>
      <input type="text" class="mono" name="u_url" value="${esc(u.url || "")}" placeholder="https://api.openai.com/v1"></label>
    <div class="grid two">
      <label class="field"><span>API key</span>
        <input class="mono" type="password" name="u_token" placeholder="${u.has_token ? "Stored — leave blank to keep" : "Optional"}"></label>
      <label class="field"><span>Force a model</span>
        <input type="text" class="mono" name="u_model" value="${esc(u.model_override || "")}" placeholder="Leave blank"></label>
    </div>
    <div class="grid three">
      <label class="field"><span>Order</span>
        <input type="number" name="u_priority" min="1" max="99" value="${u.priority ?? index + 1}">
        <div class="field-note">Lower goes first.</div></label>
      <label class="field"><span>Weight</span>
        <input type="number" name="u_weight" min="1" max="100" value="${u.weight ?? 1}"></label>
      <label class="field"><span>Use it</span>
        <label class="toggle" style="margin-top:8px"><input type="checkbox" name="u_enabled" ${u.enabled !== false ? "checked" : ""}><span class="switch"></span></label></label>
    </div>
    <div class="field-note" data-result></div>
  </div>`;
}

async function routeModal(route) {
  if (!state.cache.providers) state.cache.providers = await api("/providers");
  const entities = (await api("/entities")).entities;
  const strategies = state.cache.strategies || (await api("/strategies"));
  const chosen = new Set(route?.entities || []);
  const roles = new Set(route?.mask_roles || ["user"]);
  const ups = route?.upstreams?.length ? route.upstreams : [{}];

  openModal({
    title: route ? "Edit endpoint" : "Add an endpoint",
    wide: true,
    body: `
      <div class="grid two">
        <label class="field"><span>Path on this gateway</span>
          <input type="text" class="mono" name="prefix" value="${esc(route?.prefix || "/v1")}" placeholder="/secure/v1">
          <div class="field-note">Longest matching path wins.</div></label>
        <label class="field"><span>Label</span>
          <input type="text" name="label" value="${esc(route?.label || "")}" placeholder="Agent traffic"></label>
      </div>
      <div class="panel" style="margin:6px 0 18px">
        <div class="panel-head"><h3>Providers</h3>
          <button type="button" class="btn ghost small" id="add-upstream">Add another</button></div>
        <div class="panel-body" id="upstreams">${ups.map((u, i) => upstreamRow(u, i)).join("")}</div>
      </div>
      <div class="grid two">
        <label class="field"><span>How to choose between them</span>
          <select name="strategy">
            ${Object.entries(strategies)
              .map(([k, help]) => `<option value="${esc(k)}" ${(route?.strategy || "failover") === k ? "selected" : ""}>${esc(k.replace("_", " "))} — ${esc(help)}</option>`)
              .join("")}
          </select></label>
        <label class="field"><span>Retries on failure</span>
          <input type="number" name="retries" min="0" max="9" value="${route?.retries ?? 2}">
          <div class="field-note">A failed attempt moves to the next upstream.</div></label>
      </div>
      <label class="field"><span>Mask these message roles</span></label>
      <div class="checks" style="margin-bottom:16px">
        ${["user", "assistant", "tool", "system"]
          .map((r) => `<label><input type="checkbox" name="role" value="${r}" ${roles.has(r) ? "checked" : ""}> ${r}${r === "system" ? " (not advised)" : ""}</label>`)
          .join("")}
      </div>
      <div class="grid two">
        <label class="field"><span>Detection model on this route</span>
          <select name="use_llm">
            <option value="">Follow the global setting</option>
            <option value="true" ${route?.use_llm === true ? "selected" : ""}>Always on</option>
            <option value="false" ${route?.use_llm === false ? "selected" : ""}>Always off — faster, offline</option>
          </select></label>
        <label class="field"><span>Timeout (seconds)</span>
          <input type="number" name="timeout" value="${route?.timeout ?? 300}" min="5" max="1800"></label>
      </div>
      <label class="field"><span>Limit to these entities</span>
        <div class="field-note" style="margin:0 0 9px">Leave all unticked to use whatever is enabled globally.</div></label>
      <div class="checks">
        ${entities.map((e) => `<label><input type="checkbox" name="entity" value="${esc(e.entity)}" ${chosen.has(e.entity) ? "checked" : ""}> <span class="mono">${esc(e.entity)}</span></label>`).join("")}
      </div>`,
    onReady: (form) => {
      const list = $("#upstreams", form);
      const wire = (row) => {
        row.querySelector("[data-remove]").addEventListener("click", () => {
          if (list.children.length === 1) return toast("An endpoint needs at least one provider", true);
          row.remove();
        });
        row.querySelector("[data-test]").addEventListener("click", async () => {
          const out = row.querySelector("[data-result]");
          out.textContent = "Testing…";
          try {
            const r = await api("/upstreams/test", {
              method: "POST",
              body: {
                url: row.querySelector('[name="u_url"]').value,
                provider_type: row.querySelector('[name="u_type"]').value,
                token: row.querySelector('[name="u_token"]').value || null,
                model: row.querySelector('[name="u_model"]').value,
                upstream_id: row.dataset.uid ? Number(row.dataset.uid) : null,
              },
            });
            out.innerHTML = r.ok
              ? pill("ok", "reached" + (r.routed_via ? " via " + r.routed_via : ""))
              : pill("bad", `failed ${r.status} ${r.detail}`.slice(0, 110));
          } catch (e) { out.innerHTML = pill("bad", e.message); }
        });
        row.querySelector('[name="u_name"]').addEventListener("input", (e) => {
          row.querySelector("strong").textContent = e.target.value || "New provider";
        });
        const typeSel = row.querySelector('[name="u_type"]');
        const applyPreset = (fill) => {
          const pv = (state.cache.providers || []).find((x) => x.key === typeSel.value);
          if (!pv) return;
          row.querySelector("[data-pnote]").textContent = pv.note || "";
          if (!fill) return;
          // Only overwrite fields the person has not filled in themselves.
          const url = row.querySelector('[name="u_url"]');
          const model = row.querySelector('[name="u_model"]');
          const name = row.querySelector('[name="u_name"]');
          if (!url.value || url.dataset.preset === "1") { url.value = pv.url; url.dataset.preset = "1"; }
          if (!model.value || model.dataset.preset === "1") { model.value = pv.model; model.dataset.preset = "1"; }
          if (!name.value) { name.value = pv.label; row.querySelector("strong").textContent = pv.label; }
        };
        typeSel.addEventListener("change", () => applyPreset(true));
        applyPreset(false);
      };
      [...list.children].forEach(wire);
      $("#add-upstream", form).addEventListener("click", () => {
        const wrap = document.createElement("div");
        wrap.innerHTML = upstreamRow({}, list.children.length);
        const row = wrap.firstElementChild;
        list.appendChild(row);
        wire(row);
        row.querySelector('[name="u_name"]').focus();
      });
    },
    onSave: async (form) => {
      const upstreams = $$(".upstream", form).map((row) => {
        const v = (n) => row.querySelector(`[name="${n}"]`);
        const token = v("u_token").value;
        return {
          id: row.dataset.uid ? Number(row.dataset.uid) : null,
          name: v("u_name").value.trim(),
          provider_type: v("u_type").value,
          url: v("u_url").value.trim(),
          token: token ? token : row.dataset.uid ? null : "",
          model_override: v("u_model").value.trim(),
          priority: Number(v("u_priority").value),
          weight: Number(v("u_weight").value),
          enabled: v("u_enabled").checked,
        };
      });
      const body = {
        prefix: form.prefix.value,
        label: form.label.value,
        enabled: true,
        mask_roles: $$('[name="role"]:checked', form).map((c) => c.value),
        entities: $$('[name="entity"]:checked', form).map((c) => c.value),
        use_llm: form.use_llm.value === "" ? null : form.use_llm.value === "true",
        timeout: Number(form.timeout.value),
        strategy: form.strategy.value,
        retries: Number(form.retries.value),
        upstreams,
      };
      if (route) await api("/routes/" + route.id, { method: "PUT", body });
      else await api("/routes", { method: "POST", body });
      toast(route ? "Endpoint updated" : "Endpoint added");
      go("routes");
    },
  });
}

/* =========================================================== playground */
async function viewPlayground(el) {
  const routes = await api("/routes");
  if (!routes.length) {
    el.innerHTML = head("Playground", "Send a prompt through a route and see exactly what the model receives.") +
      `<div class="notice warn">Add an endpoint first — the playground sends through one.</div>`;
    return;
  }
  el.innerHTML =
    head("Playground", "Send a prompt through an endpoint and see exactly what the model receives. This is the chat model, not the detection model.") +
    `<div class="panel"><div class="panel-body">
      <div class="grid two">
        <label class="field"><span>Endpoint</span>
          <select id="pg-route">${routes.map((r) => `<option value="${r.id}">${esc(r.prefix)}${r.label ? " — " + esc(r.label) : ""}</option>`).join("")}</select></label>
        <label class="field"><span>Model</span>
          <div class="input-row">
            <select id="pg-model"><option value="auto:fast">auto:fast</option></select>
            <button class="btn ghost" id="pg-load" type="button">Load models</button>
          </div>
          <div class="field-note" id="pg-model-note">Load the catalogue from this endpoint's providers.</div></label>
      </div>
      <label class="field"><span>System prompt (optional, never masked)</span>
        <input type="text" id="pg-system" placeholder="You are a helpful assistant."></label>
      <label class="field"><span>Prompt</span>
        <textarea id="pg-prompt" style="min-height:150px">Summarise this ticket and say who should be contacted first.

Raised by Priya Raghunathan (PAN ABCPE1234F, Aadhaar 3456 7890 1238), who called from 9876543210. Her login came from 203.0.113.45.

Escalated to Mohammed Ashraf (PAN BZTPK5678L, Aadhaar 7890 1234 5674), reachable on 9123456780, working from 10.4.18.9.

The account is held jointly with Lakshmi Narayanan, UPI lakshmi@okhdfcbank, IFSC HDFC0001234.</textarea></label>
      <div class="run-row">
        <label class="field"><span>Temperature</span><input type="number" id="pg-temp" step="0.1" min="0" max="2" value="0.7"></label>
        <label class="field"><span>Max tokens</span><input type="number" id="pg-max" min="16" max="4096" value="512"></label>
        <button class="btn" id="pg-run">Run prompt</button>
      </div>
    </div></div>
    <div id="pg-out"></div>`;

  const loadModels = async () => {
    const note = $("#pg-model-note");
    note.textContent = "Loading…";
    const btn = $("#pg-load");
    btn.dataset.busy = "1";
    try {
      const r = await api(`/routes/${$("#pg-route").value}/models`);
      const sel = $("#pg-model");
      // Group by vendor so a catalogue of several hundred stays navigable.
      const byVendor = {};
      r.models.forEach((m) => (byVendor[m.vendor || "other"] ??= []).push(m));
      sel.innerHTML =
        `<optgroup label="Automatic"><option value="auto:fast">auto:fast</option><option value="auto">auto</option><option value="auto:smart">auto:smart</option></optgroup>` +
        Object.keys(byVendor).sort().map((v) =>
          `<optgroup label="${esc(v)}">` +
          byVendor[v].map((m) => `<option value="${esc(m.id)}">${esc(v)} / ${esc(m.short)}</option>`).join("") +
          `</optgroup>`
        ).join("");
      note.textContent = r.errors.length
        ? `${r.models.length} models. ${r.errors.length} provider(s) failed.`
        : `${r.models.length} models across this endpoint's providers.`;
    } catch (e) { note.textContent = e.message; }
    finally { delete btn.dataset.busy; }
  };
  $("#pg-load").addEventListener("click", loadModels);
  $("#pg-route").addEventListener("change", loadModels);

  $("#pg-run").addEventListener("click", async () => {
    const out = $("#pg-out");
    const btn = $("#pg-run");
    btn.dataset.busy = "1";
    btn.disabled = true;
    out.innerHTML = `<div class="panel"><div class="skeleton"><i></i><i></i><i></i></div></div>`;
    try {
      const r = await api("/playground", {
        method: "POST",
        body: {
          route_id: Number($("#pg-route").value),
          model: $("#pg-model").value,
          prompt: $("#pg-prompt").value,
          system: $("#pg-system").value,
          temperature: Number($("#pg-temp").value),
          max_tokens: Number($("#pg-max").value),
        },
      });
      if (!r.ok) {
        out.innerHTML = `<div class="notice bad">${esc(r.error || "Failed")}${
          r.attempts ? "<br>" + r.attempts.map(esc).join("<br>") : ""
        }</div>`;
        return;
      }
      const tokens = (r.placeholders || []).map((p) => p.token);
      const hl = (t) => {
        let html = esc(t).replace(/&lt;[A-Z][A-Z0-9_]*_\d+&gt;/g, (m) => `<mark class="ph">${m}</mark>`);
        // Surrogates look like ordinary data, so highlight them explicitly or
        // you cannot tell what the model was actually shown.
        tokens
          .filter((x) => !x.startsWith("<"))
          .sort((a, b) => b.length - a.length)
          .forEach((tok) => {
            html = html.split(esc(tok)).join(`<mark class="sur">${esc(tok)}</mark>`);
          });
        return html;
      };
      out.innerHTML =
        `<div class="grid four" style="margin-bottom:16px">
          <div class="metric info"><b>${r.masked_count}</b><span>Values masked</span></div>
          <div class="metric"><b>${r.latency_ms}</b><span>Milliseconds</span></div>
          <div class="metric"><b>${r.usage?.total_tokens ?? "—"}</b><span>Tokens</span></div>
          <div class="metric"><b style="font-size:14px">${esc(r.upstream)}</b><span>Provider used</span></div>
        </div>
        <div class="pg">
          <div>
            <div class="stage mono"><header>What the model received<span>${esc(r.model)}</span></header>
              <div>${r.sent_to_model.map((m) => `<b style="color:var(--muted)">${esc(m.role)}:</b> ${hl(m.content)}`).join("\n\n")}</div></div>
            <div class="stage"><header>Placeholders</header>
              ${table(
                [
                  { label: "Token", cell: (p) => `<mark class="ph">${esc(p.token)}</mark>` },
                  { label: "Real value", cell: (p) => `<code>${esc(p.value)}</code>` },
                ],
                r.placeholders,
                "Nothing was detected in this prompt."
              )}</div>
          </div>
          <div>
            <div class="stage mono"><header>Raw reply${r.routed_via ? `<span>${esc(r.routed_via)}</span>` : ""}</header>
              <div>${hl(r.raw_reply)}</div></div>
            <div class="stage"><header>Restored reply — what a client sees</header>
              <div>${esc(r.restored_reply)}</div></div>
          </div>
        </div>`;
    } catch (e) {
      out.innerHTML = `<div class="notice bad">${esc(e.message)}</div>`;
    } finally { delete btn.dataset.busy; btn.disabled = false; }
  });
}

/* ============================================================ analytics */
async function viewAnalytics(el) {
  const a = await api("/analytics");
  const worst = Math.max(1, ...a.providers.map((p) => p.p95));
  el.innerHTML =
    head("Analytics", "Latency and token use per provider, from the last few thousand requests.") +
    (a.samples
      ? `<div class="grid four" style="margin-bottom:18px">
          <div class="metric"><b>${a.samples}</b><span>Requests sampled</span></div>
          <div class="metric info"><b>${a.providers.reduce((t, p) => t + p.masked, 0)}</b><span>Values masked</span></div>
          <div class="metric"><b>${a.providers.reduce((t, p) => t + p.tokens_in + p.tokens_out, 0).toLocaleString()}</b><span>Tokens</span></div>
          <div class="metric ${a.providers.some((p) => p.errors) ? "bad" : ""}"><b>${a.providers.reduce((t, p) => t + p.errors, 0)}</b><span>Failures</span></div>
        </div>
        <div class="panel">
          <div class="panel-head"><h3>By provider</h3>
            <span class="hint">p95 is the slow tail — the number your users notice</span></div>
          ${table(
            [
              { label: "Provider", cell: (p) => `<div>${esc(p.name)}</div><div class="field-note" style="margin:2px 0 0">${esc(p.provider_type)} · <code>${esc(p.route)}</code></div>` },
              { label: "Requests", num: true, cell: (p) => p.requests },
              { label: "Failures", num: true, cell: (p) => (p.errors ? `<span style="color:var(--bad)">${p.errors}</span>` : "0") },
              { label: "p50", num: true, cell: (p) => `${p.p50} ms` },
              { label: "p95", num: true, cell: (p) => `<div style="display:flex;align-items:center;gap:8px;justify-content:flex-end"><span>${p.p95} ms</span><span class="bar"><i style="width:${Math.round((p.p95 / worst) * 100)}%"></i></span></div>` },
              { label: "Slowest", num: true, cell: (p) => `${p.max} ms` },
              { label: "Tokens in", num: true, cell: (p) => p.tokens_in.toLocaleString() },
              { label: "Tokens out", num: true, cell: (p) => p.tokens_out.toLocaleString() },
              { label: "Masked", num: true, cell: (p) => p.masked },
            ],
            a.providers,
            "No requests recorded yet."
          )}
        </div>`
      : `<div class="panel"><div class="empty">No requests recorded yet. Send something through an endpoint or the playground.</div></div>`);
}

/* ============================================================ detection */
const MODE_LABEL = { tag: "Name tag", surrogate: "Lookalike", last4: "Last 4" };
const MODE_PILL = { tag: "info", surrogate: "ok", last4: "warn" };

async function viewDetection(el) {
  const [d, settings] = await Promise.all([api("/entities"), api("/settings")]);
  const entities = d.entities;
  state.cache.strategyHelp = d.strategies;
  el.innerHTML =
    head("Entities", "What gets detected, and what the model sees in its place.") +
    `<div class="panel">
      <div class="panel-head"><h3>Confidence</h3></div>
      <div class="panel-body" style="max-width:360px">
        <label class="field"><span>Minimum score, 0 to 1</span>
          <input type="number" step="0.05" min="0" max="1" id="threshold" value="${esc(settings.score_threshold)}">
          <div class="field-note">Raise this if harmless text is being masked. Lower it if real identifiers slip through.</div></label>
        <button class="btn" id="save-threshold">Save</button>
      </div>
    </div>
    <div class="panel">
      <div class="panel-head"><h3>Data types</h3>
        <span class="hint">${entities.filter((e) => e.enabled).length} of ${entities.length} detected</span></div>
      ${table(
        [
          { label: "Type", cell: (e) => `<code>${esc(e.entity)}</code>` },
          { label: "Found by", cell: (e) => e.source === "llm" ? pill("info", "model") : e.source === "rules" ? pill("ok", "patterns") : pill("idle", "built in") },
          { label: "Model sees", cell: (e) => `<button class="btn ghost small" data-mode="${esc(e.entity)}">${esc(MODE_LABEL[e.redaction] || "Name tag")}</button>` },
          { label: "Detect", cell: (e) => `<label class="toggle"><input type="checkbox" data-entity="${esc(e.entity)}" ${e.enabled ? "checked" : ""}><span class="switch"></span></label>` },
        ],
        entities
      )}
    </div>`;

  $("#save-threshold").addEventListener("click", async (e) => {
    await busy(e.currentTarget, () => api("/settings", { method: "PUT", body: { score_threshold: $("#threshold").value } }));
    toast("Saved");
  });
  $$("[data-entity]", el).forEach((cb) =>
    cb.addEventListener("change", async () => {
      await api("/entities", { method: "PUT", body: [{ entity: cb.dataset.entity, enabled: cb.checked }] });
      toast(cb.dataset.entity + (cb.checked ? " on" : " off"));
    })
  );
  $$("[data-mode]", el).forEach((b) =>
    b.addEventListener("click", () =>
      redactionModal(entities.find((x) => x.entity === b.dataset.mode))
    )
  );
}

/* The three ways a value can be stood in for. Shared by the entity editor
   and the pattern editor so both explain it the same way. */
function redactionFields(current, shape, entity) {
  return `
    <label class="field"><span>What the model sees instead</span>
      <select name="redaction">
        <option value="tag" ${current === "tag" ? "selected" : ""}>Name tag — &lt;${esc(entity || "TYPE")}_1&gt;</option>
        <option value="surrogate" ${current === "surrogate" ? "selected" : ""}>Lookalike — a fake value with the same shape</option>
        <option value="last4" ${current === "last4" ? "selected" : ""}>Last 4 — ••••••3210</option>
      </select></label>
    <div class="mode-help" id="mode-help"></div>
    <div id="shape-block" hidden>
      <label class="field"><span>Shape</span>
        <div class="shape-row">
          <input type="text" class="mono" name="shape" value="${esc(shape || "")}" placeholder="AAAAA9999A" spellcheck="false">
          <button type="button" class="btn ghost" id="shape-learn">From example</button>
        </div>
        <div class="shape-legend">
          <span><code>A</code> letter</span><span><code>a</code> lower</span>
          <span><code>9</code> digit</span><span><code>?</code> either</span>
          <span><code>[2-9]</code> a set</span><span><code>{19}</code> literal</span>
        </div>
        <div class="field-note" id="shape-note"></div>
      </label>
    </div>
    <label class="field"><span>Try it on real-looking examples</span>
      <textarea class="mono" name="samples" style="min-height:64px" placeholder="One value per line"></textarea>
      <div class="field-note">Use fake values. This is only to preview the replacement.</div></label>
    <div class="actions" style="margin:-6px 0 12px">
      <button type="button" class="btn ghost" id="swap-preview">Preview</button>
    </div>
    <div id="swap-out"></div>`;
}

function wireRedaction(form, entity) {
  const sel = form.redaction;
  const block = $("#shape-block", form);
  const help = $("#mode-help", form);
  const refresh = () => {
    const mode = sel.value;
    block.hidden = mode !== "surrogate";
    help.textContent =
      mode === "surrogate"
        ? "The model can count the characters and check the format, so it can answer questions about the value itself. It never sees the real one."
        : mode === "last4"
        ? "Enough for a person reading the reply to recognise which record it is. The model cannot reason about the rest."
        : "The model can refer to it and tell it apart from others, but cannot inspect it. Safest, and the right choice for names and addresses.";
  };
  sel.addEventListener("change", refresh);
  refresh();

  $("#shape-learn", form)?.addEventListener("click", async (e) => {
    const first = (form.samples.value || "").split("\n").map((x) => x.trim()).filter(Boolean)[0];
    if (!first) return toast("Put an example in the box below first", true);
    const r = await busy(e.currentTarget, () => api("/surrogate/infer", { method: "POST", body: { sample: first } }));
    form.shape.value = r.shape;
    $("#shape-note", form).textContent = r.error || "";
    toast("Shape read from your example");
  });

  $("#swap-preview", form).addEventListener("click", async (e) => {
    const out = $("#swap-out", form);
    const samples = (form.samples.value || "").split("\n").map((x) => x.trim()).filter(Boolean);
    if (!samples.length) return toast("Add an example or two first", true);
    const r = await busy(e.currentTarget, () =>
      api("/surrogate/preview", {
        method: "POST",
        body: { entity: entity || "SAMPLE", redaction: sel.value, shape: form.shape?.value || "", samples },
      })
    );
    if (r.error) { out.innerHTML = `<div class="notice bad">${esc(r.error)}</div>`; return; }
    if (form.shape && !form.shape.value && r.shape) form.shape.value = r.shape;
    out.innerHTML = r.rows
      .map((row) => `<div class="swap ${esc(sel.value)}">
        <span class="real">${esc(row.real)}</span>
        <span class="arrow">→</span>
        <span class="fake">${esc(row.stand_in)}</span></div>`)
      .join("");
  });
}

async function redactionModal(entity) {
  openModal({
    title: `What the model sees for ${entity.entity}`,
    body: redactionFields(entity.redaction, entity.shape, entity.entity),
    onReady: (form) => wireRedaction(form, entity.entity),
    onSave: async (form) => {
      await api("/entities", {
        method: "PUT",
        body: [{ entity: entity.entity, redaction: form.redaction.value, shape: form.shape?.value || "" }],
      });
      toast(`${entity.entity} → ${MODE_LABEL[form.redaction.value]}`);
      go("detection");
    },
  });
}

/* ============================================================= patterns */
async function viewPatterns(el) {
  const [patterns, settings, packs] = await Promise.all([
    api("/patterns"), api("/settings"), api("/packs"),
  ]);
  state.cache.validators = settings._validators;
  const filter = state.cache.packFilter || "";
  const shown = filter ? patterns.filter((p) => p.pack === filter) : patterns;
  el.innerHTML =
    head("Patterns", "Rules that find structured identifiers. A pattern matches text; a check can then reject matches that fail a checksum.") +
    `<div class="panel">
      <div class="panel-head"><h3>Regions</h3>
        <span class="hint">Switch on only where your data comes from — other regions add false positives</span></div>
      ${table(
        [
          { label: "Pack", cell: (p) => `<div>${esc(p.label)}</div><div class="field-note" style="margin:2px 0 0">${esc(p.description)}</div>` },
          { label: "Patterns", num: true, cell: (p) => `${p.active} / ${p.patterns}` },
          { label: "Show", cell: (p) => `<button class="btn ghost small" data-filter="${esc(p.key)}">View</button>` },
          { label: "On", cell: (p) => p.key === "custom" ? "" : `<label class="toggle"><input type="checkbox" data-pack="${esc(p.key)}" ${p.enabled ? "checked" : ""}><span class="switch"></span></label>` },
        ],
        packs
      )}
    </div>
    <div class="actions" style="margin-bottom:14px">
      <button class="btn" id="add-pattern">Add a pattern</button>
      <button class="btn ghost" id="gen-pattern">Generate with AI</button>
      ${filter ? `<button class="btn ghost" id="clear-filter">Showing ${esc(filter)} — show all</button>` : ""}
    </div>
     <div class="panel">${table(
       [
         { label: "Type", cell: (p) => `<code>${esc(p.entity)}</code>` },
         { label: "Pack", cell: (p) => `<span class="tag">${esc(p.pack)}</span>` },
         { label: "Name", cell: (p) => esc(p.name) },
         { label: "Pattern", cell: (p) => `<code>${esc(p.regex.length > 38 ? p.regex.slice(0, 38) + "…" : p.regex)}</code>` },
         { label: "Check", cell: (p) => (p.validator === "none" ? "—" : pill("info", p.validator)) },
         { label: "Model sees", cell: (p) => pill(MODE_PILL[p.redaction] || "info", MODE_LABEL[p.redaction] || "Name tag") },
         { label: "Score", num: true, cell: (p) => `<div style="display:flex;align-items:center;gap:8px;justify-content:flex-end"><span>${p.score}</span><span class="bar"><i style="width:${Math.round(p.score * 100)}%"></i></span></div>` },
         { label: "On", cell: (p) => `<label class="toggle"><input type="checkbox" data-toggle="${p.id}" ${p.enabled ? "checked" : ""}><span class="switch"></span></label>` },
         { label: "", cell: (p) => `<button class="btn ghost small" data-edit="${p.id}">Edit</button> <button class="btn danger small" data-del="${p.id}">Delete</button>` },
       ],
       shown
     )}</div>`;

  const find = (id) => patterns.find((p) => p.id == id);
  $("#add-pattern").addEventListener("click", () => patternModal(null));
  $("#gen-pattern").addEventListener("click", () => generateModal());
  $("#clear-filter")?.addEventListener("click", () => {
    state.cache.packFilter = "";
    go("patterns");
  });
  $$("[data-filter]", el).forEach((b) =>
    b.addEventListener("click", () => {
      state.cache.packFilter = b.dataset.filter;
      go("patterns");
    })
  );
  $$("[data-pack]", el).forEach((cb) =>
    cb.addEventListener("change", async () => {
      try {
        await api("/packs", { method: "PUT", body: { key: cb.dataset.pack, enabled: cb.checked } });
        toast(cb.dataset.pack + (cb.checked ? " enabled" : " disabled"));
        go("patterns");
      } catch (e) { cb.checked = !cb.checked; toast(e.message, true); }
    })
  );
  $$("[data-edit]", el).forEach((b) => b.addEventListener("click", () => patternModal(find(b.dataset.edit))));
  $$("[data-del]", el).forEach((b) =>
    b.addEventListener("click", async () => {
      if (!confirm("Delete this pattern?")) return;
      await api("/patterns/" + b.dataset.del, { method: "DELETE" });
      toast("Pattern deleted");
      go("patterns");
    })
  );
  $$("[data-toggle]", el).forEach((cb) =>
    cb.addEventListener("change", async () => {
      const p = find(cb.dataset.toggle);
      try {
        await api("/patterns/" + p.id, { method: "PUT", body: { ...p, enabled: cb.checked } });
        toast(cb.checked ? "Pattern on" : "Pattern off");
      } catch (err) {
        cb.checked = !cb.checked;
        toast(err.message, true);
      }
    })
  );
}

function generateModal() {
  openModal({
    title: "Generate a pattern",
    body: `<div class="notice info">Describe the identifier in plain words. The detection model drafts a regex, context words and test samples. Nothing is saved until you review it.</div>
      <label class="field"><span>What should it detect?</span>
        <textarea name="description" placeholder="Our internal employee ID: the letters EMP followed by six digits"></textarea></label>
      <label class="field"><span>Real examples (optional)</span>
        <textarea class="mono" name="examples" placeholder="EMP004512&#10;EMP991003"></textarea>
        <div class="field-note">Use fake values, not real records — this text is sent to the detection model.</div></label>`,
    onSave: async (form) => {
      const draft = await api("/patterns/generate", {
        method: "POST",
        body: { description: form.description.value, examples: form.examples.value },
      });
      toast("Drafted — check the tester before saving");
      return () =>
        patternModal({
          entity: draft.entity, name: draft.name, regex: draft.regex,
          score: draft.score, context: draft.context, validator: "none",
          enabled: true, redaction: "tag", shape: "",
          _sample: (draft.samples || []).join("\n"),
        });
    },
  });
}

function patternModal(p) {
  const validators = state.cache.validators || { none: "" };
  openModal({
    title: p ? "Edit pattern" : "Add a pattern",
    wide: true,
    body: `
      <div class="grid two">
        <label class="field"><span>Data type</span>
          <input type="text" class="mono" name="entity" value="${esc(p?.entity || "")}" placeholder="IN_EMPLOYEE_ID">
          <div class="field-note">Capitals, digits and underscores.</div></label>
        <label class="field"><span>Name</span>
          <input type="text" name="name" value="${esc(p?.name || "")}" placeholder="Employee ID"></label>
      </div>
      <label class="field"><span>Pattern</span>
        <input type="text" class="mono" name="regex" value="${esc(p?.regex || "")}" placeholder="\\bEMP\\d{6}\\b" spellcheck="false"></label>
      <div class="grid two">
        <label class="field"><span>Extra check</span>
          <select name="validator">
            ${Object.entries(validators).map(([k, help]) => `<option value="${esc(k)}" ${p?.validator === k ? "selected" : ""}>${esc(k)} — ${esc(help)}</option>`).join("")}
          </select></label>
        <label class="field"><span>Score, 0 to 1</span>
          <input type="number" step="0.05" min="0" max="1" name="score" value="${p?.score ?? 0.5}">
          <div class="field-note">Start low for generic shapes like bare digits.</div></label>
      </div>
      <label class="field"><span>Nearby words that raise confidence</span>
        <input type="text" name="context" value="${esc((p?.context || []).join(", "))}" placeholder="employee, staff, emp id">
        <div class="field-note">Comma separated.</div></label>
      <label class="toggle" style="margin-bottom:18px"><input type="checkbox" name="enabled" ${p?.enabled !== false ? "checked" : ""}><span class="switch"></span><span>Use this pattern</span></label>
      ${redactionFields(p?.redaction || "tag", p?.shape || "", p?.entity || "")}`,
    extra: `<div class="tester">
        <div><label class="field" style="margin:0"><span>Sample text</span>
          <textarea id="rx-sample" class="mono" spellcheck="false">${esc(p?._sample || "EMP004512 raised a ticket. Order 100000000 is unrelated.")}</textarea></label></div>
        <div><div class="field-note" style="margin:0 0 7px">Live result</div>
          <div class="preview" id="rx-preview"></div>
          <div class="legend">Green passed the check. Red struck through means the pattern matched but the check rejected it.</div></div>
      </div>`,
    onReady: (form) => {
      wireRedaction(form, p?.entity || "");
      // Keep the surrogate preview honest when the entity name changes.
      form.entity.addEventListener("input", () => {
        form._entity = form.entity.value.trim().toUpperCase();
      });
      const run = debounce(async () => {
        const regex = form.regex.value;
        const preview = $("#rx-preview");
        const text = $("#rx-sample").value;
        if (!regex) return void (preview.textContent = text);
        try {
          const r = await api("/patterns/test", {
            method: "POST",
            body: { regex, validator: form.validator.value, text },
          });
          if (r.error) return void (preview.innerHTML = `<span class="legend" style="color:var(--bad)">${esc(r.error)}</span>`);
          let html = "", cursor = 0;
          r.matches.forEach((m) => {
            if (m.start < cursor) return;
            html += esc(text.slice(cursor, m.start));
            html += `<mark class="${m.valid ? "hit" : "miss"}">${esc(m.text)}</mark>`;
            cursor = m.end;
          });
          html += esc(text.slice(cursor));
          const passed = r.matches.filter((m) => m.valid).length;
          preview.innerHTML = html + `<div class="legend">${passed} kept, ${r.matches.length - passed} rejected</div>`;
        } catch (err) {
          preview.innerHTML = `<span class="legend">${esc(err.message)}</span>`;
        }
      }, 260);
      form.regex.addEventListener("input", run);
      form.validator.addEventListener("change", run);
      $("#rx-sample").addEventListener("input", run);
      run();
    },
    onSave: async (form) => {
      const body = {
        entity: form.entity.value.trim().toUpperCase(),
        name: form.name.value.trim(),
        regex: form.regex.value,
        score: Number(form.score.value),
        context: form.context.value.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean),
        validator: form.validator.value,
        enabled: form.enabled.checked,
        redaction: form.redaction.value,
        shape: form.shape?.value || "",
      };
      if (p) await api("/patterns/" + p.id, { method: "PUT", body });
      else await api("/patterns", { method: "POST", body });
      toast(p ? "Pattern updated" : "Pattern added");
      go("patterns");
    },
  });
}

/* ====================================================== detection model */
async function viewLlm(el) {
  const settings = await api("/settings");
  const llmEntities = JSON.parse(settings.llm_entities || "[]");
  el.innerHTML =
    head("Detection model", "A second pass that finds names, addresses and other things patterns cannot describe. It only returns spans — it never writes your replies.") +
    `<div class="notice warn">This is not the model your prompts are answered by. That one is chosen per request and set under Endpoints. This model only reads text to find PII, and it receives that text <strong>unmasked</strong> — point it at something you control for regulated data, or switch it off.</div>
     <div class="panel"><div class="panel-body">
      <label class="toggle" style="margin-bottom:18px">
        <input type="checkbox" id="llm_enabled" ${settings.llm_enabled === "true" ? "checked" : ""}>
        <span class="switch"></span><span>Use the detection model</span></label>
      <div class="grid two">
        <label class="field"><span>Base URL</span><input type="text" class="mono" id="llm_base_url" value="${esc(settings.llm_base_url)}"></label>
        <label class="field"><span>Model</span><input type="text" class="mono" id="llm_model" value="${esc(settings.llm_model)}"></label>
      </div>
      <label class="field"><span>API key</span>
        <input class="mono" type="password" id="llm_token" placeholder="${settings.llm_token ? "Stored — leave blank to keep" : "Optional"}"></label>
      <div class="grid two">
        <label class="field"><span>Timeout (seconds)</span><input type="number" id="llm_timeout" value="${esc(settings.llm_timeout)}"></label>
        <label class="field"><span>Score for its findings</span><input type="number" step="0.05" min="0" max="1" id="llm_score" value="${esc(settings.llm_score)}"></label>
      </div>
      <label class="field"><span>Ask it to find</span></label>
      <div class="checks" style="margin-bottom:18px">
        ${settings._entities_all.map((e) => `<label><input type="checkbox" name="le" value="${esc(e)}" ${llmEntities.includes(e) ? "checked" : ""}> <span class="mono">${esc(e)}</span></label>`).join("")}
      </div>
      <div class="actions">
        <button class="btn" id="save-llm">Save</button>
        <button class="btn ghost" id="test-llm">Test the connection</button>
        <span id="llm-result"></span>
      </div>
     </div></div>`;

  $("#save-llm").addEventListener("click", async () => {
    const body = {
      llm_enabled: $("#llm_enabled").checked,
      llm_base_url: $("#llm_base_url").value,
      llm_model: $("#llm_model").value,
      llm_timeout: $("#llm_timeout").value,
      llm_score: $("#llm_score").value,
      llm_entities: $$('[name="le"]:checked', el).map((c) => c.value),
    };
    const token = $("#llm_token").value;
    if (token) body.llm_token = token;
    await api("/settings", { method: "PUT", body });
    toast("Saved");
  });
  $("#test-llm").addEventListener("click", async (e) => {
    const out = $("#llm-result");
    out.textContent = "Testing…";
    const r = await busy(e.currentTarget, () => api("/test/llm", { method: "POST" }));
    out.innerHTML = r.ok
      ? pill("ok", "reached" + (r.routed_via ? " via " + r.routed_via : ""))
      : pill("bad", `failed ${r.status} ${r.detail}`.slice(0, 120));
  });
}

/* ============================================================== network */
async function viewNetwork(el) {
  const settings = await api("/settings");
  el.innerHTML =
    head("Egress", "Send everything this gateway calls out to through an HTTP proxy, so all traffic leaves from one address.") +
    `<div class="panel"><div class="panel-body">
      <label class="toggle" style="margin-bottom:18px">
        <input type="checkbox" id="proxy_enabled" ${settings.proxy_enabled === "true" ? "checked" : ""}>
        <span class="switch"></span><span>Route outbound traffic through a proxy</span></label>
      <label class="field"><span>Proxy address</span>
        <input class="mono" type="password" id="proxy_url" placeholder="${settings.proxy_url ? "Stored — leave blank to keep" : "http://user:pass@10.0.0.5:3128"}">
        <div class="field-note">Percent-encode any @ in the password as %40. Stored encrypted.</div></label>
      <label class="field"><span>Never proxy these hosts</span>
        <input type="text" class="mono" id="proxy_bypass" value="${esc(settings.proxy_bypass || "")}">
        <div class="field-note">Container names belong here — sending internal traffic out through the proxy fails in ways that look like broken DNS.</div></label>
      <div class="actions">
        <button class="btn" id="save-proxy">Save</button>
        <button class="btn ghost" id="test-proxy">Check where traffic exits</button>
      </div>
      <div id="proxy-result" style="margin-top:16px"></div>
    </div></div>`;

  $("#save-proxy").addEventListener("click", async () => {
    const body = { proxy_enabled: $("#proxy_enabled").checked, proxy_bypass: $("#proxy_bypass").value };
    const url = $("#proxy_url").value;
    if (url) body.proxy_url = url;
    await api("/settings", { method: "PUT", body });
    toast("Saved");
  });
  $("#test-proxy").addEventListener("click", async (e) => {
    const out = $("#proxy-result");
    out.innerHTML = `<div class="panel" style="margin:0"><div class="skeleton"><i></i><i></i></div></div>`;
    const r = await busy(e.currentTarget, () =>
      api("/test/proxy", { method: "POST", body: { url: $("#proxy_url").value || null } }));
    out.innerHTML = `<div class="grid two">
      <div class="metric"><b style="font-size:17px" class="mono">${esc(r.direct_ip || "—")}</b><span>Without the proxy</span></div>
      <div class="metric ${r.ok ? "ok" : "bad"}"><b style="font-size:17px" class="mono">${esc(r.proxy_ip || "—")}</b><span>Through the proxy</span></div>
    </div><div class="notice ${r.ok ? "good" : "bad"}" style="margin-top:14px">${esc(r.detail)}</div>`;
  });
}

/* ================================================================= test */
async function viewTest(el) {
  el.innerHTML =
    head("Scan text", "Paste text and see exactly what the gateway would find in it. Nothing is sent to a chat model here.") +
    `<div class="panel"><div class="panel-body">
      <label class="field"><span>Text</span>
        <textarea id="t-text" class="mono" style="min-height:150px">Priya Raghunathan, PAN ABCPE1234F, Aadhaar 3456 7890 1238, mobile 9876543210, UPI priya@okhdfcbank, logged in from 203.0.113.45.
Mohammed Ashraf, PAN BZTPK5678L, Aadhaar 7890 1234 5674, mobile 9123456780, from 10.4.18.9 on device 00:1A:2B:3C:4D:5E.
Joint holder Lakshmi Narayanan, A/c 50100234567890 IFSC HDFC0001234, 12/3 Kalpana Nivas, Jayanagar, Bengaluru 560041.</textarea></label>
      <div class="actions">
        <label class="toggle"><input type="checkbox" id="t-llm" checked><span class="switch"></span><span>Include the detection model</span></label>
        <button class="btn" id="t-run">Detect</button>
      </div>
    </div></div>
    <div id="t-out"></div>`;

  $("#t-run").addEventListener("click", async () => {
    const out = $("#t-out");
    const btn = $("#t-run");
    out.innerHTML = `<div class="panel"><div class="skeleton"><i></i><i></i><i></i></div></div>`;
    const text = $("#t-text").value;
    let r;
    try { r = await busy(btn, () => api("/test/detect", { method: "POST", body: { text, use_llm: $("#t-llm").checked } })); }
    catch (e) { out.innerHTML = `<div class="notice bad">${esc(e.message)}</div>`; return; }
    let html = "", cursor = 0;
    r.results.forEach((m) => {
      if (m.start < cursor) return;
      html += esc(text.slice(cursor, m.start));
      html += `<mark class="hit">${esc(m.text)}</mark>`;
      cursor = m.end;
    });
    html += esc(text.slice(cursor));
    out.innerHTML = `<div class="panel">
      <div class="panel-head"><h3>${r.count} found</h3></div>
      <div class="panel-body"><div class="preview">${html}</div></div>
      ${table(
        [
          { label: "Type", cell: (m) => `<code>${esc(m.entity_type)}</code>` },
          { label: "Text", cell: (m) => `<code>${esc(m.text)}</code>` },
          { label: "Score", num: true, cell: (m) => `<div style="display:flex;align-items:center;gap:8px;justify-content:flex-end"><span>${m.score}</span><span class="bar"><i style="width:${Math.round(m.score * 100)}%"></i></span></div>` },
          { label: "Position", num: true, cell: (m) => `${m.start}–${m.end}` },
        ],
        r.results,
        "Nothing detected."
      )}</div>`;
  });
}

/* ============================================================= api keys */
async function viewKeys(el) {
  const [data, routes] = await Promise.all([
    api("/keys"),
    isAdmin() ? api("/routes").catch(() => []) : Promise.resolve([]),
  ]);
  el.innerHTML =
    head("API keys", "Keys your apps use to reach Avron. They are not your OpenAI or provider keys — Avron adds the real one for you.") +
    (data.required
      ? `<div class="notice good">A key is needed to use Avron. Requests without one are turned away.</div>`
      : `<div class="notice warn">No key is needed right now, so <strong>anyone who can reach this server can use it</strong> — and spend on your provider account. Create a key, put it in your apps, then switch this on.</div>`) +
    (isAdmin()
      ? `<div class="panel"><div class="panel-body">
          <label class="toggle"><input type="checkbox" id="require-key" ${data.required ? "checked" : ""}><span class="switch"></span>
          <span>Ask every app for a key</span></label>
          <div class="field-note">Any app not sending a key stops working the moment you switch this on. Set them up first.</div>
        </div></div>`
      : "") +
    `<div class="actions" style="margin-bottom:14px"><button class="btn" id="add-key">Create a key</button></div>
     <div class="panel">${table(
       [
         { label: "Name", cell: (k) => esc(k.name) + (k.mine ? "" : ` <span class="tag">${esc(k.owner)}</span>`) },
         { label: "Key", cell: (k) => `<code>${esc(k.prefix)}</code>` },
         { label: "Can use", cell: (k) => (k.routes.length ? k.routes.map((r) => `<span class="tag">${esc(r)}</span>`).join(" ") : '<span class="field-note" style="margin:0">all endpoints</span>') },
         { label: "Uses", num: true, cell: (k) => k.uses },
         { label: "Last used", cell: (k) => (k.last_used ? `<span class="field-note" style="margin:0">${esc(k.last_used.replace("T", " ").replace("+00:00", ""))}</span>` : "—") },
         { label: "Expires", cell: (k) => (k.expires_at ? esc(k.expires_at.slice(0, 10)) : "never") },
         { label: "On", cell: (k) => `<label class="toggle"><input type="checkbox" data-key="${k.id}" ${k.enabled ? "checked" : ""}><span class="switch"></span></label>` },
         { label: "", cell: (k) => `<button class="btn danger small" data-revoke="${k.id}">Delete</button>` },
       ],
       data.keys,
       "No keys yet."
     )}</div>`;

  $("#require-key")?.addEventListener("change", async (e) => {
    try {
      await api("/settings", { method: "PUT", body: { require_client_key: e.target.checked } });
      toast(e.target.checked ? "A key is now required" : "Keys are optional again");
      go("keys");
    } catch (err) { e.target.checked = !e.target.checked; toast(err.message, true); }
  });

  $("#add-key").addEventListener("click", () =>
    openModal({
      title: "Create a key",
      body: `<label class="field"><span>Name</span>
          <input type="text" name="name" placeholder="Support bot, staging, Priya's laptop">
          <div class="field-note">So you know which app it belongs to when you come to turn it off.</div></label>
        <label class="field"><span>Expires after</span>
          <select name="expires">
            <option value="">Never</option>
            <option value="30">30 days</option>
            <option value="90">90 days</option>
            <option value="365">A year</option>
          </select></label>
        ${routes.length ? `<label class="field"><span>Only allow these endpoints</span>
          <div class="field-note" style="margin:0 0 8px">Leave everything unticked to allow all of them.</div></label>
          <div class="checks">${routes.map((r) => `<label><input type="checkbox" name="scope" value="${esc(r.prefix)}"> <span class="mono">${esc(r.prefix)}</span></label>`).join("")}</div>` : ""}`,
      onSave: async (form) => {
        const r = await api("/keys", {
          method: "POST",
          body: {
            name: form.name.value,
            expires_days: form.expires.value ? Number(form.expires.value) : null,
            routes: $$('[name="scope"]:checked', form).map((c) => c.value),
          },
        });
        return () => showKey(r.key);
      },
    })
  );

  $$("[data-key]", el).forEach((cb) =>
    cb.addEventListener("change", async () => {
      try {
        await api("/keys/" + cb.dataset.key, { method: "PUT", body: { enabled: cb.checked } });
        toast(cb.checked ? "Key enabled" : "Key disabled");
      } catch (e) { cb.checked = !cb.checked; toast(e.message, true); }
    })
  );
  $$("[data-revoke]", el).forEach((b) =>
    b.addEventListener("click", async () => {
      if (!confirm("Delete this key? Any app using it stops working straight away.")) return;
      await api("/keys/" + b.dataset.revoke, { method: "DELETE" });
      toast("Key deleted");
      go("keys");
    })
  );
}

function showKey(key) {
  const wrap = document.createElement("div");
  wrap.className = "backdrop";
  wrap.innerHTML = `<div class="modal" role="dialog" aria-modal="true">
    <div class="modal-head">Your new key</div>
    <div class="modal-body">
      <div class="notice bad">Copy this now — you will not see it again. Avron keeps only a scrambled version and cannot show you the original.</div>
      <label class="field"><span>Key</span>
        <input type="text" class="mono" id="new-key" readonly value="${esc(key)}"></label>
      <label class="field"><span>Paste this into your app</span>
        <textarea class="mono" readonly style="min-height:96px">curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer ${esc(key)}" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'</textarea></label>
    </div>
    <div class="modal-foot">
      <button class="btn ghost" id="copy-key">Copy key</button>
      <button class="btn" id="done-key">I have saved it</button>
    </div></div>`;
  modalRoot.replaceChildren(wrap);
  $("#new-key", wrap).select();
  $("#copy-key", wrap).addEventListener("click", async () => {
    const input = $("#new-key", wrap);
    input.select();
    try { await navigator.clipboard.writeText(key); toast("Copied"); }
    catch { document.execCommand("copy"); toast("Copied"); }
  });
  $("#done-key", wrap).addEventListener("click", () => {
    modalRoot.replaceChildren();
    go("keys");
  });
}

/* ================================================================ users */
async function viewUsers(el) {
  const users = await api("/users");
  el.innerHTML =
    head("Users", "Administrators can change anything. Members can only manage their own API keys and password.") +
    `<div class="actions" style="margin-bottom:14px"><button class="btn" id="add-user">Add someone</button></div>
     <div class="panel">${table(
       [
         { label: "Username", cell: (u) => esc(u.username) + (u.must_change ? " " + pill("warn", "must change password") : "") },
         { label: "Role", cell: (u) => (u.role === "admin" ? pill("info", "administrator") : pill("idle", "member")) },
         { label: "Added", cell: (u) => `<span class="field-note" style="margin:0">${esc(u.created_at.slice(0, 10))}</span>` },
         { label: "", cell: (u) => `<button class="btn danger small" data-del="${u.id}">Remove</button>` },
       ],
       users
     )}</div>`;

  $("#add-user").addEventListener("click", () =>
    openModal({
      title: "Add someone",
      body: `<label class="field"><span>Username</span><input type="text" name="username"></label>
             <label class="field"><span>Password</span><input name="password" type="password">
             <div class="field-note">At least 12 characters. Share it with them directly; it is not shown again.</div></label>
             <label class="field"><span>Role</span>
               <select name="role">
                 <option value="user">Member — own API keys and password only</option>
                 <option value="admin">Administrator — everything</option>
               </select></label>`,
      onSave: async (form) => {
        await api("/users", { method: "POST", body: { username: form.username.value, password: form.password.value, role: form.role.value } });
        toast("Added");
        go("users");
      },
    })
  );
  $$("[data-del]", el).forEach((b) =>
    b.addEventListener("click", async () => {
      if (!confirm("Remove this person?")) return;
      await api("/users/" + b.dataset.del, { method: "DELETE" });
      toast("Removed");
      go("users");
    })
  );
}

/* ============================================================= activity */
async function viewActivity(el) {
  const tab = state.cache.auditTab || "requests";
  el.innerHTML =
    head("Audit log", "Recent requests and every configuration change.") +
    `<div class="actions" style="margin-bottom:16px">
      <button class="btn ${tab === "requests" ? "" : "ghost"}" data-tab="requests">Requests</button>
      <button class="btn ${tab === "changes" ? "" : "ghost"}" data-tab="changes">Configuration changes</button>
     </div><div id="audit-body"></div>`;

  $$("[data-tab]", el).forEach((b) =>
    b.addEventListener("click", () => {
      state.cache.auditTab = b.dataset.tab;
      go("activity");
    })
  );

  const body = $("#audit-body", el);
  if (tab === "changes") return renderChanges(body);
  return renderRequests(body);
}

async function renderChanges(el) {
  const d = await api("/audit");
  const rows = d.entries;
  el.innerHTML =
    `<div class="panel"><div class="panel-body">
      <div class="grid two" style="max-width:560px">
        <label class="field" style="margin:0"><span>Keep changes for</span>
          <div class="input-row">
            <input type="number" id="audit-days" min="1" max="3650" value="${esc(d.days)}">
            <span class="field-note" style="margin:0;align-self:center">days</span>
          </div></label>
        <label class="field" style="margin:0"><span>Never keep more than</span>
          <div class="input-row">
            <input type="number" id="audit-limit" min="100" max="200000" step="100" value="${esc(d.limit)}">
            <span class="field-note" style="margin:0;align-self:center">entries</span>
          </div></label>
      </div>
      <div class="actions" style="margin-top:14px">
        <button class="btn" id="audit-save">Save</button>
        <span class="field-note" style="margin:0">${d.total} stored now</span>
      </div>
    </div></div>` +
    `<div class="panel">${table(
    [
      { label: "When", cell: (r) => `<span class="field-note" style="margin:0">${esc(r.ts.replace("T", " ").replace("+00:00", ""))}</span>` },
      { label: "Who", cell: (r) => esc(r.actor) },
      { label: "What", cell: (r) => `<span class="tag">${esc(r.action)}</span>` },
      { label: "Detail", cell: (r) => `<span class="field-note" style="margin:0">${esc(r.detail).slice(0, 110)}</span>` },
    ],
    rows,
    "Nothing recorded yet."
  )}</div>`;

  $("#audit-save").addEventListener("click", async (e) => {
    await busy(e.currentTarget, () =>
      api("/settings", {
        method: "PUT",
        body: {
          audit_days: $("#audit-days").value,
          audit_limit: $("#audit-limit").value,
        },
      })
    );
    toast("Saved");
    go("activity");
  });
}

async function renderRequests(el) {
  const d = await api("/captures");
  el.innerHTML =
    (d.enabled
      ? `<div class="notice warn">Recording is <strong>on</strong>. The text of each request is stored, unmasked, for ${esc(d.days)} day${d.days === "1" ? "" : "s"} — the real names and numbers, not the placeholders. Turn it off when you have finished debugging.</div>`
      : `<div class="notice">Recording is off, so only totals are kept. Switch it on to see what a request actually looked like going out and coming back.</div>`) +
    `<div class="panel"><div class="panel-body">
      <label class="toggle" style="margin-bottom:16px"><input type="checkbox" id="cap-on" ${d.enabled ? "checked" : ""}><span class="switch"></span>
        <span>Record requests</span></label>
      <div class="grid two" style="max-width:560px">
        <label class="field" style="margin:0"><span>Keep requests for</span>
          <div class="input-row">
            <input type="number" id="cap-days" min="1" max="365" value="${esc(d.days)}">
            <span class="field-note" style="margin:0;align-self:center">days</span>
          </div>
          <div class="field-note">These hold real names and numbers. Keep it short.</div></label>
        <label class="field" style="margin:0"><span>Never keep more than</span>
          <div class="input-row">
            <input type="number" id="cap-limit" min="10" max="20000" step="10" value="${esc(d.limit)}">
            <span class="field-note" style="margin:0;align-self:center">requests</span>
          </div>
          <div class="field-note">A ceiling so a busy day cannot fill the disk.</div></label>
      </div>
      <div class="actions" style="margin-top:14px">
        <button class="btn" id="cap-save">Save</button>
        <button class="btn ghost" id="cap-purge">Delete everything recorded</button>
      </div>
    </div></div>
    <div class="panel">
      <div class="panel-head"><h3>Recent requests</h3><span class="hint">click a row to see it</span></div>
      ${table(
        [
          { label: "When", cell: (c) => `<span class="field-note" style="margin:0">${esc(c.ts.slice(11, 19))}</span>` },
          { label: "Endpoint", cell: (c) => `<code>${esc(c.route)}</code>` },
          { label: "Provider", cell: (c) => esc(c.provider) },
          { label: "Model", cell: (c) => `<code>${esc(c.model || "—")}</code>` },
          { label: "Status", cell: (c) => (c.status === 0 ? pill("bad", "failed") : c.status >= 400 ? pill("bad", c.status) : pill("ok", c.status)) },
          { label: "Masked", num: true, cell: (c) => c.masked },
          { label: "Tokens", num: true, cell: (c) => (c.tokens_in + c.tokens_out) || "—" },
          { label: "Time", num: true, cell: (c) => `${c.ms} ms` },
          { label: "", cell: (c) => `<button class="btn ghost small" data-cap="${c.id}">Open</button>` },
        ],
        d.captures,
        d.enabled
          ? "Nothing recorded yet. Send a request through an endpoint, or run something in the Playground."
          : "Recording is off. Switch it on above, then send a request."
      )}
    </div>`;

  $("#cap-on").addEventListener("change", async (e) => {
    try {
      await api("/settings", { method: "PUT", body: { capture_enabled: e.target.checked } });
      toast(e.target.checked ? "Recording on" : "Recording off");
      go("activity");
    } catch (err) { e.target.checked = !e.target.checked; toast(err.message, true); }
  });
  $("#cap-save").addEventListener("click", async (e) => {
    await busy(e.currentTarget, () =>
      api("/settings", {
        method: "PUT",
        body: { capture_days: $("#cap-days").value, capture_limit: $("#cap-limit").value },
      })
    );
    toast("Saved");
    go("activity");
  });
  $("#cap-purge").addEventListener("click", async (e) => {
    if (!confirm("Delete every recorded request?")) return;
    const r = await busy(e.currentTarget, () => api("/captures", { method: "DELETE" }));
    toast(`Deleted ${r.deleted}`);
    go("activity");
  });
  $$("[data-cap]", el).forEach((b) =>
    b.addEventListener("click", () => openCapture(b.dataset.cap))
  );
}

function textOf(payload) {
  /* Pull the readable part out of a chat body so the panels are not a wall
     of JSON. Falls back to the whole object when the shape is unfamiliar. */
  if (!payload) return "";
  if (typeof payload === "string") return payload;
  if (Array.isArray(payload.messages)) {
    return payload.messages
      .map((m) => {
        const c = typeof m.content === "string"
          ? m.content
          : Array.isArray(m.content)
          ? m.content.filter((x) => x.type === "text").map((x) => x.text).join("\n")
          : JSON.stringify(m.content);
        return `${m.role}: ${c}`;
      })
      .join("\n\n");
  }
  if (payload.streamed && typeof payload.content === "string") {
    return payload.content || "(the stream ended before any text arrived)";
  }
  if (payload.note) return payload.note;
  const choice = payload.choices?.[0]?.message;
  if (choice) return choice.content ?? JSON.stringify(choice, null, 2);
  if (payload.error) return typeof payload.error === "string" ? payload.error : JSON.stringify(payload.error, null, 2);
  return JSON.stringify(payload, null, 2);
}

async function openCapture(id) {
  let c;
  try { c = await api("/captures/" + id); }
  catch (e) { return toast(e.message, true); }

  const hl = (t) => esc(t).replace(/&lt;[A-Z][A-Z0-9_]*_\d+&gt;/g, (m) => `<mark class="ph">${m}</mark>`);
  const wrap = document.createElement("div");
  wrap.className = "backdrop";
  wrap.innerHTML = `<div class="modal" style="max-width:920px" role="dialog" aria-modal="true">
    <div class="modal-head">Request at ${esc(c.ts.replace("T", " ").replace("+00:00", ""))}</div>
    <div class="modal-body">
      <div class="grid four" style="margin-bottom:16px">
        <div class="metric info"><b>${c.masked}</b><span>Values masked</span></div>
        <div class="metric"><b>${c.ms}</b><span>Milliseconds</span></div>
        <div class="metric"><b>${(c.tokens_in + c.tokens_out) || "—"}</b><span>Tokens</span></div>
        <div class="metric"><b style="font-size:14px">${esc(c.provider)}</b><span>Provider</span></div>
      </div>
      <div class="field-note" style="margin-bottom:14px">
        <code>${esc(c.route)}</code> · model <code>${esc(c.model || "—")}</code> ·
        ${c.tokens_in} in / ${c.tokens_out} out${c.key_name ? ` · key ${esc(c.key_name)}` : ""}
      </div>
      <div class="pg">
        <div>
          <div class="stage mono"><header>What you sent<span>unmasked</span></header>
            <div>${esc(textOf(c.req_raw))}</div></div>
          <div class="stage mono"><header>What the model got<span>masked</span></header>
            <div>${hl(textOf(c.req_masked))}</div></div>
        </div>
        <div>
          <div class="stage mono"><header>What the model replied<span>${c.resp_raw?.streamed ? "streamed, masked" : "masked"}</span></header>
            <div>${hl(textOf(c.resp_raw))}</div></div>
          <div class="stage mono"><header>What your app got back<span>restored</span></header>
            <div>${esc(textOf(c.resp_restored))}</div></div>
        </div>
      </div>
      <div class="stage"><header>Placeholders</header>
        ${table(
          [
            { label: "Token", cell: (x) => `<mark class="ph">${esc(x.token)}</mark>` },
            { label: "Real value", cell: (x) => `<code>${esc(x.value)}</code>` },
          ],
          c.placeholders || [],
          "Nothing was detected in this request."
        )}</div>
    </div>
    <div class="modal-foot"><button class="btn" id="cap-close">Close</button></div>
  </div>`;
  modalRoot.replaceChildren(wrap);
  const close = () => modalRoot.replaceChildren();
  $("#cap-close", wrap).addEventListener("click", close);
  wrap.addEventListener("click", (e) => { if (e.target === wrap) close(); });
  document.addEventListener("keydown", function onKey(e) {
    if (e.key === "Escape") { close(); document.removeEventListener("keydown", onKey); }
  });
}

/* ============================================================== account */
async function viewAccount(el) {
  el.innerHTML =
    head("Your account", "Change the password for " + state.user.username + ".") +
    (state.user.must_change ? `<div class="notice bad">This account still uses the password printed at first run. Change it now.</div>` : "") +
    `<div class="panel"><div class="panel-body" style="max-width:400px">
      <label class="field"><span>Current password</span><input type="password" id="p-old" autocomplete="current-password"></label>
      <label class="field"><span>New password</span><input type="password" id="p-new" autocomplete="new-password">
        <div class="field-note">At least 12 characters.</div></label>
      <button class="btn" id="p-save">Change password</button>
    </div></div>`;

  $("#p-save").addEventListener("click", async () => {
    try {
      await api("/account/password", {
        method: "POST",
        body: { current_password: $("#p-old").value, new_password: $("#p-new").value },
      });
      state.user.must_change = false;
      toast("Password changed");
      go("account");
    } catch (err) { toast(err.message, true); }
  });
}

/* ================================================================ modal */
function openModal({ title, body, extra = "", onSave, onReady, wide }) {
  const wrap = document.createElement("div");
  wrap.className = "backdrop";
  wrap.innerHTML = `<div class="modal" style="${wide ? "max-width:780px" : ""}" role="dialog" aria-modal="true">
    <div class="modal-head">${esc(title)}</div>
    <form id="modal-form"><div class="modal-body">${body}${extra}</div>
    <div class="modal-foot">
      <button type="button" class="btn ghost" id="modal-cancel">Cancel</button>
      <button type="submit" class="btn">Save</button>
    </div></form></div>`;
  modalRoot.replaceChildren(wrap);

  const close = () => modalRoot.replaceChildren();
  $("#modal-cancel", wrap).addEventListener("click", close);
  wrap.addEventListener("click", (e) => { if (e.target === wrap) close(); });
  document.addEventListener("keydown", function onKey(e) {
    if (e.key === "Escape") { close(); document.removeEventListener("keydown", onKey); }
  });

  const form = $("#modal-form", wrap);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const button = form.querySelector('[type="submit"]');
    button.disabled = true;
    try {
      // onSave may return a function to run once this dialog is gone — used
      // when one dialog hands off to another, like the new-key reveal.
      const next = await onSave(form);
      close();
      if (typeof next === "function") next();
    } catch (err) {
      toast(err.message, true);
      button.disabled = false;
    }
  });
  if (onReady) onReady(form);
  // Focus here rather than with the autofocus attribute: the browser blocks
  // autofocus when something is already focused, which it always is after a
  // button click.
  form.querySelector("input, select, textarea")?.focus();
}

/* Marks a button busy for the duration of an async action. The CSS attaches
   a spinner to [data-busy], so callers do not manage markup. */
async function busy(button, fn) {
  const label = button.textContent;
  button.dataset.busy = "1";
  button.disabled = true;
  try { return await fn(); }
  finally {
    delete button.dataset.busy;
    button.disabled = false;
    button.textContent = label;
  }
}

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

/* ================================================================= boot */
async function boot() {
  try {
    state.user = await api("/me");
    // Pick the landing view before the shell renders. Calling go() afterwards
    // starts a second render that races the first one.
    if (state.user.must_change) state.view = "account";
    else if (!isAdmin()) state.view = "keys";
    renderShell();
  } catch { renderLogin(); }
}

boot();
