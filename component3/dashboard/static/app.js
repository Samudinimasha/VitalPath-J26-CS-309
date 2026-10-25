// Component 3 demonstration website: live view of the real pipeline.
(function () {
  "use strict";

  const state = { events: [], stats: {}, incident: null, settings: {}, filter: "all" };
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const clock = (t) => new Date(t * 1000).toLocaleTimeString([], { hour12: false });

  const INJECTED = {
    replay: "replay", handover: "handover replay", "handover-next": "after handover",
    tamper: "tampered", "tamper-original": "original", case_swap: "case swap", "case_swap-original": "original",
    jump: "fake jump", stale: "stale", future: "future", malformed: "malformed", flood: "flood",
    hr300: "HR 300", probe_off: "probe off", shock: "shock",
  };
  const CLINICAL = ["hr300", "probe_off", "shock"];

  const ALERTS = {
    "R-REPLAY-DUPLICATE": ["REPLAY DETECTED", "This packet ID was already received earlier in the case. Discarded before delivery; the hospital stream is unaffected."],
    "R-REPLAY-OUTSIDE-WINDOW": ["REPLAY DETECTED", "This packet ID is far older than anything still accepted. Discarded before delivery."],
    "R-TS-STALE": ["STALE PACKET REJECTED", "The packet's timestamp is more than 30 seconds old. Discarded before delivery."],
    "R-TS-FUTURE": ["FUTURE-DATED PACKET REJECTED", "The packet is stamped more than 2 seconds in the future. Discarded before delivery."],
    "R-TS-REGRESSION": ["OUT-OF-TIME PACKET REJECTED", "The packet's time falls behind newer packets beyond the 1 second tolerance."],
    "R-MALFORMED-HEADER": ["MALFORMED PACKET", "The packet header is damaged or unreadable. Discarded before delivery."],
    "R-DECRYPT-FAILED": ["TAMPERING DETECTED", "The seal is broken: the packet was altered or forged. Discarded; the genuine packet is unaffected."],
    "R-PAYLOAD-MALFORMED": ["BAD PAYLOAD", "The decrypted data is not a valid vital-sign record."],
    "R-RATE-LIMIT": ["FLOOD BLOCKED", "More than 20 packets per second from this device. Excess packets dropped before any other check."],
  };

  // ---------------------------------------------------------------- vitals
  const VITALS = [
    ["hr", "HR", "bpm"], ["spo2", "SpO₂", "%"], ["bp", "BP", "mmHg"], ["resp", "RESP", "/min"], ["pulse", "PULSE", "bpm"],
  ];
  const RANK = { normal: 1, borderline: 2, critical: 3, invalid: 3 };

  function renderVitals() {
    const ev = [...state.events].reverse().find((e) => e.vitals);
    $("vitals").innerHTML = VITALS.map(([key, label, unit]) => {
      let value = "—", band = "no reading";
      if (ev) {
        const v = ev.vitals, b = ev.bands || {};
        if (key === "bp") {
          if (v.sbp != null && v.dbp != null) {
            value = `${fmt(v.sbp)}/${fmt(v.dbp)}`;
            band = (RANK[b.sbp] || 0) >= (RANK[b.dbp] || 0) ? b.sbp : b.dbp;
          }
        } else if (v[key] != null) {
          value = fmt(v[key]);
          band = key === "pulse" ? "cross-check" : (b[key] || "");
        }
      }
      return `<div class="vital ${esc(band)}"><div class="label">${label} ${unit}</div>` +
        `<div class="value">${esc(value)}</div><div class="band">${esc(String(band).toUpperCase())}</div></div>`;
    }).join("");
  }
  const fmt = (n) => (Math.round(n * 10) / 10).toString();

  // ---------------------------------------------------------------- trace
  function renderTrace() {
    const canvas = $("trace");
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = 150;
    canvas.width = w * dpr; canvas.height = h * dpr;
    canvas.style.height = h + "px";
    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);
    const css = getComputedStyle(document.documentElement);
    const ink = css.getPropertyValue("--ink"), line = css.getPropertyValue("--line"),
      muted = css.getPropertyValue("--muted"), amber = css.getPropertyValue("--amber"), red = css.getPropertyValue("--red");
    const evs = state.events.slice(-60);
    const hrs = evs.filter((e) => e.vitals && e.vitals.hr != null).map((e) => e.vitals.hr);
    let lo = Math.min(50, ...hrs), hi = Math.max(130, ...hrs);
    lo = Math.floor(lo / 10) * 10; hi = Math.ceil(hi / 10) * 10;
    const left = 34, right = w - 8, top = 8, bottom = h - 22;
    const x = (i) => left + (evs.length < 2 ? 0 : (i / 59) * (right - left));
    const y = (v) => bottom - ((v - lo) / (hi - lo)) * (bottom - top);
    ctx.font = "11px " + css.getPropertyValue("--mono");
    ctx.fillStyle = muted; ctx.strokeStyle = line; ctx.lineWidth = 1;
    const step = hi - lo > 150 ? 50 : 20;
    for (let v = Math.ceil(lo / step) * step; v <= hi; v += step) {
      ctx.beginPath(); ctx.moveTo(left, y(v)); ctx.lineTo(right, y(v)); ctx.stroke();
      ctx.fillText(String(v), 2, y(v) + 4);
    }
    evs.forEach((e, i) => {
      if (e.decision === "DISCARD") {
        ctx.strokeStyle = red; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.moveTo(x(i), bottom + 4); ctx.lineTo(x(i), bottom + 16); ctx.stroke();
      }
    });
    ctx.strokeStyle = ink; ctx.lineWidth = 2; ctx.beginPath();
    let started = false;
    evs.forEach((e, i) => {
      if (!(e.vitals && e.vitals.hr != null)) return;
      const px = x(i), py = y(e.vitals.hr);
      if (!started) { ctx.moveTo(px, py); started = true; } else { ctx.lineTo(px, py); }
    });
    ctx.stroke();
    evs.forEach((e, i) => {
      if (e.decision === "FLAG" && e.vitals && e.vitals.hr != null) {
        ctx.fillStyle = e.label === "Flagged" ? red : amber;
        ctx.beginPath(); ctx.arc(x(i), y(e.vitals.hr), 4, 0, Math.PI * 2); ctx.fill();
      }
    });
  }

  // ---------------------------------------------------------------- table
  const FILTERS = {
    all: () => true,
    discard: (e) => e.decision === "DISCARD",
    flag: (e) => e.decision === "FLAG",
    replay: (e) => e.replay === "dropped",
    range: (e) => e.rules.some((r) => /^R-(HR|SPO2|SBP|DBP|RESP)-/.test(r)),
    corr: (e) => e.rules.some((r) => r.startsWith("R-CORR")),
  };

  function rowHtml(e, fresh) {
    const reason = e.rules.length ? esc(e.rules.join(", ")) : "—";
    const detail = e.decision === "DISCARD" && e.detail ? ` <span class="detail">${esc(e.detail)}</span>` : "";
    const inj = e.injected ? `<span class="tag">${esc(INJECTED[e.injected] || e.injected)}</span>` : "";
    const cls = (e.decision === "DISCARD" ? "r-discard" : "") + (fresh ? " fresh" : "");
    return `<tr class="${cls}" data-id="${e.id}"><td>${clock(e.t)}</td><td>${esc(e.packet_id)}</td>` +
      `<td class="rp-${esc(e.replay || "")}">${esc(e.replay || "—")}</td>` +
      `<td class="d-${esc(e.decision)}">${esc(e.decision)}${e.label ? " · " + esc(e.label) : ""}</td>` +
      `<td>${e.score == null ? "" : e.score}</td><td class="reason">${reason}${detail}</td><td>${inj}</td></tr>` +
      subRowHtml(e, cls);
  }

  // Lines under each packet, like the terminal receiver: what decryption read,
  // then the points behind a flag.
  function subRowHtml(e, cls) {
    let read;
    if (e.vitals) {
      read = `decrypted and read: ${esc(vitalsLine(e.vitals))}`;
    } else if (e.decrypted === false && e.decision === "DISCARD" && e.replay === "accepted") {
      read = "decryption failed: seal broken, contents not trusted";
    } else {
      read = "not decrypted: stopped before anyone looked inside";
    }
    const pts = (e.points || []).map((p) => `<div class="pts">+${p.points}&nbsp; ${esc(p.rule)}: ${esc(p.reason)}</div>`).join("");
    return `<tr class="sub ${cls}" data-id="${e.id}"><td></td><td colspan="6"><div class="read">${read}</div>${pts}</td></tr>`;
  }

  function vitalsLine(v) {
    const parts = [];
    if (v.hr != null) parts.push(`HR ${fmt(v.hr)}`);
    if (v.pulse != null) parts.push(`pulse ${fmt(v.pulse)}`);
    if (v.spo2 != null) parts.push(`SpO2 ${fmt(v.spo2)}%`);
    if (v.sbp != null && v.dbp != null) parts.push(`BP ${fmt(v.sbp)}/${fmt(v.dbp)}`);
    if (v.resp != null) parts.push(`RESP ${fmt(v.resp)}`);
    return parts.join(" · ");
  }

  function renderRows(freshIds) {
    const f = FILTERS[state.filter];
    const rows = state.events.filter(f).slice(-120).reverse();
    $("rows").innerHTML = rows.map((e) => rowHtml(e, freshIds && freshIds.has(e.id))).join("") ||
      `<tr><td colspan="7" class="detail">No packets match this filter yet.</td></tr>`;
  }

  // ---------------------------------------------------------------- alert + stats
  function renderAlert() {
    const e = [...state.events].reverse().find((x) => x.decision === "DISCARD" || x.label === "Flagged");
    const box = $("alert");
    if (!e) {
      box.className = "card alert ok";
      $("alert-title").textContent = "ALL CLEAR";
      $("alert-text").textContent = "No packet has been discarded or flagged yet.";
      $("alert-meta").innerHTML = "";
      return;
    }
    let title, text;
    if (e.decision === "DISCARD") {
      [title, text] = ALERTS[e.rules[0]] || ["PACKET DISCARDED", e.detail];
      box.className = "card alert bad";
    } else {
      title = "FLAGGED FOR CLINICIAN";
      text = "Delivered with a warning. " + e.points.map((p) => `+${p.points} ${p.reason}`).join("; ");
      box.className = "card alert warn";
    }
    $("alert-title").textContent = title;
    $("alert-text").textContent = text;
    $("alert-meta").innerHTML = [
      `${esc(e.packet_id)} · ${esc(e.device)} · ${esc(e.case)}`,
      `rule ${esc(e.rules.join(", "))}`,
      e.decision === "DISCARD" ? (e.decrypted ? "payload decrypted, seal failed" : "payload never decrypted") : `score ${e.score}`,
      clock(e.t),
    ].map((l) => `<span>${l}</span>`).join("");
  }

  function renderStats() {
    const s = state.stats;
    const rows = [
      ["Packets checked", s.packets], ["Accepted", s.accepted], ["Flagged", s.flagged], ["Discarded", s.discarded],
      ["Discarded without decryption", s.discarded_unopened],
      ["Mean check latency", `${s.mean_ms} ms`], ["99th percentile latency", `${s.p99_ms} ms`], ["Budget", "20 ms"],
    ];
    $("stats").innerHTML = rows.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v == null ? "—" : v)}</dd>`).join("");
    const st = state.settings;
    $("settings").innerHTML = [
      ["Replay window", `${st.window} packet IDs`], ["Max packet age", `${st.max_age_s} s`],
      ["Future skew allowed", `${st.future_skew_s} s`], ["Out-of-order tolerance", `${st.backward_tolerance_s} s`],
      ["Flood limit", st.rate_limit],
    ].map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join("");
  }

  // ---------------------------------------------------------------- buttons
  function renderButtons(attacks, source) {
    if (!Object.keys(attacks).length) {
      document.querySelectorAll(".side-col .sub").forEach((el) => (el.hidden = true));
      $("attack-buttons").innerHTML =
        `<p class="sub-note" style="margin:0">Listening to the ambulance sender on <b>${esc(source)}</b>. ` +
        `Attacks come from the sender: start it with <code>--attacks</code> in another terminal. ` +
        `A pause of 2 s or more appears as a handover on the Handover incident tab.</p>`;
      $("clinical-buttons").innerHTML = "";
      return;
    }
    const make = (names, cls) => names.map((n) =>
      `<button class="btn ${cls}" data-attack="${esc(n)}">${esc(attacks[n])}</button>`).join("");
    const names = Object.keys(attacks);
    $("attack-buttons").innerHTML = make(names.filter((n) => !CLINICAL.includes(n)), "attack");
    $("clinical-buttons").innerHTML = make(names.filter((n) => CLINICAL.includes(n)), "clinical");
    document.querySelectorAll("[data-attack]").forEach((b) => b.addEventListener("click", () => fire(b.dataset.attack)));
  }

  function fire(name) {
    const buttons = document.querySelectorAll("[data-attack]");
    buttons.forEach((b) => (b.disabled = true));
    $("busy").textContent = name === "handover" ? "link down 3 s…" : "sending…";
    fetch("/api/attack/" + encodeURIComponent(name), { method: "POST" }).catch(() => {});
    setTimeout(() => {
      buttons.forEach((b) => (b.disabled = false));
      $("busy").textContent = "";
    }, name === "handover" ? 3800 : name === "flood" ? 1600 : 700);
  }

  // ---------------------------------------------------------------- drawer
  const ICON = { ok: "✓", warn: "!", bad: "✗", skip: "–" };
  function openDrawer(id) {
    const e = state.events.find((x) => x.id === id);
    if (!e) return;
    $("d-title").textContent = e.packet_id;
    const stages = e.stages.map(([name, status, text, rule]) =>
      `<div class="stage s-${status}"><span class="icon">${ICON[status]}</span><span class="name">${esc(name)}</span>` +
      `<span class="text">${esc(text)}${rule ? `<span class="rule">${esc(rule)}</span>` : ""}</span></div>`).join("");
    const vitals = e.vitals ? Object.entries(e.vitals).map(([k, v]) => `${k} ${fmt(v)}`).join(" · ") : "not decrypted";
    const verdict = e.decision === "DISCARD" ? "DISCARD: packet dropped, alert logged"
      : e.decision === "ACCEPT" ? "ACCEPT 'Normal': delivered to the hospital"
      : `FLAG '${e.label}' (score ${e.score}): delivered with a warning for the clinician`;
    const points = e.points.length ? `<ul class="points">${e.points.map((p) => `<li>+${p.points}  ${esc(p.rule)}: ${esc(p.reason)}</li>`).join("")}</ul>` : "";
    $("d-body").innerHTML =
      `<dl class="kv mono"><dt>Received</dt><dd>${clock(e.t)}</dd><dt>Device</dt><dd>${esc(e.device)}</dd>` +
      `<dt>Case</dt><dd>${esc(e.case)}</dd><dt>Injected</dt><dd>${esc(e.injected ? INJECTED[e.injected] || e.injected : "none (genuine stream)")}</dd>` +
      `<dt>Vitals read</dt><dd>${esc(vitals)}</dd><dt>Latency</dt><dd>${e.latency_ms} ms</dd></dl>` +
      stages + `<div class="verdict ${esc(e.decision)}">${esc(verdict)}</div>` + points;
    $("drawer").hidden = false;
    $("d-close").focus();
  }
  $("rows").addEventListener("click", (ev) => {
    const tr = ev.target.closest("tr[data-id]");
    if (tr) openDrawer(Number(tr.dataset.id));
  });
  $("d-close").addEventListener("click", () => ($("drawer").hidden = true));
  $("drawer").addEventListener("click", (ev) => { if (ev.target.id === "drawer") $("drawer").hidden = true; });
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") $("drawer").hidden = true; });

  // ---------------------------------------------------------------- incident (Figma 1h)
  function renderIncident() {
    const inc = state.incident;
    if (!inc) {
      $("timeline").innerHTML = `<div class="empty">No handover yet. On the Live detection tab, press “5G handover + replay”.</div>`;
      ["inc-summary", "inc-rejected", "inc-after"].forEach((id) => ($(id).innerHTML = ""));
      ["inc-note", "inc-rejected-note", "inc-after-note", "inc-legend"].forEach((id) => ($(id).innerHTML = ""));
      $("inc-range").textContent = "";
      return;
    }
    const end = inc.end || Date.now() / 1000;
    const t0 = inc.start - 8, t1 = end + 8;
    const evs = state.events.filter((e) => e.t >= t0 && e.t <= t1);
    const W = 1000, H = 150, L = 20, R = 980, axis = 95;
    const x = (t) => L + ((t - t0) / (t1 - t0)) * (R - L);
    const colour = (e) => (e.decision === "DISCARD" ? "var(--red)" : e.decision === "FLAG" && e.label === "Flagged" ? "var(--amber)" : "var(--green)");
    const ticks = evs.map((e) => {
      const tall = e.decision === "DISCARD";
      return `<line x1="${x(e.t)}" x2="${x(e.t)}" y1="${axis - (tall ? 34 : 22)}" y2="${axis + 6}" stroke="${colour(e)}" stroke-width="${tall ? 4 : 3}"><title>${esc(e.packet_id)} ${esc(e.decision)}</title></line>`;
    }).join("");
    const label = (t, anchor) => `<text x="${x(t)}" y="${H - 20}" text-anchor="${anchor}" font-size="13" fill="var(--muted)" font-family="var(--mono)">${clock(t)}</text>`;
    $("timeline").innerHTML =
      `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Packet timeline around the handover">` +
      `<rect x="${x(inc.start)}" y="10" width="${Math.max(2, x(end) - x(inc.start))}" height="${axis - 2}" fill="var(--amber-soft)" stroke="var(--amber)" stroke-dasharray="4 3"/>` +
      `<text x="${x(inc.start) + 6}" y="26" font-size="13" fill="var(--amber)" font-family="var(--mono)">HANDOVER ${inc.gap_s} s</text>` +
      `<line x1="${L}" x2="${R}" y1="${axis}" y2="${axis}" stroke="var(--line)" stroke-width="2"/>` + ticks +
      label(t0, "start") + label((inc.start + end) / 2, "middle") + label(t1, "end") + `</svg>`;
    const counts = { accepted: 0, rejected: 0, flagged: 0 };
    evs.forEach((e) => (e.decision === "DISCARD" ? counts.rejected++ : e.label === "Flagged" ? counts.flagged++ : counts.accepted++));
    $("inc-legend").innerHTML = `<span><i class="sw sw-green"></i>accepted ${counts.accepted}</span>` +
      `<span><i class="sw sw-red"></i>rejected ${counts.rejected}</span><span><i class="sw sw-amber"></i>flagged ${counts.flagged}</span>`;
    $("inc-range").textContent = `${clock(t0)} – ${clock(t1)} · link down shaded`;

    const forged = evs.find((e) => e.injected === "handover");
    const next = evs.find((e) => e.injected === "handover-next");
    $("inc-summary").innerHTML = kv([["unit", "AMB-07"], ["case", "CASE001"], ["device", "MON-01"],
      ["link down", clock(inc.start)], ["duration", `${inc.gap_s} s`], ["type", "replay during handover"]]);
    $("inc-note").innerHTML = `<div class="callout bad">A captured packet was resent while the link re-established. It was rejected before delivery.</div>`;
    if (forged) {
      $("inc-rejected").innerHTML = kv([["packet", forged.packet_id], ["received", clock(forged.t)],
        ["timestamp", "refreshed by attacker"], ["replay check", forged.replay || "—"], ["rule", forged.rules.join(", ")],
        ["decrypted", forged.decrypted ? "yes" : "no"]]);
      $("inc-rejected-note").innerHTML = `<div class="callout plain">Its timestamp looked fresh, but this packet ID had already been accepted, so the Replay Engine rejected it without opening it.</div>`;
    }
    if (next) {
      $("inc-after").innerHTML = kv([["packet", next.packet_id], ["received", clock(next.t)], ["replay check", next.replay],
        ["decision", `${next.decision}${next.label ? " · " + next.label : ""}`]]);
      $("inc-after-note").innerHTML = `<div class="callout ok">The ambulance's real next packet was accepted at once: the replay window is kept per device, so it survived the handover (FR2).</div>`;
    }
  }
  const kv = (pairs) => pairs.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");

  // ---------------------------------------------------------------- tabs, filters
  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => { x.classList.toggle("active", x === t); x.setAttribute("aria-selected", x === t); });
    $("view-live").hidden = t.dataset.view !== "live";
    $("view-incident").hidden = t.dataset.view !== "incident";
    if (t.dataset.view === "incident") renderIncident(); else renderTrace();
  }));
  $("filters").addEventListener("click", (ev) => {
    const b = ev.target.closest("[data-f]");
    if (!b) return;
    state.filter = b.dataset.f;
    document.querySelectorAll("#filters .chip").forEach((c) => c.classList.toggle("active", c === b));
    renderRows();
  });

  // ---------------------------------------------------------------- live data
  let pending = new Set(), scheduled = false;
  function schedule() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      renderRows(pending); pending = new Set();
      renderVitals(); renderAlert();
      if (!$("view-live").hidden) renderTrace();
      if (!$("view-incident").hidden) renderIncident();
    });
  }

  function setStatus(live) {
    $("status").className = "pill " + (live ? "live" : "down");
    $("status-text").textContent = live ? "DETECTION ACTIVE" : "DISCONNECTED";
  }

  function refreshState() {
    return fetch("/api/state").then((r) => r.json()).then((s) => {
      state.stats = s.stats; state.incident = s.incident; state.settings = s.settings;
      $("context").textContent = s.source === "simulated"
        ? `${s.unit} · ${s.case} · ${s.device}` : `${s.case} · ${s.device} · live from ${s.source}`;
      renderStats();
      if (!$("view-incident").hidden) renderIncident();
      return s;
    });
  }

  refreshState().then((s) => {
    state.events = s.events;
    renderButtons(s.attacks, s.source);
    schedule();
    const source = new EventSource("/api/stream");
    source.onopen = () => setStatus(true);
    source.onerror = () => setStatus(false);
    source.onmessage = (msg) => {
      const e = JSON.parse(msg.data);
      state.events.push(e);
      if (state.events.length > 400) state.events.splice(0, state.events.length - 400);
      pending.add(e.id);
      schedule();
    };
    setInterval(refreshState, 2000);
  }).catch(() => setStatus(false));
  window.addEventListener("resize", () => { if (!$("view-live").hidden) renderTrace(); });
})();
