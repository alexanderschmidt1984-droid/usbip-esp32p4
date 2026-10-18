// USB/IP Server WebUI - Application Logic
// Sections: Dashboard, Devices, Topology, Settings
(function() {
    'use strict';

    /* Server requires X-USBIP-CSRF on every non-GET request (CSRF protection).
     * Wrap fetch once so every call - including inline onclick handlers - sends it. */
    (function() {
        var origFetch = window.fetch.bind(window);
        window.fetch = function(url, opts) {
            opts = opts || {};
            var m = (opts.method || 'GET').toUpperCase();
            if (m !== 'GET' && m !== 'HEAD') {
                var h = new Headers(opts.headers || {});
                h.set('X-USBIP-CSRF', '1');
                opts.headers = h;
            }
            return origFetch(url, opts);
        };
    })();

    /* ================================================================
     * Utility functions
     * ================================================================ */

    function formatBytes(b) {
        if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB/s';
        if (b >= 1024) return (b / 1024).toFixed(1) + ' KB/s';
        return Math.round(b) + ' B/s';
    }

    function formatUptime(sec) {
        if (sec < 0 || !isFinite(sec)) return '--';
        var d = Math.floor(sec / 86400);
        var h = Math.floor((sec % 86400) / 3600);
        var m = Math.floor((sec % 3600) / 60);
        if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
        if (h > 0) return h + 'h ' + m + 'm';
        return m + 'm';
    }

    function hex4(v) {
        return ('0000' + v.toString(16)).slice(-4);
    }

    function esc(s) {
        if (!s) return '';
        var d = document.createElement('div');
        d.appendChild(document.createTextNode(s));
        return d.innerHTML;
    }

    /* ================================================================
     * Languages. UI strings are looked up by their source text (as written
     * in index.html / here), help sections are replaced as a whole. The
     * language files come from /lang?l=xx and are only loaded on demand.
     * ================================================================ */

    var LANGS = [['de', 'Deutsch'], ['en', 'English'], ['fr', 'Français'], ['es', 'Español'],
                 ['it', 'Italiano'], ['pt', 'Português'], ['da', 'Dansk'], ['sv', 'Svenska'],
                 ['ru', 'Русский'], ['uk', 'Українська'], ['tr', 'Türkçe'], ['ar', 'العربية']];
    var I18N = { lang: '', ui: {}, help: {} };
    var helpUnits = null;      /* leaf blocks of the help sections, see i18nCaptureHelp */
    var I18N_SKIP = { SCRIPT: 1, STYLE: 1, PRE: 1, CODE: 1, svg: 1, SVG: 1, TEXTAREA: 1 };

    window._t = function(s) { return t(s); };
    function t(s) {
        var v = I18N.ui[s];
        return v === undefined || v === '' ? s : v;
    }

    function i18nSkip(el) {
        for (; el && el !== document.body; el = el.parentNode) {
            if (I18N_SKIP[el.nodeName] || (el.hasAttribute && el.hasAttribute('data-help'))) return true;
            if (el.getAttribute && el.getAttribute('translate') === 'no') return true;   /* names, versions */
            if (el.className && typeof el.className === 'string' && /(^| )h-/.test(el.className)) return true;
        }
        return false;
    }

    /* Help is translated per leaf block (li, p, summary): key = its inner HTML
     * with <pre> command blocks replaced by {P0}, {P1}... so commands are never
     * part of a translation. Captured once, before the live values (host
     * name, tunnel address) are filled into the help. */
    function i18nCaptureHelp() {
        if (helpUnits) return;
        helpUnits = [];
        var els = document.querySelectorAll('[data-help] li, [data-help] p, [data-help] summary');
        for (var i = 0; i < els.length; i++) {
            var el = els[i];
            if (el.querySelector('li, p')) continue;          /* not a leaf block */
            el._hsrc = el.innerHTML;
            el._hpre = [];
            var pres = el.querySelectorAll('pre');
            for (var k = 0; k < pres.length; k++) el._hpre.push(pres[k].outerHTML);
            var n = 0;
            el._hkey = el.innerHTML.replace(/<pre>[\s\S]*?<\/pre>/g, function() { return '{P' + (n++) + '}'; })
                                   .replace(/\s+/g, ' ').trim();
            helpUnits.push(el);
        }
    }

    function i18nApplyDom() {
        var w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
        var n;
        while ((n = w.nextNode())) {
            if (n._src === undefined) {
                if (!/[A-Za-zÀ-ž]{2}/.test(n.nodeValue) || i18nSkip(n.parentNode)) { n._src = null; continue; }
                n._src = n.nodeValue;
            }
            if (n._src === null) continue;
            var m = /^(\s*)([\s\S]*?)(\s*)$/.exec(n._src);
            var key = m[2].replace(/\s+/g, ' ');
            n.nodeValue = m[1] + t(key) + m[3];
        }
        var els = document.querySelectorAll('[placeholder],[title]');
        for (var i = 0; i < els.length; i++) {
            var el = els[i];
            if (i18nSkip(el)) continue;
            if (!el._srcAttr) el._srcAttr = { placeholder: el.getAttribute('placeholder'), title: el.getAttribute('title') };
            if (el._srcAttr.placeholder) el.setAttribute('placeholder', t(el._srcAttr.placeholder));
            if (el._srcAttr.title) el.setAttribute('title', t(el._srcAttr.title));
        }
        i18nCaptureHelp();
        for (var j = 0; j < helpUnits.length; j++) {
            var u = helpUnits[j];
            var tr = I18N.help[u._hkey];
            u.innerHTML = tr ? tr.replace(/\{P(\d+)\}/g, function(_, k) { return u._hpre[k] || ''; })
                             : u._hsrc;
        }
        if (typeof setHelpOs === 'function') setHelpOs(helpOs);
        setAllText('h-host', location.hostname);
        fillHelpValues(lastWgInfo);
    }

    function i18nPick() {
        var saved = null;
        try { saved = localStorage.getItem('usbip-lang'); } catch (e) { /* storage blocked */ }
        var codes = LANGS.map(function(l) { return l[0]; });
        if (saved && codes.indexOf(saved) !== -1) return saved;
        var prefs = navigator.languages || [navigator.language || 'en'];
        for (var i = 0; i < prefs.length; i++) {
            var c = String(prefs[i]).slice(0, 2).toLowerCase();
            if (codes.indexOf(c) !== -1) return c;
        }
        return 'en';
    }

    function setLanguage(code, remember) {
        if (remember) {
            try { localStorage.setItem('usbip-lang', code); } catch (e) { /* storage blocked */ }
        }
        document.documentElement.lang = code;
        document.documentElement.dir = code === 'ar' ? 'rtl' : 'ltr';
        var $sel = document.getElementById('lang-select');
        if ($sel) $sel.value = code;
        /* Apply the last copy of this language at once (no flash of the source
         * language), then the current file from the board. */
        var cached = null;
        try { cached = JSON.parse(localStorage.getItem('usbip-lang-' + code) || 'null'); } catch (e) { /* none */ }
        if (cached) {
            I18N = { lang: code, ui: cached.ui || {}, help: cached.help || {} };
            i18nApplyDom();
        }
        return fetch('/lang?l=' + code)
            .then(function(r) { return r.ok ? r.text() : null; })
            .catch(function() { return null; })
            .then(function(txt) {
                var d = null;
                try { d = txt ? JSON.parse(txt) : null; } catch (e) { d = null; }
                if (!d) d = cached || { ui: {}, help: {} };
                else { try { localStorage.setItem('usbip-lang-' + code, txt); } catch (e) { /* full/blocked */ } }
                I18N = { lang: code, ui: d.ui || {}, help: d.help || {} };
                i18nApplyDom();
                applyTheme(theme);
                if (activeSection === 'settings') loadAllSettings();
                if (lastStats) handleStats(lastStats);
            });
    }

    /* ================================================================
     * WireGuard status (sidebar badge, device client badges)
     * ================================================================ */

    var lastWgInfo = null;

    function updateWgBadge(wg, self) {
        lastWgInfo = wg;
        var $b = document.getElementById('wg-badge');
        var $t = document.getElementById('wg-badge-text');
        if (!$b || !$t) return;
        fillHelpValues(wg);
        var https = location.protocol === 'https:';
        if (!(wg && wg.up && self) && https) {
            $b.style.display = '';
            $b.className = 'ws-status wg-badge secure';
            $t.textContent = t('Über HTTPS verschlüsselt');
            $b.title = t('Diese Web-UI-Sitzung ist per HTTPS (TLS) verschlüsselt.');
            return;
        }
        if (!wg || !wg.enabled) { $b.style.display = 'none'; return; }
        $b.style.display = '';
        if (wg.up && self) {
            $b.className = 'ws-status wg-badge secure';
            $t.textContent = t('Über WireGuard geschützt');
            $b.title = t('Diese Web-UI-Sitzung läuft durch den WireGuard-Tunnel') + ' (' + wg.addr + ').';
        } else if (wg.up) {
            $b.className = 'ws-status wg-badge lan';
            $t.textContent = t('WireGuard aktiv · Sitzung über LAN');
            $b.title = t('Der Tunnel steht, diese Sitzung nutzt ihn aber nicht. Geschützt:') + ' http://' + wg.addr + '/';
        } else {
            $b.className = 'ws-status wg-badge busy';
            $t.textContent = 'WireGuard: ' + (wg.state || '?');
            $b.title = t('Tunnel eingeschaltet, aber nicht verbunden.');
        }
    }

    /* tr = transport reported by the board: 0 plain, 1 TLS (stunnel), 2 WireGuard */
    function clientBadge(tr, str) {
        if (tr === 2) {
            return '<span class="badge badge-wg" title="' + t('USB/IP-Verbindung läuft durch den WireGuard-Tunnel') + '">&#128274; ' +
                   esc(str) + ' · WireGuard</span>';
        }
        if (tr === 1) {
            return '<span class="badge badge-wg" title="' + t('USB/IP-Verbindung ist per TLS verschlüsselt (stunnel)') + '">&#128274; ' +
                   esc(str) + ' · TLS</span>';
        }
        return '<span class="badge badge-state" title="' + t('Unverschlüsselte USB/IP-Verbindung') + '">' + esc(str) + '</span>';
    }

    /* ================================================================
     * Theme: auto (system) -> dark -> light, saved per browser
     * ================================================================ */

    var THEMES = ['auto', 'dark', 'light'];
    var THEME_LABEL = { auto: 'Auto', dark: 'Dunkel', light: 'Hell' };
    var THEME_ICON = { auto: '\u25D0', dark: '\u263E', light: '\u2600' };
    var theme = 'auto';
    try { theme = localStorage.getItem('usbip-theme') || 'auto'; } catch (e) { /* storage blocked */ }
    if (THEMES.indexOf(theme) === -1) theme = 'auto';

    function applyTheme(t) {
        theme = t;
        if (t === 'auto') document.documentElement.removeAttribute('data-theme');
        else document.documentElement.setAttribute('data-theme', t);
        try { localStorage.setItem('usbip-theme', t); } catch (e) { /* storage blocked */ }
        var $icon = document.getElementById('theme-toggle-icon');
        var $text = document.getElementById('theme-toggle-text');
        if ($icon) $icon.textContent = THEME_ICON[t];
        if ($text) $text.textContent = window._t(THEME_LABEL[t]);
        if (typeof drawBandwidthChart === 'function') drawBandwidthChart();
    }

    /* Current theme colours for canvas/SVG drawing (CSS variables don't reach those). */
    function themeColors() {
        var cs = getComputedStyle(document.documentElement);
        function v(n) { return cs.getPropertyValue(n).trim(); }
        return { surface: v('--surface'), text: v('--text'), text2: v('--text-secondary'),
                 dim: v('--text-dim'), line: v('--line'), border: v('--border'), grid: v('--grid') };
    }

    /* ================================================================
     * Settings help: OS tabs and live values in the examples
     * ================================================================ */

    var helpOs = null;
    try { helpOs = localStorage.getItem('usbip-help-os'); } catch (e) { /* storage blocked */ }
    if (!helpOs) helpOs = /Windows/i.test(navigator.userAgent) ? 'windows' : 'debian';

    function setHelpOs(os) {
        helpOs = os;
        try { localStorage.setItem('usbip-help-os', os); } catch (e) { /* storage blocked */ }
        var btns = document.querySelectorAll('.os-tabs button');
        for (var i = 0; i < btns.length; i++) {
            btns[i].classList.toggle('active', btns[i].getAttribute('data-os') === os);
        }
        var panes = document.querySelectorAll('.os-pane');
        for (var j = 0; j < panes.length; j++) {
            panes[j].classList.toggle('active', panes[j].getAttribute('data-os') === os);
        }
    }

    document.addEventListener('click', function(e) {
        var b = e.target.closest ? e.target.closest('.os-tabs button') : null;
        if (b) { e.preventDefault(); setHelpOs(b.getAttribute('data-os')); }
    });

    function setAllText(cls, val) {
        var els = document.getElementsByClassName(cls);
        for (var i = 0; i < els.length; i++) els[i].textContent = val;
    }

    var lastHelpWg = '';
    function fillHelpValues(wg) {
        var addr = (wg && wg.addr) || '10.8.0.2';
        var pub = ($id('wg-pubkey') && $id('wg-pubkey').value) || '<öffentlicher Schlüssel des Boards>';
        var key = addr + '|' + pub;
        if (key === lastHelpWg) return;
        lastHelpWg = key;
        setAllText('h-wgaddr', addr);
        setAllText('h-wgpub', pub);
    }

    function ip4str(ip) {
        if (!ip) return '';
        return (ip & 0xFF) + '.' +
               ((ip >>> 8) & 0xFF) + '.' +
               ((ip >>> 16) & 0xFF) + '.' +
               ((ip >>> 24) & 0xFF);
    }

    function speedStr(s) {
        return ['LS', 'FS', 'HS', '', '', 'SS'][s] || '?';
    }

    function speedClass(s) {
        return ['ls', 'fs', 'hs', '', '', 'ss'][s] || '';
    }

    function stateStr(s) {
        return ['Available', 'Exported', 'Error'][s] || 'Unknown';
    }

    function stateClass(s) {
        return ['available', 'exported', 'error'][s] || 'available';
    }

    var USB_CLASS = {
        0x00: 'Composite', 0x01: 'Audio', 0x02: 'CDC', 0x03: 'HID',
        0x05: 'Physical', 0x06: 'Image', 0x07: 'Printer', 0x08: 'Mass Storage',
        0x09: 'Hub', 0x0A: 'CDC Data', 0x0B: 'Smart Card', 0x0D: 'Content Security',
        0x0E: 'Video', 0x0F: 'Healthcare', 0x10: 'Audio/Video', 0x11: 'Billboard',
        0x12: 'USB-C Bridge', 0xDC: 'Diagnostic', 0xE0: 'Wireless',
        0xEF: 'Miscellaneous', 0xFE: 'Application Specific', 0xFF: 'Vendor Specific'
    };

    var EP_TYPE = ['Control', 'Isochronous', 'Bulk', 'Interrupt'];

    /* ================================================================
     * Toast notification
     * ================================================================ */

    function toast(msg, type) {
        var el = document.createElement('div');
        el.className = 'toast' + (type ? ' ' + type : '');
        el.textContent = msg;
        document.body.appendChild(el);
        /* Trigger reflow for transition */
        el.offsetHeight;
        el.classList.add('show');
        setTimeout(function() {
            el.classList.remove('show');
            setTimeout(function() {
                if (el.parentNode) el.parentNode.removeChild(el);
            }, 300);
        }, 3000);
    }

    /* ================================================================
     * DOM references
     * ================================================================ */

    var $sidebar = document.getElementById('sidebar');
    var $hamburger = document.getElementById('hamburger');
    var $navItems = document.querySelectorAll('.nav-item[data-section]');
    var $sections = document.querySelectorAll('.section');
    var $wsDot = document.getElementById('ws-dot');
    var $wsText = document.getElementById('ws-status-text');
    var $sidebarUptime = document.getElementById('sidebar-uptime');

    /* Dashboard */
    var $sDevices = document.getElementById('s-devices');
    var $sClients = document.getElementById('s-clients');
    var $sThroughput = document.getElementById('s-throughput');
    var $sMemory = document.getElementById('s-memory');
    var $sUptime = document.getElementById('s-uptime');
    var $sCpu = document.getElementById('s-cpu');
    var $pmBadge = document.getElementById('pm-badge');
    var $pmBadgeText = document.getElementById('pm-badge-text');
    var $sMemBar = document.getElementById('s-mem-bar');
    var $bwIn = document.getElementById('bw-in');
    var $bwOut = document.getElementById('bw-out');
    var $bwChart = document.getElementById('bw-chart');
    var $logArea = document.getElementById('log-area');

    /* Devices */
    var $deviceList = document.getElementById('device-list');

    /* Topology */
    var $topologySvg = document.getElementById('topology-svg');

    /* ================================================================
     * State
     * ================================================================ */

    var activeSection = 'dashboard';
    var ws = null;
    var wsReconnectTimer = null;

    /* Previous device bytes for throughput calc */
    var prevDevBytes = {};     /* idx -> { bi, bo, ts } */
    var devThroughput = {};    /* idx -> { bIn, bOut } */

    /* Global throughput */
    var prevTotalBytes = null; /* { bi, bo, ts } */
    var totalThroughputIn = 0;
    var totalThroughputOut = 0;

    /* Bandwidth chart rolling data */
    var BW_POINTS = 120;
    var bwIn = new Array(BW_POINTS);
    var bwOut = new Array(BW_POINTS);
    for (var _i = 0; _i < BW_POINTS; _i++) { bwIn[_i] = 0; bwOut[_i] = 0; }

    /* Last known stats for cross-section use */
    var lastStats = null;

    /* Expanded device index */
    var expandedDevIdx = -1;

    /* Track which log entries we've seen (by timestamp) */
    var renderedLogKeys = {};
    var logEntries = [];
    var MAX_LOG_ENTRIES = 15;

    /* Settings ACL working list */
    var aclEntries = [];

    /* ================================================================
     * Sidebar navigation
     * ================================================================ */

    function switchSection(name) {
        activeSection = name;
        for (var i = 0; i < $navItems.length; i++) {
            var item = $navItems[i];
            if (item.getAttribute('data-section') === name) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        }
        for (var j = 0; j < $sections.length; j++) {
            var sec = $sections[j];
            if (sec.id === 'sec-' + name) {
                sec.classList.add('active');
            } else {
                sec.classList.remove('active');
            }
        }
        /* Close mobile sidebar */
        $sidebar.classList.remove('open');
        var overlay = document.querySelector('.sidebar-overlay');
        if (overlay) overlay.classList.remove('active');

        /* Section-specific init */
        if (name === 'settings') {
            loadAllSettings();
        }
        if (name === 'devices' && lastStats) {
            updateDeviceList(lastStats.devices || []);
        }
        if (name === 'topology' && lastStats) {
            buildTopology(lastStats.devices || []);
        }
    }

    for (var ni = 0; ni < $navItems.length; ni++) {
        (function(item) {
            item.addEventListener('click', function(e) {
                e.preventDefault();
                switchSection(item.getAttribute('data-section'));
            });
        })($navItems[ni]);
    }

    /* Hamburger toggle */
    if ($hamburger) {
        $hamburger.addEventListener('click', function() {
            var isOpen = $sidebar.classList.toggle('open');
            var overlay = document.querySelector('.sidebar-overlay');
            if (!overlay) {
                overlay = document.createElement('div');
                overlay.className = 'sidebar-overlay';
                overlay.addEventListener('click', function() {
                    $sidebar.classList.remove('open');
                    overlay.classList.remove('active');
                });
                document.body.appendChild(overlay);
            }
            if (isOpen) {
                overlay.classList.add('active');
            } else {
                overlay.classList.remove('active');
            }
        });
    }

    /* ================================================================
     * WebSocket connection
     * ================================================================ */

    var wsLostTimer = null;

    function wsConnect() {
        if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) {
            return;
        }
        var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(proto + '//' + location.host + '/ws');

        ws.onopen = function() {
            if (wsLostTimer) {
                clearTimeout(wsLostTimer);
                wsLostTimer = null;
            }
            $wsDot.classList.remove('connecting');
            $wsDot.classList.add('connected');
            $wsText.textContent = t('Connected');
            if (wsReconnectTimer) {
                clearTimeout(wsReconnectTimer);
                wsReconnectTimer = null;
            }
        };

        ws.onclose = function() {
            /* Grey "reconnecting" first; red only if it stays down (a page
             * reload or a short drop should not look like an error). */
            $wsDot.classList.remove('connected');
            $wsDot.classList.add('connecting');
            $wsText.textContent = t('Verbinde…');
            if (!wsLostTimer) {
                wsLostTimer = setTimeout(function() {
                    wsLostTimer = null;
                    $wsDot.classList.remove('connecting');
                    $wsText.textContent = t('Disconnected');
                }, 5000);
            }
            ws = null;
            if (!wsReconnectTimer) {
                wsReconnectTimer = setTimeout(function() {
                    wsReconnectTimer = null;
                    wsConnect();
                }, 2000);
            }
        };

        ws.onerror = function() {
            /* onclose will fire after onerror */
        };

        ws.onmessage = function(ev) {
            try {
                var msg = JSON.parse(ev.data);
                if (msg.type === 'stats') {
                    handleStats(msg);
                }
            } catch (e) {
                console.error('WS message handling error:', e);
            }
        };
    }

    /* ================================================================
     * Stats handler - dispatches to all sections
     * ================================================================ */

    function handleStats(msg) {
        lastStats = msg;
        var devices = msg.devices || [];
        var now = Date.now();

        /* --- Compute per-device throughput --- */
        var totalBi = 0, totalBo = 0;
        for (var i = 0; i < devices.length; i++) {
            var d = devices[i];
            totalBi += d.bi;
            totalBo += d.bo;
            var prev = prevDevBytes[d.idx];
            if (prev) {
                var dt = (now - prev.ts) / 1000;
                if (dt > 0) {
                    devThroughput[d.idx] = {
                        bIn: Math.max(0, (d.bi - prev.bi) / dt),
                        bOut: Math.max(0, (d.bo - prev.bo) / dt)
                    };
                }
            }
            prevDevBytes[d.idx] = { bi: d.bi, bo: d.bo, ts: now };
        }

        /* --- Global throughput --- */
        if (prevTotalBytes) {
            var gdt = (now - prevTotalBytes.ts) / 1000;
            if (gdt > 0) {
                totalThroughputIn = Math.max(0, (totalBi - prevTotalBytes.bi) / gdt);
                totalThroughputOut = Math.max(0, (totalBo - prevTotalBytes.bo) / gdt);
            }
        }
        prevTotalBytes = { bi: totalBi, bo: totalBo, ts: now };

        /* Push bandwidth data */
        bwIn.push(totalThroughputIn);
        bwOut.push(totalThroughputOut);
        if (bwIn.length > BW_POINTS) bwIn.shift();
        if (bwOut.length > BW_POINTS) bwOut.shift();

        /* --- Count unique clients --- */
        var clientSet = {};
        var clientCount = 0;
        for (var ci = 0; ci < devices.length; ci++) {
            var cip = devices[ci].client_ip;
            if (cip && !clientSet[cip]) {
                clientSet[cip] = true;
                clientCount++;
            }
        }

        /* --- WireGuard badge --- */
        updateWgBadge(msg.wg, msg.wg_self);

        /* --- Update dashboard --- */
        updateDashboard(msg, devices, clientCount);

        /* --- Update devices section --- */
        if (activeSection === 'devices') {
            updateDeviceList(devices);
        }

        /* --- Update topology section --- */
        if (activeSection === 'topology') {
            buildTopology(devices);
        }

        /* --- Logs --- */
        if (msg.logs) {
            updateLogs(msg.logs);
        }
    }

    /* ================================================================
     * Dashboard
     * ================================================================ */

    /* Estimate total internal heap ~400KB for ESP32-P4 */
    var TOTAL_INTERNAL_HEAP = 400 * 1024;

    function updateDashboard(msg, devices, clientCount) {
        $sDevices.textContent = devices.length;
        $sClients.textContent = clientCount;
        $sThroughput.textContent = formatBytes(totalThroughputIn + totalThroughputOut);
        $sUptime.textContent = formatUptime(msg.uptime_sec);
        if (msg.cpu_mhz) $sCpu.textContent = msg.cpu_mhz + ' MHz';
        /* Power save badge: lit whenever the setting is on (MHz = current mode). */
        $pmBadge.style.display = msg.pm ? '' : 'none';
        if (msg.pm) {
            $pmBadgeText.textContent = t('Energiesparen an') + (msg.cpu_mhz ? ' \u00b7 ' + msg.cpu_mhz + ' MHz' : '');
        }
        $sidebarUptime.textContent = t('Uptime') + ': ' + formatUptime(msg.uptime_sec);

        /* Memory */
        var usedInternal = TOTAL_INTERNAL_HEAP - msg.free_internal;
        var pct = Math.min(100, Math.max(0, (usedInternal / TOTAL_INTERNAL_HEAP) * 100));
        $sMemory.textContent = Math.round(msg.free_heap / 1024) + ' KB';
        $sMemBar.style.width = pct.toFixed(1) + '%';

        /* Bandwidth summary */
        $bwIn.textContent = formatBytes(totalThroughputIn);
        $bwOut.textContent = formatBytes(totalThroughputOut);

        /* Chart */
        drawBandwidthChart();
    }

    /* ================================================================
     * Bandwidth chart
     * ================================================================ */

    function drawBandwidthChart() {
        var canvas = $bwChart;
        if (!canvas) return;

        /* Handle high-DPI displays */
        var rect = canvas.getBoundingClientRect();
        var w = rect.width;
        var h = rect.height;
        if (w === 0 || h === 0) return;

        var dpr = window.devicePixelRatio || 1;
        canvas.width = w * dpr;
        canvas.height = h * dpr;

        var ctx = canvas.getContext('2d');
        ctx.scale(dpr, dpr);
        ctx.clearRect(0, 0, w, h);

        /* Find max value for Y axis */
        var maxVal = 1024; /* minimum 1 KB/s scale */
        for (var i = 0; i < BW_POINTS; i++) {
            if (bwIn[i] > maxVal) maxVal = bwIn[i];
            if (bwOut[i] > maxVal) maxVal = bwOut[i];
        }
        maxVal *= 1.15; /* headroom */

        var padL = 0, padR = 0, padT = 8, padB = 4;
        var cw = w - padL - padR;
        var ch = h - padT - padB;

        /* Grid lines */
        ctx.strokeStyle = themeColors().grid;
        ctx.lineWidth = 0.5;
        var gridLines = 4;
        for (var g = 0; g <= gridLines; g++) {
            var gy = padT + (ch * g / gridLines);
            ctx.beginPath();
            ctx.moveTo(padL, gy);
            ctx.lineTo(padL + cw, gy);
            ctx.stroke();
        }

        /* Draw a filled line */
        function drawLine(data, strokeColor, fillColor) {
            var step = cw / (BW_POINTS - 1);
            ctx.beginPath();
            for (var j = 0; j < BW_POINTS; j++) {
                var x = padL + j * step;
                var y = padT + ch - (data[j] / maxVal) * ch;
                if (j === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
            }
            ctx.strokeStyle = strokeColor;
            ctx.lineWidth = 1.5;
            ctx.stroke();

            /* Fill area under */
            ctx.lineTo(padL + (BW_POINTS - 1) * step, padT + ch);
            ctx.lineTo(padL, padT + ch);
            ctx.closePath();
            ctx.fillStyle = fillColor;
            ctx.fill();
        }

        drawLine(bwIn, '#3b82f6', 'rgba(59,130,246,0.10)');
        drawLine(bwOut, '#22c55e', 'rgba(34,197,94,0.08)');
    }

    /* ================================================================
     * Event log
     * ================================================================ */

    var LOG_LEVEL = ['DEBUG', 'INFO', 'WARN', 'ERROR'];
    var LOG_CLASS = ['debug', 'info', 'warn', 'error'];

    function updateLogs(logs) {
        if (!logs || !logs.length) return;

        /* Merge new entries */
        var changed = false;
        for (var i = 0; i < logs.length; i++) {
            var entry = logs[i];
            var key = entry.ts + ':' + entry.msg;
            if (!renderedLogKeys[key]) {
                renderedLogKeys[key] = true;
                logEntries.push(entry);
                changed = true;
            }
        }

        if (!changed) return;

        /* Sort by timestamp descending, keep last N */
        logEntries.sort(function(a, b) { return b.ts - a.ts; });
        if (logEntries.length > MAX_LOG_ENTRIES) {
            var removed = logEntries.splice(MAX_LOG_ENTRIES);
            for (var r = 0; r < removed.length; r++) {
                delete renderedLogKeys[removed[r].ts + ':' + removed[r].msg];
            }
        }

        /* Render */
        var html = '';
        for (var j = 0; j < logEntries.length; j++) {
            var e = logEntries[j];
            var lvl = e.level || 1;
            var cls = LOG_CLASS[lvl] || 'info';
            /* timestamp: convert microseconds to readable time */
            var sec = Math.floor(e.ts / 1000000);
            var tsStr = formatUptime(sec);
            html += '<div class="log-entry ' + cls + '">' +
                    '<span class="ts">' + esc(tsStr) + '</span>' +
                    '<span class="msg">' + esc(e.msg) + '</span></div>';
        }
        $logArea.innerHTML = html;
    }

    /* ================================================================
     * Devices section
     * ================================================================ */

    function updateDeviceList(devices) {
        if (!devices.length) {
            $deviceList.innerHTML = '<div class="empty-state">' + t('No USB devices connected') + '</div>';
            return;
        }

        /* Remove stale empty-state placeholder before reconciling cards */
        var emptyState = $deviceList.querySelector('.empty-state');
        if (emptyState) emptyState.parentNode.removeChild(emptyState);

        /* Build or update device cards - reconcile existing DOM */
        var existingCards = $deviceList.querySelectorAll('.device-card');
        var existingMap = {};
        for (var e = 0; e < existingCards.length; e++) {
            var eidx = existingCards[e].getAttribute('data-idx');
            existingMap[eidx] = existingCards[e];
        }

        /* Track which indices are present */
        var presentIdxs = {};

        for (var i = 0; i < devices.length; i++) {
            var d = devices[i];
            presentIdxs[d.idx] = true;
            var tp = devThroughput[d.idx] || { bIn: 0, bOut: 0 };
            var isExpanded = (expandedDevIdx === d.idx);
            var spdStr = speedStr(d.speed);
            var spdCls = speedClass(d.speed);
            var stCls = stateClass(d.state);
            var stStr = t(stateStr(d.state));
            var clientStr = d.client_ip ? ip4str(d.client_ip) : '';

            /* Determine primary class from icl */
            var primaryClass = '';
            if (d.icl && d.icl.length > 0) {
                for (var ic = 0; ic < d.icl.length; ic++) {
                    if (d.icl[ic] !== 0) {
                        primaryClass = USB_CLASS[d.icl[ic]] || ('Class 0x' + hex4(d.icl[ic]));
                        break;
                    }
                }
                if (!primaryClass && d.icl.length > 0) {
                    primaryClass = USB_CLASS[d.icl[0]] || '';
                }
            }

            var devName = d.prod || d.mfr || primaryClass || t('Unknown Device');

            var card = existingMap[d.idx];
            if (card) {
                /* Update existing card in place */
                var dot = card.querySelector('.status-dot');
                if (dot) dot.className = 'status-dot ' + stCls;

                var nameEl = card.querySelector('.device-name');
                if (nameEl) nameEl.textContent = devName;

                var idsEl = card.querySelector('.device-ids');
                if (idsEl) {
                    var idsText = d.path + '  ' + hex4(d.vid) + ':' + hex4(d.pid);
                    if (primaryClass) idsText += '  ' + primaryClass;
                    idsEl.textContent = idsText;
                }

                /* Update badges */
                var badgesEl = card.querySelector('.device-badges');
                if (badgesEl) {
                    var badgeHtml = '<span class="badge badge-' + spdCls + '">' + spdStr + '</span>' +
                                   '<span class="badge badge-state badge-' + stCls + '">' + stStr + '</span>';
                    if (clientStr) {
                        badgeHtml += clientBadge(d.tr, clientStr);
                    }
                    var tpTotal = tp.bIn + tp.bOut;
                    if (tpTotal > 0) {
                        badgeHtml += '<span class="badge badge-state">' + formatBytes(tpTotal) + '</span>';
                    }
                    badgesEl.innerHTML = badgeHtml;
                }

                delete existingMap[d.idx];
            } else {
                /* Create new card */
                card = document.createElement('div');
                card.className = 'device-card' + (isExpanded ? ' expanded' : '');
                card.setAttribute('data-idx', d.idx);

                var idsText = d.path + '  ' + hex4(d.vid) + ':' + hex4(d.pid);
                if (primaryClass) idsText += '  ' + primaryClass;

                var badgeHtml = '<span class="badge badge-' + spdCls + '">' + spdStr + '</span>' +
                               '<span class="badge badge-state badge-' + stCls + '">' + stStr + '</span>';
                if (clientStr) {
                    badgeHtml += clientBadge(d.tr, clientStr);
                }
                var tpTotal = tp.bIn + tp.bOut;
                if (tpTotal > 0) {
                    badgeHtml += '<span class="badge badge-state">' + formatBytes(tpTotal) + '</span>';
                }

                card.innerHTML =
                    '<div class="device-card-header" onclick="window._toggleDevice(' + d.idx + ')">' +
                        '<div class="status-dot ' + stCls + '"></div>' +
                        '<div class="device-summary">' +
                            '<div class="device-name">' + esc(devName) + '</div>' +
                            '<div class="device-ids">' + esc(idsText) + '</div>' +
                        '</div>' +
                        '<div class="device-badges">' + badgeHtml + '</div>' +
                        '<div class="expand-icon">&#9660;</div>' +
                    '</div>' +
                    '<div class="device-card-body" id="dev-body-' + d.idx + '">' +
                        '<div class="text-dim" style="padding:1rem 0;text-align:center">' + t('Loading...') + '</div>' +
                    '</div>';

                $deviceList.appendChild(card);
            }
        }

        /* Remove cards for devices no longer present */
        for (var oldIdx in existingMap) {
            if (existingMap.hasOwnProperty(oldIdx)) {
                var old = existingMap[oldIdx];
                if (old.parentNode) old.parentNode.removeChild(old);
            }
        }
    }

    /* Toggle device detail expansion */
    window._toggleDevice = function(idx) {
        var card = $deviceList.querySelector('.device-card[data-idx="' + idx + '"]');
        if (!card) return;

        if (expandedDevIdx === idx) {
            /* Collapse */
            card.classList.remove('expanded');
            expandedDevIdx = -1;
            return;
        }

        /* Collapse previous */
        var prev = $deviceList.querySelector('.device-card.expanded');
        if (prev) prev.classList.remove('expanded');

        expandedDevIdx = idx;
        card.classList.add('expanded');

        /* Fetch detail */
        fetchDeviceDetail(idx);
    };

    function fetchDeviceDetail(idx) {
        var body = document.getElementById('dev-body-' + idx);
        if (!body) return;
        body.innerHTML = '<div class="text-dim" style="padding:1rem 0;text-align:center">' + t('Loading...') + '</div>';

        fetch('/api/devices/detail?idx=' + idx)
            .then(function(r) { return r.json(); })
            .then(function(detail) {
                renderDeviceDetail(idx, detail);
            })
            .catch(function(err) {
                body.innerHTML = '<div class="text-dim" style="padding:1rem 0;text-align:center">' + t('Failed to load details') + '</div>';
            });
    }

    function renderDeviceDetail(idx, d) {
        var body = document.getElementById('dev-body-' + idx);
        if (!body) return;

        var html = '';

        /* Device info rows */
        html += '<div class="device-detail-row"><span class="detail-label">' + t('Bus ID') + '</span><span class="detail-value">' + esc(d.path) + '</span></div>';
        html += '<div class="device-detail-row"><span class="detail-label">' + t('VID:PID') + '</span><span class="detail-value">' + hex4(d.vid) + ':' + hex4(d.pid) + '</span></div>';
        html += '<div class="device-detail-row"><span class="detail-label">' + t('BCD Device') + '</span><span class="detail-value">' + hex4(d.bcd_device || 0) + '</span></div>';
        html += '<div class="device-detail-row"><span class="detail-label">' + t('Class') + '</span><span class="detail-value">' + (USB_CLASS[d['class']] || ('0x' + hex4(d['class'] || 0))) + '</span></div>';
        html += '<div class="device-detail-row"><span class="detail-label">' + t('Speed') + '</span><span class="detail-value">' + esc(d.speed) + '</span></div>';
        html += '<div class="device-detail-row"><span class="detail-label">' + t('State') + '</span><span class="detail-value">' + esc(t(d.state || '')) + '</span></div>';
        if (d.client_ip) {
            html += '<div class="device-detail-row"><span class="detail-label">' + t('Client') + '</span><span class="detail-value">' + esc(d.client_ip) + '</span></div>';
        }
        html += '<div class="device-detail-row"><span class="detail-label">' + t('Manufacturer') + '</span><span class="detail-value">' + esc(d.manufacturer || '--') + '</span></div>';
        html += '<div class="device-detail-row"><span class="detail-label">' + t('Product') + '</span><span class="detail-value">' + esc(d.product || '--') + '</span></div>';
        html += '<div class="device-detail-row"><span class="detail-label">' + t('Serial') + '</span><span class="detail-value">' + esc(d.serial || '--') + '</span></div>';

        /* Stats */
        html += '<div class="device-detail-row"><span class="detail-label">' + t('Bytes In') + '</span><span class="detail-value">' + (d.bytes_in || 0).toLocaleString() + '</span></div>';
        html += '<div class="device-detail-row"><span class="detail-label">' + t('Bytes Out') + '</span><span class="detail-value">' + (d.bytes_out || 0).toLocaleString() + '</span></div>';
        html += '<div class="device-detail-row"><span class="detail-label">' + t('URBs OK') + '</span><span class="detail-value">' + (d.urbs_completed || 0).toLocaleString() + '</span></div>';
        html += '<div class="device-detail-row"><span class="detail-label">' + t('URBs Failed') + '</span><span class="detail-value">' + (d.urbs_failed || 0).toLocaleString() + '</span></div>';

        /* Interfaces table */
        if (d.interfaces && d.interfaces.length) {
            html += '<div style="margin-top:0.75rem;font-size:0.8125rem;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.04em">' + t('Interfaces') + '</div>';
            html += '<table style="width:100%;font-size:0.8125rem;border-collapse:collapse;margin-top:0.375rem">';
            html += '<tr style="color:var(--text-dim);text-align:left"><th style="padding:0.25rem 0.5rem;font-weight:500">#</th><th style="padding:0.25rem 0.5rem;font-weight:500">' + t('Class') + '</th><th style="padding:0.25rem 0.5rem;font-weight:500">' + t('Sub') + '</th><th style="padding:0.25rem 0.5rem;font-weight:500">' + t('Proto') + '</th><th style="padding:0.25rem 0.5rem;font-weight:500">' + t('EPs') + '</th></tr>';
            for (var ii = 0; ii < d.interfaces.length; ii++) {
                var iface = d.interfaces[ii];
                var cls = USB_CLASS[iface['class']] || ('0x' + ('00' + iface['class'].toString(16)).slice(-2));
                html += '<tr style="border-top:1px solid var(--border-light)">' +
                    '<td style="padding:0.25rem 0.5rem;font-family:var(--mono)">' + iface.number + '</td>' +
                    '<td style="padding:0.25rem 0.5rem">' + esc(cls) + '</td>' +
                    '<td style="padding:0.25rem 0.5rem;font-family:var(--mono)">' + iface.subclass + '</td>' +
                    '<td style="padding:0.25rem 0.5rem;font-family:var(--mono)">' + iface.protocol + '</td>' +
                    '<td style="padding:0.25rem 0.5rem;font-family:var(--mono)">' + iface.num_endpoints + '</td>' +
                    '</tr>';
            }
            html += '</table>';
        }

        /* Endpoints table */
        if (d.endpoints && d.endpoints.length) {
            html += '<div style="margin-top:0.75rem;font-size:0.8125rem;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.04em">' + t('Endpoints') + '</div>';
            html += '<table style="width:100%;font-size:0.8125rem;border-collapse:collapse;margin-top:0.375rem">';
            html += '<tr style="color:var(--text-dim);text-align:left"><th style="padding:0.25rem 0.5rem;font-weight:500">' + t('Addr') + '</th><th style="padding:0.25rem 0.5rem;font-weight:500">' + t('Dir') + '</th><th style="padding:0.25rem 0.5rem;font-weight:500">' + t('Type') + '</th><th style="padding:0.25rem 0.5rem;font-weight:500">' + t('MaxPkt') + '</th><th style="padding:0.25rem 0.5rem;font-weight:500">' + t('Interval') + '</th></tr>';
            for (var ei = 0; ei < d.endpoints.length; ei++) {
                var ep = d.endpoints[ei];
                html += '<tr style="border-top:1px solid var(--border-light)">' +
                    '<td style="padding:0.25rem 0.5rem;font-family:var(--mono)">' + esc(ep.address) + '</td>' +
                    '<td style="padding:0.25rem 0.5rem">' + esc(ep.direction) + '</td>' +
                    '<td style="padding:0.25rem 0.5rem">' + esc(ep.type) + '</td>' +
                    '<td style="padding:0.25rem 0.5rem;font-family:var(--mono)">' + ep.max_packet_size + '</td>' +
                    '<td style="padding:0.25rem 0.5rem;font-family:var(--mono)">' + ep.interval + '</td>' +
                    '</tr>';
            }
            html += '</table>';
        }

        /* Action buttons */
        html += '<div class="device-card-actions">';
        if (d.state === 'Exported') {
            html += '<button class="btn btn-sm btn-secondary" onclick="window._deviceAction(\'disconnect\',' + idx + ')">' + t('Disconnect Client') + '</button>';
        }
        html += '<button class="btn btn-sm btn-secondary" onclick="window._deviceAction(\'export\',' + idx + ')">' + t('Toggle Export') + '</button>';
        html += '<button class="btn btn-sm btn-danger" onclick="window._ejectDevice(' + idx + ')">' + t('Eject') + '</button>';
        html += '</div>';

        body.innerHTML = html;
    }

    /* Eject asks first; a translated question must not end up inside the onclick attribute */
    window._ejectDevice = function(idx) {
        if (confirm(t('Eject this device?'))) window._deviceAction('disconnect', idx);
    };

    /* Device action handler */
    window._deviceAction = function(action, idx) {
        var url = '/api/devices/' + action + '?idx=' + idx;
        fetch(url, { method: 'POST' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.ok) {
                    toast(t('Action completed'), 'success');
                    /* Re-fetch detail if still expanded */
                    if (expandedDevIdx === idx) {
                        setTimeout(function() { fetchDeviceDetail(idx); }, 300);
                    }
                } else {
                    toast(data.error || t('Action failed'), 'error');
                }
            })
            .catch(function() {
                toast(t('Request failed'), 'error');
            });
    };

    /* Navigate to device from topology */
    window._showDevice = function(idx) {
        switchSection('devices');
        expandedDevIdx = -1; /* reset so toggle will expand */
        /* Wait for device list to render, then toggle */
        setTimeout(function() {
            window._toggleDevice(idx);
        }, 100);
    };

    /* ================================================================
     * Topology section - SVG tree
     * ================================================================ */

    function buildTopology(devices) {
        var C = themeColors();
        if (!devices || !devices.length) {
            $topologySvg.innerHTML = '<svg viewBox="0 0 500 100"><text x="250" y="50" text-anchor="middle" fill="' + C.dim + '" font-family="system-ui" font-size="12">' + t('No devices connected') + '</text></svg>';
            return;
        }

        /* Parse hierarchy from busid (path field) */
        /* "1-1" = root device, "1-1.3" = behind hub port 3, "1-1.3.2" = deeper */
        var rootDevices = [];   /* direct on root hub */
        var hubChildren = {};   /* hubIdx -> [{ port, device }] */
        var hubIndices = {};    /* device idx -> true if it's a hub */
        var virtualHubs = {};   /* path -> virtual hub object */
        var nextVirtualIdx = -1000; /* negative idx for virtual hubs */

        /* Detect hubs from class codes */
        for (var h = 0; h < devices.length; h++) {
            var dh = devices[h];
            if (dh.icl) {
                for (var hc = 0; hc < dh.icl.length; hc++) {
                    if (dh.icl[hc] === 0x09) {
                        hubIndices[dh.idx] = true;
                        break;
                    }
                }
            }
        }

        /* Sort devices by path for consistent layout */
        var sorted = devices.slice().sort(function(a, b) {
            return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
        });

        /* Build parent map: for "1-1.3", parent path is "1-1" */
        var devByPath = {};
        for (var dp = 0; dp < sorted.length; dp++) {
            devByPath[sorted[dp].path] = sorted[dp];
        }

        /* First pass: infer virtual hubs from child paths */
        for (var vi = 0; vi < sorted.length; vi++) {
            var vdev = sorted[vi];
            var vparts = vdev.path.split('.');
            if (vparts.length > 1) {
                var vparentPath = vparts.slice(0, -1).join('.');
                if (!devByPath[vparentPath] && !virtualHubs[vparentPath]) {
                    /* Extract hub address from path (e.g. "1-3" -> addr 3) */
                    var addrMatch = vparentPath.match(/-(\d+)/);
                    var hubAddr = addrMatch ? addrMatch[1] : '?';
                    var vhub = {
                        idx: nextVirtualIdx--,
                        path: vparentPath,
                        vid: 0, pid: 0,
                        speed: 2, /* default HS */
                        state: 0,
                        icl: [0x09],
                        bi: 0, bo: 0,
                        prod: 'Hub',
                        mfr: '',
                        _virtual: true,
                        _hubAddr: hubAddr
                    };
                    virtualHubs[vparentPath] = vhub;
                    devByPath[vparentPath] = vhub;
                    hubIndices[vhub.idx] = true;
                }
            }
        }

        /* Add virtual hubs to sorted list and re-sort */
        for (var vp in virtualHubs) {
            if (virtualHubs.hasOwnProperty(vp)) {
                sorted.push(virtualHubs[vp]);
            }
        }
        sorted.sort(function(a, b) {
            return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
        });

        for (var s = 0; s < sorted.length; s++) {
            var dev = sorted[s];
            var parts = dev.path.split('.');
            if (parts.length <= 1) {
                /* Root-level device (e.g. "1-1") */
                rootDevices.push(dev);
            } else {
                /* Child device - find parent hub */
                var parentPath = parts.slice(0, -1).join('.');
                var port = parseInt(parts[parts.length - 1], 10);
                var parentDev = devByPath[parentPath];
                if (parentDev) {
                    if (!hubChildren[parentDev.idx]) hubChildren[parentDev.idx] = [];
                    hubChildren[parentDev.idx].push({ port: port, device: dev });
                } else {
                    /* Parent not found, treat as root */
                    rootDevices.push(dev);
                }
            }
        }

        /* Layout constants */
        var nodeW = 120, nodeH = 44;
        var hubNodeH = 56;
        var rootY = 15, tier1Y = 80, tier2Y = 170;
        var hGap = 16;
        var rootNodeW = 160, rootNodeH = 32;

        /* Calculate total width needed */
        var columns = [];
        for (var ri = 0; ri < rootDevices.length; ri++) {
            var rd = rootDevices[ri];
            var children = hubChildren[rd.idx] || [];
            var isHub = !!(hubIndices[rd.idx] || children.length > 0);
            if (isHub && children.length > 0) {
                /* Hub needs width for all children */
                var hubW = Math.max(nodeW, children.length * (nodeW + hGap) - hGap);
                columns.push({ dev: rd, width: hubW, children: children, isHub: true });
            } else {
                columns.push({ dev: rd, width: nodeW, children: [], isHub: isHub });
            }
        }

        var totalWidth = 0;
        for (var tw = 0; tw < columns.length; tw++) {
            totalWidth += columns[tw].width;
            if (tw > 0) totalWidth += hGap * 2;
        }
        totalWidth = Math.max(totalWidth, rootNodeW) + 80; /* padding */

        var hasChildren = false;
        for (var hcc = 0; hcc < columns.length; hcc++) {
            if (columns[hcc].children.length > 0) { hasChildren = true; break; }
        }
        var svgH = hasChildren ? tier2Y + nodeH + 30 : tier1Y + nodeH + 30;

        var svg = '<svg viewBox="0 0 ' + totalWidth + ' ' + svgH + '" xmlns="http://www.w3.org/2000/svg">';

        /* Root controller node */
        var rootX = totalWidth / 2;
        svg += '<g class="topo-node">';
        svg += '<rect x="' + (rootX - rootNodeW / 2) + '" y="' + rootY + '" width="' + rootNodeW + '" height="' + rootNodeH + '" rx="8" fill="' + C.surface + '" stroke="#3b82f6" stroke-width="2"/>';
        svg += '<text x="' + rootX + '" y="' + (rootY + 21) + '" text-anchor="middle" font-family="system-ui" font-size="11" font-weight="600" fill="' + C.text + '">ESP32-P4 Host Controller</text>';
        svg += '</g>';

        /* Place tier 1 columns */
        var startX = (totalWidth - (totalWidth - 80)) / 2;
        var xCursor = startX;

        for (var ci = 0; ci < columns.length; ci++) {
            var col = columns[ci];
            var colCenter = xCursor + col.width / 2;
            var d = col.dev;
            var borderColor = d.state === 1 ? '#22c55e' : d.state === 0 ? '#3b82f6' : '#94a3b8';
            var nh = col.isHub ? hubNodeH : nodeH;
            var vidpid = d._virtual ? 'Addr ' + d._hubAddr : hex4(d.vid) + ':' + hex4(d.pid);
            var prodLabel = d.prod || '';
            if (!prodLabel && d.icl && d.icl.length > 0) {
                for (var plc = 0; plc < d.icl.length; plc++) {
                    if (d.icl[plc] !== 0 && USB_CLASS[d.icl[plc]]) { prodLabel = USB_CLASS[d.icl[plc]]; break; }
                }
            }
            if (prodLabel.length > 15) prodLabel = prodLabel.substring(0, 13) + '..';

            /* Line from root to device */
            var rootBottom = rootY + rootNodeH;
            svg += '<g class="topo-edge">';
            svg += '<line x1="' + rootX + '" y1="' + rootBottom + '" x2="' + rootX + '" y2="' + (rootBottom + 12) + '" stroke="' + C.line + '" stroke-width="1.5"/>';
            svg += '<line x1="' + rootX + '" y1="' + (rootBottom + 12) + '" x2="' + colCenter + '" y2="' + (rootBottom + 12) + '" stroke="' + C.line + '" stroke-width="1.5"/>';
            svg += '<line x1="' + colCenter + '" y1="' + (rootBottom + 12) + '" x2="' + colCenter + '" y2="' + tier1Y + '" stroke="' + C.line + '" stroke-width="1.5"/>';
            svg += '</g>';

            /* Device node */
            var nodeClass = col.isHub ? 'topo-hub' : 'topo-node';
            if (d.state === 1) nodeClass += ' topo-imported';
            var clickAttr = d._virtual ? '' : ' style="cursor:pointer" onclick="window._showDevice(' + d.idx + ')"';
            svg += '<g class="' + nodeClass + '"' + clickAttr + '>';
            svg += '<rect x="' + (colCenter - nodeW / 2) + '" y="' + tier1Y + '" width="' + nodeW + '" height="' + nh + '" rx="8" fill="' + (col.isHub ? 'rgba(59,130,246,0.06)' : C.surface) + '" stroke="' + borderColor + '" stroke-width="1.5"/>';
            svg += '<text x="' + colCenter + '" y="' + (tier1Y + 14) + '" text-anchor="middle" font-family="system-ui" font-size="10" font-weight="600" fill="' + C.text + '">' + esc(d.path) + '</text>';
            svg += '<text x="' + colCenter + '" y="' + (tier1Y + 26) + '" text-anchor="middle" font-family="system-ui" font-size="9" fill="' + C.text2 + '">' + esc(vidpid) + '</text>';
            if (prodLabel) {
                svg += '<text x="' + colCenter + '" y="' + (tier1Y + 37) + '" text-anchor="middle" font-family="system-ui" font-size="8" fill="' + C.dim + '">' + esc(prodLabel) + '</text>';
            }

            /* Speed badge in SVG */
            var spdTxt = speedStr(d.speed);
            var badgeCols = { 'HS': '#22c55e', 'FS': '#3b82f6', 'LS': '#f59e0b', 'SS': '#9333ea' };
            var badgeCol = badgeCols[spdTxt] || '#94a3b8';
            svg += '<text x="' + (colCenter + nodeW / 2 - 8) + '" y="' + (tier1Y + 12) + '" text-anchor="end" font-family="system-ui" font-size="8" font-weight="700" fill="' + badgeCol + '">' + spdTxt + '</text>';

            if (col.isHub && col.children.length > 0) {
                /* Draw port circles along bottom of hub */
                var portY = tier1Y + nh - 10;
                var portSpacing = Math.min(20, (nodeW - 20) / Math.max(col.children.length, 1));
                var portStart = colCenter - ((col.children.length - 1) * portSpacing) / 2;
                for (var pi = 0; pi < col.children.length; pi++) {
                    var px = portStart + pi * portSpacing;
                    svg += '<circle cx="' + px + '" cy="' + portY + '" r="4" fill="' + C.border + '" stroke="' + C.dim + '" stroke-width="1"/>';
                    svg += '<text x="' + px + '" y="' + (portY + 3) + '" text-anchor="middle" font-family="system-ui" font-size="6" fill="' + C.text2 + '">' + col.children[pi].port + '</text>';
                }
            }

            svg += '</g>';

            /* Draw children (tier 2) */
            if (col.children.length > 0) {
                var childStartX = colCenter - ((col.children.length * (nodeW + hGap)) - hGap) / 2;
                for (var ki = 0; ki < col.children.length; ki++) {
                    var child = col.children[ki].device;
                    var cx = childStartX + ki * (nodeW + hGap) + nodeW / 2;
                    var childBorder = child.state === 1 ? '#22c55e' : child.state === 0 ? '#3b82f6' : '#94a3b8';
                    var cVidpid = hex4(child.vid) + ':' + hex4(child.pid);
                    var cProdLabel = child.prod || '';
                    if (!cProdLabel && child.icl && child.icl.length > 0) {
                        for (var cplc = 0; cplc < child.icl.length; cplc++) {
                            if (child.icl[cplc] !== 0 && USB_CLASS[child.icl[cplc]]) { cProdLabel = USB_CLASS[child.icl[cplc]]; break; }
                        }
                    }
                    if (cProdLabel.length > 15) cProdLabel = cProdLabel.substring(0, 13) + '..';

                    /* Connecting line */
                    var hubBottom = tier1Y + nh;
                    svg += '<g class="topo-edge">';
                    svg += '<line x1="' + colCenter + '" y1="' + hubBottom + '" x2="' + colCenter + '" y2="' + (hubBottom + 12) + '" stroke="' + C.line + '" stroke-width="1.5"/>';
                    svg += '<line x1="' + colCenter + '" y1="' + (hubBottom + 12) + '" x2="' + cx + '" y2="' + (hubBottom + 12) + '" stroke="' + C.line + '" stroke-width="1.5"/>';
                    svg += '<line x1="' + cx + '" y1="' + (hubBottom + 12) + '" x2="' + cx + '" y2="' + tier2Y + '" stroke="' + C.line + '" stroke-width="1.5"/>';
                    svg += '</g>';

                    /* Child device node */
                    var childNodeClass = 'topo-node' + (child.state === 1 ? ' topo-imported' : '');
                    svg += '<g class="' + childNodeClass + '" style="cursor:pointer" onclick="window._showDevice(' + child.idx + ')">';
                    svg += '<rect x="' + (cx - nodeW / 2) + '" y="' + tier2Y + '" width="' + nodeW + '" height="' + nodeH + '" rx="8" fill="' + C.surface + '" stroke="' + childBorder + '" stroke-width="1.5"/>';
                    svg += '<text x="' + cx + '" y="' + (tier2Y + 14) + '" text-anchor="middle" font-family="system-ui" font-size="10" font-weight="600" fill="' + C.text + '">' + esc(child.path) + '</text>';
                    svg += '<text x="' + cx + '" y="' + (tier2Y + 26) + '" text-anchor="middle" font-family="system-ui" font-size="9" fill="' + C.text2 + '">' + esc(cVidpid) + '</text>';
                    if (cProdLabel) {
                        svg += '<text x="' + cx + '" y="' + (tier2Y + 37) + '" text-anchor="middle" font-family="system-ui" font-size="8" fill="' + C.dim + '">' + esc(cProdLabel) + '</text>';
                    }

                    var cSpdTxt = speedStr(child.speed);
                    var cBadgeCol = badgeCols[cSpdTxt] || '#94a3b8';
                    svg += '<text x="' + (cx + nodeW / 2 - 8) + '" y="' + (tier2Y + 12) + '" text-anchor="end" font-family="system-ui" font-size="8" font-weight="700" fill="' + cBadgeCol + '">' + cSpdTxt + '</text>';

                    svg += '</g>';
                }
            }

            xCursor += col.width + hGap * 2;
        }

        svg += '</svg>';
        $topologySvg.innerHTML = svg;
    }

    /* ================================================================
     * Settings section
     * ================================================================ */

    function loadAllSettings() {
        /* One request at a time: seven parallel fetches plus the WebSocket exceed
         * the server's max_open_sockets (7), and its LRU purge then closes the
         * WebSocket (oldest socket) -> brief "Disconnected" on every visit. */
        var loaders = [loadNetworkSettings, loadAuthSettings, loadAclSettings,
                       loadUsbHub, loadDevFilter, loadWireguard, loadSecurity, loadPower, loadSystemInfo];
        loaders.reduce(function(p, fn) {
            return p.then(function() { return fn(); }, function() { return fn(); });
        }, Promise.resolve());
    }

    /* --- Network --- */

    var $setHostname = document.getElementById('set-hostname');
    var $setDhcp = document.getElementById('set-dhcp');
    var $staticFields = document.getElementById('static-fields');
    var $setIp = document.getElementById('set-ip');
    var $setMask = document.getElementById('set-mask');
    var $setGw = document.getElementById('set-gw');
    var $setDns = document.getElementById('set-dns');
    var $setCurrentIp = document.getElementById('set-current-ip');

    if ($setDhcp) {
        $setDhcp.addEventListener('change', function() {
            $staticFields.style.display = this.checked ? 'none' : 'block';
        });
    }

    function loadNetworkSettings() {
        return fetch('/api/settings/network')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if ($setHostname) $setHostname.value = data.hostname || '';
                if ($setDhcp) {
                    $setDhcp.checked = (data.dhcp !== false && data.dhcp !== 'false');
                    $staticFields.style.display = $setDhcp.checked ? 'none' : 'block';
                }
                if ($setIp) $setIp.value = data.static_ip || '';
                if ($setMask) $setMask.value = data.netmask || '';
                if ($setGw) $setGw.value = data.gateway || '';
                if ($setDns) $setDns.value = data.dns || '';
            })
            .catch(function() { /* ignore */ });

        /* Get current IP from system info */
        fetch('/api/stats')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if ($setCurrentIp && data.ip) $setCurrentIp.textContent = data.ip;
            })
            .catch(function() { /* ignore */ });
    }

    window.saveNetwork = function() {
        var body = {
            hostname: $setHostname.value,
            dhcp: $setDhcp.checked ? 'true' : 'false',
            static_ip: $setIp.value,
            netmask: $setMask.value,
            gateway: $setGw.value,
            dns: $setDns.value
        };
        fetch('/api/settings/network', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.ok) {
                toast(t('Network settings saved. Reboot to apply.'), 'success');
            } else {
                toast(data.error || t('Save failed'), 'error');
            }
        })
        .catch(function() { toast(t('Request failed'), 'error'); });
    };

    /* --- Auth --- */

    var $setAuthEnabled = document.getElementById('set-auth-enabled');
    var $authFields = document.getElementById('auth-fields');
    var $setAuthUser = document.getElementById('set-auth-user');
    var $setAuthPass = document.getElementById('set-auth-pass');

    if ($setAuthEnabled) {
        $setAuthEnabled.addEventListener('change', function() {
            $authFields.style.display = this.checked ? 'block' : 'none';
        });
    }

    function loadAuthSettings() {
        return fetch('/api/settings/auth')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if ($setAuthEnabled) {
                    $setAuthEnabled.checked = !!data.enabled;
                    $authFields.style.display = data.enabled ? 'block' : 'none';
                }
                if ($setAuthUser) $setAuthUser.value = data.username || '';
                if ($setAuthPass) {
                    $setAuthPass.value = '';
                    $setAuthPass.placeholder = data.has_password ? t('(unchanged)') : t('required');
                }
                var $hint = document.getElementById('auth-hint');
                if ($hint) $hint.style.display = data.has_password ? 'none' : 'block';
            })
            .catch(function() { /* ignore */ });
    }

    window.saveAuth = function() {
        var $pass2 = document.getElementById('set-auth-pass2');
        if ($setAuthPass.value !== $pass2.value) {
            toast(t('Passwörter stimmen nicht überein'), 'error');
            $pass2.focus();
            return;
        }
        var body = {
            enabled: $setAuthEnabled.checked,
            username: $setAuthUser.value,
            password: $setAuthPass.value
        };
        fetch('/api/settings/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.ok) {
                toast(t('Auth settings saved'), 'success');
                $setAuthPass.value = '';
                $pass2.value = '';
                loadAuthSettings();
            } else {
                toast(data.error || t('Save failed'), 'error');
            }
        })
        .catch(function() { toast(t('Request failed'), 'error'); });
    };

    /* --- Device filter (VID:PID allowlist) --- */

    function loadDevFilter() {
        var $en = document.getElementById('devf-enabled');
        var $list = document.getElementById('devf-list');
        if (!$en || !$list) return;
        return fetch('/api/settings/devfilter')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                $en.checked = !!data.enabled;
                $list.value = data.list || '';
            })
            .catch(function() { /* ignore */ });
    }

    window.saveDevFilter = function() {
        var body = {
            enabled: document.getElementById('devf-enabled').checked,
            list: document.getElementById('devf-list').value.trim()
        };
        if (body.enabled && !confirm(t('Apply device filter? The USB bus is reset and attached clients are dropped.'))) return;
        fetch('/api/settings/devfilter', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.ok) {
                toast(t('Device filter saved'), 'success');
                loadDevFilter();
            } else {
                toast(data.error || t('Save failed'), 'error');
            }
        })
        .catch(function() { toast(t('Request failed'), 'error'); });
    };

    /* --- USB hub compatibility (Full Speed only) --- */

    function loadUsbHub() {
        return fetch('/api/settings/usb')
            .then(function(r) { return r.json(); })
            .then(function(d) {
                document.getElementById('usb-hub-panel').style.display =
                    d.supported && (d.hub_seen || d.fsls_saved) ? '' : 'none';
                document.getElementById('set-fsls').checked = !!d.fsls_saved;
                var state = d.fsls_active ? t('Aktiv: USB läuft mit Full Speed.') : t('Aktiv: USB läuft mit High Speed.');
                if (d.fsls_saved !== d.fsls_active) state += ' ' + t('Neue Einstellung gilt nach dem Neustart.');
                document.getElementById('usb-fsls-state').textContent = state;
            })
            .catch(function() { /* ignore */ });
    }

    window.saveUsbHub = function() {
        var on = document.getElementById('set-fsls').checked;
        if (!confirm(t('Einstellung speichern und Board neu starten? Eingebundene Geräte werden getrennt.'))) return;
        fetch('/api/settings/usb', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ fsls_only: on })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (!data.ok) { toast(data.error || t('Save failed'), 'error'); return; }
            toast(t('Gespeichert - Board startet neu'), 'success');
            fetch('/api/system/restart', { method: 'POST' });
        })
        .catch(function() { toast(t('Request failed'), 'error'); });
    };

    /* --- Power save --- */

    function loadPower() {
        return fetch('/api/settings/power')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                document.getElementById('power-group').style.display = data.available ? '' : 'none';
                document.getElementById('set-power').checked = !!data.enabled;
            })
            .catch(function() { /* ignore */ });
    }

    window.savePower = function() {
        var on = document.getElementById('set-power').checked;
        fetch('/api/settings/power', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: on })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.ok) {
                toast(on ? t('Energiesparen an') : t('Energiesparen aus - volle Leistung'), 'success');
            } else {
                toast(data.error || t('Save failed'), 'error');
                loadPower();
            }
        })
        .catch(function() { toast(t('Request failed'), 'error'); loadPower(); });
    };

    /* --- WireGuard tunnel --- */

    function $id(x) { return document.getElementById(x); }

    function wgAgo(s) {
        if (s < 0) return t('never');
        if (s < 60) return t('{n} s ago').replace('{n}', s);
        if (s < 3600) return t('{n} min ago').replace('{n}', Math.floor(s / 60));
        return t('{n} h ago').replace('{n}', Math.floor(s / 3600));
    }

    function wgStatus(data) {
        var $st = $id('wg-state');
        if (!$st) return;
        var txt = data.state + (data.state === 'connected' || data.handshake_ago >= 0
            ? ' · ' + t('last handshake') + ' ' + wgAgo(data.handshake_ago) : '');
        if (data.error) txt += ' · ' + data.error;
        $st.textContent = txt;
        $st.className = 'wg-state ' + (data.state === 'connected' ? 'ok'
            : (data.state === 'disabled' ? '' : (data.error ? 'err' : 'busy')));
        $id('wg-pubkey').value = data.public_key || '';
    }

    function loadWireguard(statusOnly) {
        if (!$id('wg-enabled')) return;
        return fetch('/api/settings/wireguard')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                wgStatus(data);
                if (statusOnly) return;
                $id('wg-enabled').checked = !!data.enabled;
                $id('wg-peer').value = data.peer_public_key || '';
                $id('wg-endpoint').value = data.endpoint || '';
                $id('wg-port').value = data.port || 51820;
                $id('wg-address').value = data.address || '';
                $id('wg-netmask').value = data.netmask || '255.255.255.0';
                $id('wg-keepalive').value = (data.keepalive != null) ? data.keepalive : 25;
                $id('wg-psk').value = '';
                $id('wg-psk').placeholder = data.has_psk ? t('(stored - empty = keep, "-" = remove)') : t('optional');
                $id('wg-privkey').value = '';
            })
            .catch(function() { /* ignore */ });
    }

    /* Refresh the tunnel status while the settings page is open */
    setInterval(function() {
        var sec = $id('sec-settings');
        if (sec && sec.classList.contains('active') && !document.hidden) loadWireguard(true);
    }, 5000);

    window.wgCopyPub = function() {
        var v = $id('wg-pubkey').value;
        if (!v) { toast(t('Generate a key pair first'), 'error'); return; }
        if (navigator.clipboard) navigator.clipboard.writeText(v).then(function() { toast(t('Public key copied'), 'success'); });
        else { $id('wg-pubkey').select(); document.execCommand('copy'); toast(t('Public key copied'), 'success'); }
    };

    window.wgGenKey = function() {
        if ($id('wg-pubkey').value &&
            !confirm(t('Create a NEW key pair? The old key stops working - the public key must be updated on the peer.'))) return;
        fetch('/api/settings/wireguard/genkey', { method: 'POST' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.ok) { $id('wg-pubkey').value = data.public_key; toast(t('Key pair generated'), 'success'); }
                else toast(data.error || t('Key generation failed'), 'error');
            })
            .catch(function() { toast(t('Request failed'), 'error'); });
    };

    window.saveWireguard = function() {
        var body = {
            enabled: $id('wg-enabled').checked,
            peer_public_key: $id('wg-peer').value.trim(),
            endpoint: $id('wg-endpoint').value.trim(),
            port: parseInt($id('wg-port').value, 10) || 51820,
            address: $id('wg-address').value.trim(),
            netmask: $id('wg-netmask').value.trim(),
            keepalive: parseInt($id('wg-keepalive').value, 10) || 0,
            preshared_key: $id('wg-psk').value.trim(),
            private_key: $id('wg-privkey').value.trim()
        };
        fetch('/api/settings/wireguard', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.ok) { toast(t('WireGuard settings saved'), 'success'); loadWireguard(); }
            else toast(data.error || t('Save failed'), 'error');
        })
        .catch(function() { toast(t('Request failed'), 'error'); });
    };

    window.wgShowConfig = function() {
        var pub = $id('wg-pubkey').value, addr = $id('wg-address').value.trim();
        if (!pub || !addr) { toast(t('Generate a key and set the tunnel address first'), 'error'); return; }
        var cfg = '[Peer]\n# usbip-esp32p4\nPublicKey = ' + pub + '\nAllowedIPs = ' + addr + '/32\n';
        if ($id('wg-psk').placeholder.indexOf('stored') === 0 || $id('wg-psk').value)
            cfg += 'PresharedKey = <same preshared key>\n';
        $id('wg-peercfg').value = cfg;
        $id('wg-peercfg').style.display = 'block';
    };

    /* --- Transport encryption (USB/IP over TLS, HTTPS) --- */

    var secState = {};

    function loadSecurity() {
        if (!document.getElementById('sec-https')) return;
        return fetch('/api/settings/security')
            .then(function(r) { return r.json(); })
            .then(function(d) {
                secState = d;
                var radios = document.querySelectorAll('input[name="tls-mode"]');
                for (var i = 0; i < radios.length; i++) radios[i].checked = (parseInt(radios[i].value, 10) === d.usbip_tls_mode);
                document.getElementById('sec-https').checked = !!d.https;
                document.getElementById('sec-fp').textContent = d.cert_fp || t('(no certificate yet)');
                var note = document.getElementById('sec-https-note');
                note.textContent = (d.https !== d.https_active) ? t('Restart required to apply.') :
                    (d.https_active ? t('Active') + ': https://' + location.hostname + '/' : '');
                document.getElementById('sec-tls-info').textContent = 'Port ' + d.tls_port +
                    ' · ' + t('active TLS sessions') + ': ' + d.tls_sessions;
            })
            .catch(function() { /* ignore */ });
    }

    function tlsModeValue() {
        var r = document.querySelector('input[name="tls-mode"]:checked');
        return r ? parseInt(r.value, 10) : 0;
    }

    window.saveSecurity = function() {
        var https = document.getElementById('sec-https').checked;
        var mode = tlsModeValue();
        if (mode === 2 && !confirm(t('TLS only: plain USB/IP connections (port 3240) will be refused. Clients need stunnel. Continue?'))) return;
        if (https !== !!secState.https_active &&
            !confirm(t('HTTPS change takes effect after a restart. The web UI will then be at ') +
                     (https ? 'https://' : 'http://') + location.hostname + '/ . Your browser will warn once about the self-signed certificate - compare the fingerprint shown here.')) return;
        fetch('/api/settings/security', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usbip_tls_mode: mode, https: https })
        })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d.ok) { toast(t('Encryption settings saved'), 'success'); loadSecurity(); }
            else toast(d.error || t('Save failed'), 'error');
        })
        .catch(function() { toast(t('Request failed'), 'error'); });
    };

    function pskRequest(action) {
        return fetch('/api/settings/security/psk', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: action })
        }).then(function(r) { return r.json(); });
    }

    var lastPsk = null;

    function stunnelOs() {
        var r = document.querySelector('input[name="stunnel-os"]:checked');
        return r ? r.value : 'linux';
    }

    function showStunnel(d) {
        if (d) lastPsk = d;
        d = lastPsk;
        if (!d) return;
        var host = location.hostname;
        var port = secState.tls_port || 3241;
        var common = '[usbip]\nclient = yes\naccept = 127.0.0.1:3240\nconnect = ' + host + ':' + port + '\n';
        var tail = 'PSKidentity = ' + d.identity + '\n' +
            'sslVersionMax = TLSv1.2\n' +
            'ciphers = ECDHE-PSK-CHACHA20-POLY1305:ECDHE-PSK-AES128-CBC-SHA256:PSK-AES128-GCM-SHA256\n\n';
        var txt;
        if (stunnelOs() === 'windows') {
            var dir = 'C:\\Program Files (x86)\\stunnel\\config';
            txt = '; ' + dir + '\\stunnel.conf  (replace the example services in it)\n' +
                  '; 64-bit installer: C:\\Program Files\\stunnel\\config - adjust both paths\n' +
                  common + 'PSKsecrets = ' + dir + '\\usbip.psk\n' + tail +
                  '; ' + dir + '\\usbip.psk  (one line)\n' + d.identity + ':' + d.psk + '\n\n' +
                  '; Admin console:\n;   stunnel.exe -install\n;   net start stunnel\n' +
                  '; then:\n;   usbip.exe attach -r 127.0.0.1 -b <busid>\n';
        } else {
            txt = '# /etc/stunnel/usbip.conf\n' + common +
                  'PSKsecrets = /etc/stunnel/usbip.psk\n' + tail +
                  '# /etc/stunnel/usbip.psk  (chmod 600)\n' + d.identity + ':' + d.psk + '\n\n' +
                  '# then:  sudo usbip attach -r 127.0.0.1 -b <busid>\n';
        }
        document.getElementById('sec-psk').value = d.psk;
        document.getElementById('sec-stunnel').value = txt;
        document.getElementById('sec-stunnel-box').style.display = 'block';
    }

    var osRadios = document.querySelectorAll('input[name="stunnel-os"]');
    for (var oi = 0; oi < osRadios.length; oi++) {
        osRadios[oi].addEventListener('change', function() { showStunnel(); });
    }

    window.secShowPsk = function() {
        pskRequest('show').then(function(d) {
            if (d.ok) showStunnel(d); else toast(d.error || t('Failed'), 'error');
        }).catch(function() { toast(t('Request failed'), 'error'); });
    };

    window.secRegenPsk = function() {
        if (!confirm(t('Create a new TLS key? Existing stunnel configurations stop working.'))) return;
        pskRequest('regenerate').then(function(d) {
            if (d.ok) { showStunnel(d); toast(t('New TLS key created'), 'success'); }
            else toast(d.error || t('Failed'), 'error');
        }).catch(function() { toast(t('Request failed'), 'error'); });
    };

    window.secRegenCert = function() {
        if (!confirm(t('Create a new HTTPS certificate? It is used after the next restart; browsers will warn again.'))) return;
        fetch('/api/settings/security/cert', { method: 'POST' })
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.ok) { toast(t('New certificate created (active after restart)'), 'success'); loadSecurity(); }
                else toast(d.error || t('Failed'), 'error');
            })
            .catch(function() { toast(t('Request failed'), 'error'); });
    };

    /* --- ACL --- */

    var $aclRadios = document.querySelectorAll('input[name="acl-mode"]');
    var $aclListSection = document.getElementById('acl-list-section');
    var $aclList = document.getElementById('acl-list');
    var $aclNewType = document.getElementById('acl-new-type');
    var $aclNewValue = document.getElementById('acl-new-value');
    var $aclNewComment = document.getElementById('acl-new-comment');
    var aclMe = { ip: '', mac: '' };

    for (var ai = 0; ai < $aclRadios.length; ai++) {
        $aclRadios[ai].addEventListener('change', function() {
            $aclListSection.style.display = this.value === 'closed' ? 'block' : 'none';
        });
    }
    $aclNewType.addEventListener('change', function() {
        $aclNewValue.placeholder = this.value === 'mac' ? 'aa:bb:cc:dd:ee:ff' : '192.168.1.100';
    });

    function loadAclSettings() {
        return fetch('/api/settings/acl')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                /* Set mode radio */
                var mode = data.closed ? 'closed' : 'open';
                for (var i = 0; i < $aclRadios.length; i++) {
                    $aclRadios[i].checked = ($aclRadios[i].value === mode);
                }
                $aclListSection.style.display = data.closed ? 'block' : 'none';

                aclEntries = data.entries || [];
                aclMe = { ip: data.me_ip || '', mac: data.me_mac || '' };
                document.getElementById('acl-add-me').style.display = aclMe.ip ? '' : 'none';
                document.getElementById('acl-me-info').textContent = aclMe.ip
                    ? t('Dieser PC') + ': ' + aclMe.ip + (aclMe.mac ? ' / ' + aclMe.mac : ' (' + t('MAC unbekannt, nicht im selben LAN') + ')')
                    : '';
                renderAclList();
            })
            .catch(function() { /* ignore */ });
    }

    function renderAclList() {
        if (!$aclList) return;
        if (!aclEntries.length) {
            $aclList.innerHTML = '<div class="text-dim" style="padding:0.5rem 0;font-size:0.8125rem">' + t('No entries in allowlist') + '</div>';
            return;
        }
        var html = '';
        for (var i = 0; i < aclEntries.length; i++) {
            var e = aclEntries[i];
            html += '<div class="acl-item">' +
                '<span class="acl-type">' + (e.type === 'mac' ? 'MAC' : 'IP') + '</span>' +
                '<span class="acl-ip">' + esc(e.value) + '</span>' +
                '<span class="acl-comment">' + esc(e.comment || '') + '</span>' +
                '<button onclick="window._removeAclEntry(' + i + ')">' + t('Remove') + '</button>' +
                '</div>';
        }
        $aclList.innerHTML = html;
    }

    window._removeAclEntry = function(index) {
        aclEntries.splice(index, 1);
        renderAclList();
    };

    function normMac(v) {
        var m = v.trim().toLowerCase().replace(/-/g, ':');
        return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(m) ? m : null;
    }

    function pushAclEntry(type, value, comment) {
        if (type === 'mac') {
            value = normMac(value);
            if (!value) { toast(t('Invalid MAC address (aa:bb:cc:dd:ee:ff)'), 'error'); return false; }
        } else if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) {
            toast(t('Invalid IP address'), 'error');
            return false;
        }
        for (var i = 0; i < aclEntries.length; i++) {
            if (aclEntries[i].type === type && aclEntries[i].value === value) {
                toast(t('Already in list'), 'error');
                return false;
            }
        }
        if (aclEntries.length >= 32) { toast(t('List full (max 32)'), 'error'); return false; }
        aclEntries.push({ type: type, value: value, comment: comment.slice(0, 31) });
        renderAclList();
        return true;
    }

    window.addAclEntry = function() {
        var value = $aclNewValue.value.trim();
        if (!value) return;
        if (pushAclEntry($aclNewType.value, value, $aclNewComment.value.trim())) {
            $aclNewValue.value = '';
            $aclNewComment.value = '';
        }
    };

    window.addAclMe = function() {
        var type = $aclNewType.value;
        var value = type === 'mac' ? aclMe.mac : aclMe.ip;
        if (!value) { toast(t('MAC dieses PCs unbekannt (nicht im selben LAN) - IP verwenden'), 'error'); return; }
        if (pushAclEntry(type, value, $aclNewComment.value.trim())) $aclNewComment.value = '';
    };

    window.saveAcl = function() {
        var closed = false;
        for (var i = 0; i < $aclRadios.length; i++) {
            if ($aclRadios[i].checked && $aclRadios[i].value === 'closed') {
                closed = true;
                break;
            }
        }
        var body = {
            closed: closed,
            entries: aclEntries
        };
        fetch('/api/settings/acl', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.ok) {
                toast(t('ACL settings saved'), 'success');
                loadAclSettings();
            } else {
                toast(data.error || t('Save failed'), 'error');
            }
        })
        .catch(function() { toast(t('Request failed'), 'error'); });
    };

    window.resetUsbBus = function() {
        if (!confirm(t('Reset the USB bus? This disconnects and re-enumerates ALL devices and drops any attached clients.'))) return;
        fetch('/api/usb/reset', { method: 'POST' })
            .then(function(r) { toast(r.ok ? t('Action completed') : t('Action failed'), r.ok ? 'success' : 'error'); })
            .catch(function() { toast(t('Request failed'), 'error'); });
    };

    /* --- Restart / factory reset (with feedback; a silent failure looked like "nothing happens") --- */

    window.systemAction = function(what) {
        var reset = what === 'factory-reset';
        if (!confirm(reset ? t('Alle Einstellungen löschen und neu starten?') : t('Board neu starten?'))) return;
        fetch('/api/system/' + what, { method: 'POST' })
            .then(function(r) {
                return r.json().catch(function() { return {}; }).then(function(d) {
                    if (r.ok && d.ok !== false) {
                        toast(reset ? t('Werksreset - Board startet neu…') : t('Board startet neu…'), 'success');
                    } else {
                        toast((d.error || (t('Fehler') + ' ' + r.status)) + (r.status === 401 ? ' - ' + t('bitte neu anmelden') : ''), 'error');
                    }
                });
            })
            .catch(function() {
                /* the board may already be restarting and drop the connection */
                toast(t('Keine Antwort - Board startet vermutlich neu'), 'success');
            });
    };

    /* --- Software components (versions reported by the firmware) --- */

    var componentsLoaded = false;
    function loadComponents() {
        if (componentsLoaded) return;
        fetch('/api/system/components')
            .then(function(r) { return r.ok ? r.json() : null; })
            .then(function(list) {
                if (!list || !list.length) return;
                componentsLoaded = true;
                var html = '';
                for (var i = 0; i < list.length; i++) {
                    html += '<tr><td>' + esc(list[i].name) + '</td><td>' + esc(list[i].version) +
                            '</td><td>' + esc(list[i].license) + '</td></tr>';
                }
                document.getElementById('sw-board').innerHTML = html;
            })
            .catch(function() { /* ignore */ });
    }

    /* --- System info --- */

    function loadSystemInfo() {
        return fetch('/api/system/info')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var $ver = document.getElementById('sys-version');
                var $idf = document.getElementById('sys-idf');
                var $chip = document.getElementById('sys-chip');
                var $heap = document.getElementById('sys-heap');
                if ($ver) $ver.textContent = data.version || '--';
                var $sver = document.getElementById('sidebar-version');
                if ($sver && data.version) $sver.textContent = 'v' + data.version;
                if ($idf) $idf.textContent = data.idf_version || '--';
                if ($chip) $chip.textContent = (data.chip || 'ESP32-P4') + (data.revision ? ' ' + data.revision : '');
                if ($heap) $heap.textContent = Math.round((data.heap_free || 0) / 1024) + ' KB free';
                var $reset = document.getElementById('sys-reset');
                if ($reset && data.reset) {
                    $reset.textContent = data.reset;
                    $reset.style.color = data.crash ? 'var(--red)' : '';
                }
                var $crashes = document.getElementById('sys-crashes');
                if ($crashes && data.crashes !== undefined) $crashes.textContent = data.crashes;
                loadComponents();
                var $prev = document.getElementById('log-prev');
                if ($prev) $prev.style.display = data.prev_log > 0 ? '' : 'none';
            })
            .catch(function() { /* ignore */ });
    }

    /* ================================================================
     * Packet Capture
     * ================================================================ */

    var capState = { capturing: false, card_present: false };
    var capPollTimer = null;
    var capUnavailable = false;  /* firmware built without CONFIG_CAPTURE_ENABLED */

    function formatFileSize(bytes) {
        if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
        if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return bytes + ' B';
    }

    function pollCaptureStatus() {
        fetch('/api/capture/status')
            .then(function(r) {
                if (r.status === 404) return { available: false };
                return r.json();
            })
            .then(function(data) {
                if (!data) return;
                if (data.available === false) {
                    /* Capture not compiled in: hide the panel and stop polling for good */
                    capUnavailable = true;
                    stopCapturePoll();
                    var $panel = document.getElementById('cap-panel');
                    if ($panel) $panel.style.display = 'none';
                    return;
                }
                capState = data;
                var $card = document.getElementById('cap-card');
                var $status = document.getElementById('cap-status');
                var $filename = document.getElementById('cap-filename');
                var $size = document.getElementById('cap-size');
                var $packets = document.getElementById('cap-packets');
                var $dropped = document.getElementById('cap-dropped');
                var $toggle = document.getElementById('cap-toggle');
                var $download = document.getElementById('cap-download');
                var $delete = document.getElementById('cap-delete');

                if ($card) {
                    $card.textContent = data.card_present ? t('Present') : t('Not Found');
                    $card.style.color = data.card_present ? '#4caf50' : '#f44336';
                }
                if ($status) {
                    $status.textContent = data.capturing ? t('Recording') : t('Idle');
                    $status.style.color = data.capturing ? '#ff9800' : '';
                }
                if ($filename) $filename.textContent = data.filename || '--';
                if ($size) $size.textContent = formatFileSize(data.file_size || 0);
                if ($packets) $packets.textContent = data.packet_count || '0';
                if ($dropped) {
                    $dropped.textContent = data.dropped_count || '0';
                    $dropped.style.color = data.dropped_count > 0 ? '#ff9800' : '';
                }
                if ($toggle) {
                    $toggle.textContent = data.capturing ? t('Stop Capture') : t('Start Capture');
                    $toggle.disabled = !data.card_present && !data.capturing;
                }
                if ($download) $download.disabled = !data.filename || data.file_size === 0;
                if ($delete) $delete.disabled = !data.filename || data.file_size === 0 || data.capturing;
            })
            .catch(function() { /* ignore poll errors */ });
    }

    function startCapturePoll() {
        if (capPollTimer || capUnavailable) return;
        pollCaptureStatus();
        capPollTimer = setInterval(pollCaptureStatus, 2000);
    }

    function stopCapturePoll() {
        if (capPollTimer) {
            clearInterval(capPollTimer);
            capPollTimer = null;
        }
    }

    window.toggleCapture = function() {
        var url = capState.capturing ? '/api/capture/stop' : '/api/capture/start';
        fetch(url, { method: 'POST' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.ok) {
                    toast(capState.capturing ? t('Capture stopped') : t('Capture started') + ': ' + (data.filename || ''));
                } else {
                    toast(data.error || t('Capture error'), 'error');
                }
                pollCaptureStatus();
            })
            .catch(function() { toast(t('Request failed'), 'error'); });
    };

    window.downloadCapture = function() {
        window.location.href = '/api/capture/download';
    };

    window.deleteCapture = function() {
        if (!confirm(t('Delete the capture file?'))) return;
        fetch('/api/capture/delete', { method: 'POST' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.ok) {
                    toast(t('Capture file deleted'));
                } else {
                    toast(data.error || t('Delete failed'), 'error');
                }
                pollCaptureStatus();
            })
            .catch(function() { toast(t('Request failed'), 'error'); });
    };

    /* Start polling when on dashboard */
    var origSwitchSection = switchSection;
    switchSection = function(name) {
        origSwitchSection(name);
        if (name === 'dashboard') {
            startCapturePoll();
        } else {
            stopCapturePoll();
        }
    };

    /* Initial poll if starting on dashboard */
    if (activeSection === 'dashboard') {
        startCapturePoll();
    }

    /* ================================================================
     * Hash-based navigation
     * ================================================================ */

    function checkHash() {
        var hash = location.hash.replace('#', '');
        if (hash && ['dashboard', 'devices', 'topology', 'settings'].indexOf(hash) !== -1) {
            switchSection(hash);
        }
    }

    window.addEventListener('hashchange', checkHash);
    checkHash();

    /* ================================================================
     * Init
     * ================================================================ */

    i18nCaptureHelp();
    var $langSel = document.getElementById('lang-select');
    LANGS.forEach(function(l) {
        var o = document.createElement('option');
        o.value = l[0];
        o.textContent = l[1];
        $langSel.appendChild(o);
    });
    $langSel.addEventListener('change', function() { setLanguage(this.value, true); });
    applyTheme(theme);
    setLanguage(i18nPick(), false);
    document.getElementById('theme-toggle').addEventListener('click', function() {
        applyTheme(THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length]);
    });
    setHelpOs(helpOs);
    setAllText('h-host', location.hostname);
    fillHelpValues(null);
    wsConnect();
    loadSystemInfo();
    console.log('USB/IP WebUI loaded');

})();
