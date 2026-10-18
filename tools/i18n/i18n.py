#!/usr/bin/env python3
"""Web UI translations.

Collects the translatable texts from components/webui/frontend (index.html:
text nodes, placeholder/title; app.js: t('...') literals; help sections as
leaf blocks with <pre> replaced by {P0}...), keeps their numbering in keys.json
(new texts are appended, existing numbers never change) and builds
frontend/lang/xx.json from tr/xx.txt.

tr/xx.txt: one entry per line, "U<n>|text" (UI text n of keys.json) or
"H<n>|html" (help block n, in the order of the German source).

Usage (from the repository root):
    python3 tools/i18n/i18n.py           check + build all languages
    python3 tools/i18n/i18n.py --list    print all numbered texts (to translate new ones)

Missing translations only warn (the UI shows the source text); changed
placeholders, <code> contents or tags are errors.
"""
import collections, json, os, re, sys
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FRONT = os.path.join(ROOT, 'components', 'webui', 'frontend')
HERE = os.path.dirname(os.path.abspath(__file__))
LANGS = ['de', 'en', 'fr', 'es', 'it', 'pt', 'da', 'sv', 'ru', 'uk', 'tr', 'ar']
# Proper names / technical terms that are never translated
SKIP = {'USB/IP', 'ESP32-P4', 'DHCP', 'DNS', 'IP', 'MAC', 'Linux', 'ESP-IDF', 'CPU', 'vpn.example.org',
        'usbip-esp32p4', 'Windows 10/11', 'VID:PID', 'IN:', 'OUT:', '--'}
# Values set by app.js at runtime, not visible in index.html
EXTRA = ['Available', 'Exported', 'Error', 'Unknown', 'Auto', 'Dunkel', 'Hell']

SKIP_TAGS = {'script', 'style', 'svg', 'pre', 'code'}
VOID = {'input', 'br', 'img', 'meta', 'link', 'hr', 'source', 'circle', 'rect', 'path', 'line', 'polyline'}


class UiText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.ui = [], []

    def skipping(self):
        return any(t in SKIP_TAGS or a.get('data-help') or (a.get('class') or '').startswith('h-')
                   or a.get('translate') == 'no' for t, a in self.stack)

    def handle_starttag(self, t, attrs):
        a = dict(attrs)
        if not self.skipping():
            for k in ('placeholder', 'title', 'aria-label'):
                if a.get(k) and re.search(r'[A-Za-zÄÖÜäöü]{2}', a[k]):
                    self.ui.append(a[k])
        if t not in VOID:
            self.stack.append((t, a))

    def handle_endtag(self, t):
        if t in VOID:
            return
        while self.stack:
            if self.stack.pop()[0] == t:
                break

    def handle_data(self, d):
        txt = ' '.join(d.split())
        if txt and not self.skipping() and re.search(r'[A-Za-zÄÖÜäöü]{2}', txt):
            self.ui.append(txt)


def collect():
    html = open(os.path.join(FRONT, 'index.html'), encoding='utf-8').read()
    js = open(os.path.join(FRONT, 'app.js'), encoding='utf-8').read()
    p = UiText()
    p.feed(html)
    lits = [m.group(1).replace("\\'", "'") for m in re.finditer(r"\bt\('((?:[^'\\]|\\.)*)'\)", js)]
    keys = []
    for k in p.ui + lits + EXTRA:
        if k not in keys and k not in SKIP:
            keys.append(k)
    # help: leaf li/p/summary blocks, <pre> -> {Pn}; mirrors i18nCaptureHelp() in app.js
    units = []
    for m in re.finditer(r'<details class="help" data-help="[a-z]+">(.*?)</details>', html, re.S):
        for b in re.finditer(r'<(li|p|summary)(\s[^>]*)?>(.*?)</\1>', m.group(1), re.S):
            inner = b.group(3)
            if re.search(r'<(li|p)\b', inner):
                continue
            n = iter(range(100))
            key = ' '.join(re.sub(r'<pre>.*?</pre>', lambda _: '{P%d}' % next(n), inner, flags=re.S).split())
            if re.search(r'[A-Za-zÄÖÜäöü]{3}', re.sub(r'<[^>]+>|\{P\d+\}', '', key)) and key not in units:
                units.append(key)
    return keys, units


def tags(s):
    c = collections.Counter(re.findall(r'</?(?:b|code|span[^>]*)>|\{P?\d*n?\}', s))
    c.update('CODE:' + x for x in re.findall(r'<code>(.*?)</code>', s))
    return c


def main():
    keys_now, units = collect()
    kfile = os.path.join(HERE, 'keys.json')
    keys = json.load(open(kfile, encoding='utf-8')) if os.path.exists(kfile) else []
    new = [k for k in keys_now if k not in keys]
    keys += new                                   # existing numbers never change
    json.dump(keys, open(kfile, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    gone = [i for i, k in enumerate(keys) if k not in keys_now]

    if '--list' in sys.argv:
        for i, k in enumerate(keys):
            print('U%d|%s%s' % (i, k, '   (unused)' if i in gone else ''))
        for i, u in enumerate(units):
            print('H%d|%s' % (i, u))
        return 0

    ok = True
    for lang in LANGS:
        tr = {}
        for ln, line in enumerate(open(os.path.join(HERE, 'tr', lang + '.txt'), encoding='utf-8'), 1):
            line = line.rstrip('\n')
            if not line.strip():
                continue
            m = re.match(r'([UH])(\d+)\|(.*)$', line)
            if not m:
                print('%s.txt:%d: bad line' % (lang, ln)); ok = False; continue
            tr[(m.group(1), int(m.group(2)))] = m.group(3)
        ui, help_, missing = {}, {}, []
        for i, k in enumerate(keys):
            if i in gone:
                continue
            v = tr.get(('U', i))
            if v is None:
                missing.append('U%d' % i); continue
            if ('{n}' in k) != ('{n}' in v):
                print('%s: U%d placeholder {n} lost' % (lang, i)); ok = False
            if v != k:
                ui[k] = v
        for i, k in enumerate(units):
            v = tr.get(('H', i))
            if v is None:
                if lang != 'de':                  # German help is the source
                    missing.append('H%d' % i)
                continue
            if tags(k) != tags(v):
                print('%s: H%d markup differs from the source' % (lang, i)); ok = False
            if v != k:
                help_[k] = v
        out = os.path.join(FRONT, 'lang', lang + '.json')
        json.dump({'ui': ui, 'help': help_}, open(out, 'w', encoding='utf-8'), ensure_ascii=False, separators=(',', ':'))
        print('%-3s %3d ui, %2d help%s' % (lang, len(ui), len(help_),
              ('   missing: ' + ' '.join(missing)) if missing else ''))
    if new:
        print('new texts (translate in tr/*.txt):', ', '.join('U%d' % keys.index(k) for k in new))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
