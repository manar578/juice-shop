import json, os, html

R = 'reports'
e = html.escape

def load(name):
    try:
        with open(os.path.join(R, name)) as f:
            return json.load(f)
    except Exception:
        return None

def table(headers, rows):
    if not rows:
        return '<p>Aucun résultat.</p>'
    h = ''.join('<th>' + e(x) + '</th>' for x in headers)
    b = ''.join('<tr>' + ''.join('<td>' + e(str(c)) + '</td>' for c in r) + '</tr>' for r in rows)
    return '<table><tr>' + h + '</tr>' + b + '</table>'

parts = []

g = load('gitleaks.json')
if g is not None:
    rows = [(x.get('RuleID'), x.get('File'), x.get('StartLine')) for x in g]
    parts.append(('Gitleaks : secrets', str(len(g)) + ' fuite(s) non exemptée(s)',
                  table(['Règle', 'Fichier', 'Ligne'], rows)))

sg = load('semgrep.json')
if sg is not None:
    res = sg.get('results', [])
    rows = sorted((x['extra']['severity'], x['path'], x['start']['line'],
                   x['check_id'].split('.')[-1]) for x in res)
    nerr = len([r for r in rows if r[0] == 'ERROR'])
    parts.append(('Semgrep : analyse du code (SAST)',
                  str(len(res)) + ' résultat(s), dont ' + str(nerr) + ' ERROR',
                  table(['Sévérité', 'Fichier', 'Ligne', 'Règle'], rows)))

def trivy(name, title):
    t = load(name)
    if t is None:
        return
    vulns = []
    for r in t.get('Results', []):
        vulns += r.get('Vulnerabilities') or []
    crit = [v for v in vulns if v.get('Severity') == 'CRITICAL']
    rows = sorted(set((v['VulnerabilityID'], v['PkgName'], v['InstalledVersion'],
                       v.get('FixedVersion') or 'aucun') for v in crit))
    parts.append((title, str(len(vulns)) + ' vulnérabilité(s), dont ' + str(len(crit)) + ' CRITICAL',
                  table(['CVE', 'Paquet', 'Version installée', 'Version corrigée'], rows)))

trivy('trivy-fs.json', 'Trivy : dépendances (SCA)')
trivy('trivy-image.json', 'Trivy : image Docker')

z = load('zap-report.json')
if z is not None:
    alerts = [a for site in z.get('site', []) for a in site.get('alerts', [])]
    rows = sorted(((a.get('riskdesc'), a.get('name')) for a in alerts), reverse=True)
    parts.append(('OWASP ZAP : analyse dynamique (DAST)', str(len(alerts)) + ' alerte(s)',
                  table(['Risque', 'Alerte'], rows)))

body = ''.join('<h2>' + e(t) + '</h2><p><b>' + e(s) + '</b></p>' + tb for t, s, tb in parts)
page = ('<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">'
        '<title>Rapport de sécurité</title><style>'
        'body{font-family:sans-serif;max-width:960px;margin:2em auto;padding:0 1em}'
        'table{border-collapse:collapse;width:100%;margin-bottom:1.5em}'
        'th,td{border:1px solid #ccc;padding:6px 10px;text-align:left}'
        'th{background:#eee}</style></head><body>'
        '<h1>Rapport de sécurité DevSecOps, build #' + os.environ.get('BUILD_NUMBER', '?') + '</h1>'
        + body + '</body></html>')

with open(os.path.join(R, 'rapport-securite.html'), 'w', encoding='utf-8') as f:
    f.write(page)
print('Rapport HTML généré')
