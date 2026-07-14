# Plan d’action SecFlowOps — passage d’une simulation paramétrée à un déploiement réel

## 0. Objectif scientifique

L’objectif n’est pas de corriger marginalement l’article de simulation, mais de produire une nouvelle contribution expérimentale : **SecFlowOps**, une validation réelle du principe SecFlow dans un pipeline CI/CD opérationnel, avec de vrais outils DevSecOps, de vrais dépôts, des workflows exécutables, des métriques collectées automatiquement, des artefacts reproductibles et une rédaction scientifique autonome.

Le nouvel article doit distinguer explicitement :

- ce qui venait de l’ancien article : architecture SecFlow, six configurations, ablation Policy-Only / Agents-Only, métriques MTTR/MTTD/couverture/taux de remédiation/taux de succès pipeline ;
- ce qui devient nouveau : exécution réelle dans CI/CD, OPA/Rego réel, scanners réels, agents de remédiation réels ou semi-autonomes, branches/PRs réelles, journaux CI réels, artefacts vérifiables ;
- ce qui reste limité : absence éventuelle d’organisation partenaire, taille du corpus, caractère contrôlé des vulnérabilités injectées, absence éventuelle d’étude humaine directe si elle n’est pas menée.

## 1. Répertoire cible à créer

Créer un répertoire racine :

```text
SecFlowOps/
```

Structure minimale attendue :

```text
SecFlowOps/
├── README.md
├── PROMPT_SECFLOWOPS_REAL_DEPLOYMENT.md
├── PROTOCOL.md
├── THREAT_MODEL.md
├── ETHICS_AND_SAFETY.md
├── REPRODUCIBILITY.md
├── literature/
│   ├── search_protocol.md
│   ├── screening_log.csv
│   ├── related_work_matrix.csv
│   ├── references.bib
│   └── verified_sources.md
├── repos/
│   ├── README.md
│   ├── selected_repositories.csv
│   └── ground_truth/
├── workflows/
│   ├── github-actions/
│   ├── reusable/
│   └── templates/
├── policies/
│   ├── rego/
│   ├── tests/
│   └── policy_manifest.yml
├── scanners/
│   ├── semgrep/
│   ├── codeql/
│   ├── trivy/
│   ├── gitleaks/
│   ├── zap/
│   └── dependabot/
├── secflowops/
│   ├── normalizer/
│   ├── policy_gate/
│   ├── agents/
│   ├── collector/
│   ├── metrics/
│   └── dashboard/
├── experiments/
│   ├── design_matrix.csv
│   ├── runbook.md
│   ├── preregistration.md
│   └── raw_logs_manifest.csv
├── data/
│   ├── raw/
│   ├── normalized/
│   ├── processed/
│   └── manual_labels/
├── scripts/
│   ├── run_matrix.py
│   ├── normalize_findings.py
│   ├── compute_metrics.py
│   ├── statistical_analysis.py
│   └── generate_figures.py
├── figures/
├── tables/
├── paper/
│   ├── main.tex
│   ├── sections/
│   ├── figures/
│   ├── tables/
│   └── references.bib
└── artifact/
    ├── README_REPRODUCE.md
    ├── environment.yml
    ├── requirements.txt
    ├── docker-compose.yml
    └── checksums.sha256
```

## 2. Principe de la nouvelle contribution

### 2.1 Ancienne contribution à conserver

Conserver les éléments conceptuels suivants :

1. architecture SecFlow en couches : CI/CD, scanners, Policy Engine, agents, observabilité ;
2. six configurations expérimentales ;
3. ablation isolant Policy-as-Code et agents ;
4. décision de politique sur findings résiduels après remédiation ;
5. règles de blocage initiales : zéro critique résiduelle, seuil de vulnérabilités high, plafond CVSS, absence de secret ;
6. métriques : MTTD, MTTR, temps pipeline, couverture, faux positifs, faux négatifs, taux de remédiation autonome, succès pipeline ;
7. analyse de sensibilité sur les politiques de gating et la fiabilité de remédiation.

### 2.2 Nouvelle contribution à produire

Le nouvel article doit pouvoir annoncer, sans surclaim :

> We present SecFlowOps, a real CI/CD deployment and artifact-backed evaluation of an integrated DevSecOps pipeline combining Policy-as-Code, multi-layer scanning, and semi-autonomous remediation.

Ne pas annoncer “production-ready” sans déploiement organisationnel réel.

## 3. Périmètre expérimental réaliste

### 3.1 Plateforme CI/CD

Option recommandée : GitHub Actions avec runner Linux fixe.

Deux modes possibles :

- **Mode A — self-hosted runner** : préférable pour contrôler CPU/RAM/cache/réseau ;
- **Mode B — GitHub-hosted runner** : acceptable si les limites de variabilité sont documentées.

Le protocole doit enregistrer pour chaque run :

- OS ;
- type de runner ;
- CPU/RAM visibles ;
- versions des actions ;
- versions des scanners ;
- commit SHA ;
- branche ;
- heure de début/fin ;
- état des caches ;
- résultat build/test/scan/gate/remediation.

### 3.2 Outils DevSecOps réels

Outils recommandés :

| Couche | Outil principal | Sortie exploitable |
|---|---|---|
| SAST | Semgrep CE + CodeQL si disponible | JSON/SARIF |
| SCA | Dependabot, OSV-Scanner, pip-audit/npm audit selon langage | JSON/GitHub alerts |
| Secrets | Gitleaks + GitHub secret scanning si dépôt public | JSON/SARIF/alerts |
| Containers/IaC | Trivy | JSON/SARIF |
| DAST | OWASP ZAP baseline ou full scan sur app locale/staging | JSON/XML/HTML |
| Policy-as-Code | OPA/Rego | JSON decision logs |
| Supply chain posture | OpenSSF Scorecard | JSON |
| Remédiation | Dependabot PRs, Semgrep autofix si possible, RemediatorAgent contrôlé | PRs/patches/tests |

Remarque : l’usage de GitHub Advanced Security, secret scanning privé ou Copilot Autofix dépend des droits disponibles. Si indisponible, documenter l’indisponibilité et utiliser les alternatives open-source.

## 4. Sélection des dépôts et données

### 4.1 Types de dépôts

Utiliser uniquement :

- dépôts possédés par l’auteur ;
- forks contrôlés ;
- benchmarks volontairement vulnérables ;
- applications de démonstration locales ;
- jamais des systèmes tiers non autorisés.

Corpus minimal recommandé :

| Classe | Objectif | Exemple de contenu |
|---|---|---|
| App API | SAST/SCA/secrets/DAST | REST API Node/Python |
| App web conteneurisée | DAST/container scan | Dockerfile + endpoint local |
| Microservice IaC | OPA/Trivy IaC | Docker/Kubernetes/Terraform minimal |
| Dépôt dépendances vulnérables | SCA/remédiation | lockfile avec versions vulnérables connues |

### 4.2 Ground truth

Le nouvel article ne doit plus utiliser une population de vulnérabilités synthétique non vérifiable. Construire un ground truth traçable :

1. **Vulnérabilités injectées contrôlées** : chaque vulnérabilité a un identifiant, un fichier, une ligne, un CWE/CVE si applicable, un commit d’introduction et un commit de correction attendu.
2. **Vulnérabilités de benchmark** : utiliser les labels officiels des benchmarks si disponibles.
3. **Vulnérabilités SCA** : associer les dépendances à OSV/GHSA/NVD quand possible.
4. **Secrets** : utiliser seulement des secrets factices, invalides, marqués comme test secrets ; ne jamais publier de credential réel.
5. **Validation manuelle** : au moins deux annotateurs pour un sous-ensemble critique ; calculer l’accord inter-annotateurs si l’étude prétend mesurer précision/faux positifs.

Fichier attendu :

```text
repos/ground_truth/ground_truth_findings.csv
```

Colonnes minimales :

```csv
finding_id,repo,branch,commit_intro,commit_fix,file,line_start,line_end,type,cwe,cve,tool_expected,severity,cvss,source,expected_detection,expected_remediation,notes
```

## 5. Configurations expérimentales

Conserver six configurations, mais les rendre opérationnelles :

| ID | Configuration | Description réelle |
|---|---|---|
| C0 | BuildOnly | build + tests, aucun scan bloquant |
| C1 | ManualSecurity | scans générés, triage/correction manuelle ou semi-manuelle mesurée via issues/PRs ; si aucun humain, renommer en NonBlockingSecurity |
| C2 | AutoScanning | scanners réels, rapports normalisés, pas de policy gate, pas de remédiation auto |
| C3 | PolicyOnly | scanners + OPA/Rego gate, pas d’agent de remédiation |
| C4 | AgentsOnly | scanners + agent ouvrant PR/patchs, pas de gate OPA bloquant |
| C5 | SecFlowOps | scanners + agent + OPA/Rego gate sur findings résiduels |

Important : si la configuration C1 n’implique pas de vraie intervention humaine mesurée, ne pas l’appeler “Manual Security”. L’appeler “NonBlocking Scanning” ou “Report-Only Security”.

## 6. Design expérimental

### 6.1 Unité expérimentale

Un run = exécution complète d’un workflow CI/CD sur un commit expérimental donné, pour une configuration donnée, sur un dépôt donné.

### 6.2 Plan minimal recommandé

Minimum défendable :

```text
3 dépôts × 8 scénarios de vulnérabilités × 6 configurations × 3 répétitions = 432 runs CI
```

Plan plus solide :

```text
5 dépôts × 10 scénarios × 6 configurations × 5 répétitions = 1500 runs CI
```

Chaque scénario doit être exécuté dans les six configurations sur le même commit de départ. Randomiser l’ordre des configurations pour limiter les effets de cache et de charge.

### 6.3 Scénarios

Créer des scénarios défensifs, contrôlés et documentés :

- dépendance vulnérable connue ;
- secret factice ;
- règle Semgrep détectable ;
- configuration Docker/Kubernetes non conforme ;
- image conteneur avec vulnérabilité connue ;
- endpoint web local détectable par DAST passif ;
- combinaison multi-couche ;
- scénario sans vulnérabilité pour mesurer les faux positifs.

Ne pas inclure d’instructions d’attaque contre des systèmes tiers.

## 7. Architecture SecFlowOps réelle

### 7.1 Pipeline général

```text
Commit/PR
  → Build/Test
  → SAST/SCA/Secret/Container/IaC scans en parallèle
  → Normalisation JSON commune
  → RemediatorAgent facultatif selon configuration
  → OPA/Rego Policy Gate facultatif selon configuration
  → Staging local facultatif
  → DAST ZAP si endpoint disponible
  → Post-DAST policy decision
  → Collecte métriques
  → Export CSV/JSON/SARIF/Markdown
```

### 7.2 Schéma de findings

Fichier attendu :

```text
secflowops/normalizer/schemas/finding.schema.json
```

Champs minimaux :

```json
{
  "finding_id": "string",
  "tool": "semgrep|codeql|trivy|gitleaks|zap|dependabot|opa|scorecard|manual",
  "category": "sast|sca|secret|container|iac|dast|policy|supply_chain",
  "repo": "string",
  "commit": "string",
  "file": "string|null",
  "line_start": "integer|null",
  "line_end": "integer|null",
  "cwe": "string|null",
  "cve": "string|null",
  "severity": "critical|high|medium|low|info",
  "cvss": "number|null",
  "message": "string",
  "fingerprint": "string",
  "is_ground_truth": "boolean|null",
  "is_false_positive": "boolean|null",
  "remediated": "boolean",
  "remediation_method": "none|dependabot|semgrep_autofix|rule_based_agent|llm_agent|manual",
  "timestamps": {
    "introduced_at": "string|null",
    "detected_at": "string|null",
    "patch_proposed_at": "string|null",
    "patch_validated_at": "string|null",
    "gate_decided_at": "string|null"
  }
}
```

### 7.3 Policy Engine OPA/Rego

Règles minimales :

- deny if residual critical > 0 ;
- deny if residual high > threshold ;
- deny if max CVSS > threshold ;
- deny if residual secret > 0 ;
- warn if coverage < threshold ;
- warn if tool failure not justified ;
- deny if DAST target unavailable in configurations où DAST est obligatoire.

Écrire des tests OPA unitaires pour chaque règle.

## 8. RemediatorAgent réel ou semi-autonome

Le RemediatorAgent doit être implémenté avec niveaux de risque :

| Niveau | Type de patch | Action autorisée |
|---|---|---|
| R0 | dépendance patch/minor compatible | PR automatique, pas d’auto-merge |
| R1 | Semgrep autofix localisé | PR automatique après tests |
| R2 | patch rule-based sur exemple contrôlé | PR automatique avec label `needs-review` |
| R3 | patch LLM non trivial | PR seulement, revue humaine obligatoire |
| R4 | secret réel ou suspicion de secret réel | pas de patch automatique ; alerte + rotation manuelle |

Règle absolue : aucun agent ne pousse directement sur `main`. Tout passe par branche + PR + tests + logs.

Métriques de l’agent :

- nombre de findings pris en charge ;
- nombre de PRs ouvertes ;
- nombre de PRs vertes ;
- nombre de PRs rejetées ;
- taux de patch qui supprime le finding ;
- taux de patch qui casse les tests ;
- délai détection → PR ;
- délai PR → tests verts ;
- intervention humaine requise.

## 9. Métriques à collecter

### 9.1 Métriques primaires

- pipeline_time_seconds ;
- MTTD_seconds ;
- MTTR_seconds ;
- time_to_patch_pr_seconds ;
- time_to_green_patch_seconds ;
- security_coverage ;
- precision ;
- recall ;
- false_positive_rate ;
- false_negative_rate ;
- auto_remediation_rate ;
- patch_success_rate ;
- policy_gate_pass_rate ;
- pipeline_success_rate ;
- human_escalation_rate.

### 9.2 Métriques secondaires

- nombre d’alertes par PR ;
- nombre d’alertes critiques/high résiduelles ;
- nombre de secrets détectés ;
- nombre de dépendances vulnérables corrigées ;
- taille du patch ;
- nombre de fichiers modifiés ;
- durée par scanner ;
- failures/outages des outils ;
- cache hit/miss.

### 9.3 Charge cognitive

Deux options :

- **Option sans étude humaine** : ne parler que de proxy de charge, par exemple alertes à trier, PRs ouvertes, escalades humaines, taux de faux positifs ; ne pas conclure sur la charge cognitive réelle.
- **Option avec étude humaine** : protocole éthique, consentement, NASA-TLX ou questionnaire validé, tâches comparables, randomisation, population décrite. Sans cette étude, ne pas écrire “reduced cognitive load” comme résultat direct.

## 10. Analyse statistique

### 10.1 Principe

Les données réelles seront hiérarchiques : runs imbriqués dans dépôts, scénarios, commits et configurations. Éviter une simple série de t-tests comme preuve principale.

### 10.2 Analyses recommandées

- statistiques descriptives : moyenne, médiane, écart-type, IQR ;
- intervalles de confiance bootstrap 95 % ;
- modèles mixtes ou régression robuste avec effets aléatoires dépôt/scénario ;
- tests de Welch ou Mann-Whitney seulement comme analyse complémentaire ;
- correction Holm-Bonferroni ou Benjamini-Hochberg selon l’objectif ;
- tailles d’effet : Cliff’s delta, Cohen’s d si conditions satisfaites, odds ratio pour pass/fail ;
- analyse de sensibilité sur seuils OPA : critical tolerance, high threshold, CVSS ceiling, secret rule ;
- analyse d’ablation : contribution marginale de Policy Engine et agent.

### 10.3 À éviter

- déclarer une généralisation industrielle à partir de 2–3 dépôts ;
- présenter p < 0.05 comme preuve suffisante ;
- ignorer les runs échoués ;
- supprimer les outliers sans protocole pré-enregistré ;
- mélanger des findings multiples d’un même commit comme observations indépendantes sans correction.

## 11. Revue de littérature enrichie

### 11.1 Sources primaires et officielles à consulter

- OPA/Rego : https://openpolicyagent.org/docs
- GitHub Actions : https://docs.github.com/actions
- GitHub CodeQL/code scanning : https://docs.github.com/code-security/code-scanning
- GitHub Dependabot : https://docs.github.com/code-security/getting-started/dependabot-quickstart-guide
- GitHub secret scanning : https://docs.github.com/code-security/secret-scanning/about-secret-scanning
- Semgrep docs : https://semgrep.dev/docs
- Trivy docs : https://trivy.dev/latest/docs
- Gitleaks repo/docs : https://github.com/gitleaks/gitleaks
- OWASP ZAP docs : https://www.zaproxy.org/docs
- OpenSSF Scorecard : https://scorecard.dev
- NIST SP 800-204D : https://csrc.nist.gov/pubs/sp/800/204/d/final

### 11.2 Requête de recherche bibliographique

Utiliser Semantic Scholar API si la clé de l’auteur est disponible, sinon Crossref/DBLP/pages éditeur.

Requêtes minimales :

```text
DevSecOps CI/CD empirical evaluation Policy-as-Code OPA Rego
software supply chain security CI/CD NIST SP 800-204D
SAST CI/CD false positives developer fatigue empirical study
secret scanning benchmark Gitleaks TruffleHog GitHub secret scanning
container vulnerability scanning Trivy Grype empirical comparison
automated vulnerability repair CI/CD agents Pull Request remediation
LLM vulnerability repair PatchAgent OSS-Fuzz automated patching
Policy-as-Code agentic RAG ARPaCCino Rego compliance
Dependabot alert fatigue dependency update bots empirical study
OpenSSF Scorecard software supply chain security empirical
```

Chaque référence critique doit être vérifiée : titre, auteurs, venue, année, DOI, statut, rôle exact dans l’article.

## 12. Nouvel article — structure recommandée

Titre possible :

> SecFlowOps: Artifact-Backed Evaluation of Policy-as-Code, Multi-Layer Scanning, and Semi-Autonomous Remediation in Real CI/CD Pipelines

Plan recommandé :

1. Introduction
2. Background and Motivation
3. Related Work
4. SecFlowOps Architecture
5. Experimental Protocol
6. Real CI/CD Deployment
7. Results
8. Ablation and Sensitivity Analysis
9. Discussion
10. Threats to Validity
11. Artifact Availability
12. Conclusion

### Claims autorisés si les résultats les soutiennent

- “We implemented SecFlowOps in GitHub Actions with OPA/Rego and open-source scanners.”
- “We report an artifact-backed evaluation across X repositories, Y vulnerability scenarios and Z workflow runs.”
- “The ablation indicates that remediation automation primarily affects MTTR, while policy gating primarily affects deployment success and governance.”

### Claims à éviter sans preuve terrain

- “production-ready” ;
- “industrial validation” ;
- “reduces developer cognitive load” sans étude humaine ;
- “first” sans revue systématique complète ;
- “autonomous remediation is safe” sans modèle de menace et validation de patch.

## 13. Critères d’arrêt

Le projet peut être considéré prêt pour rédaction lorsque les éléments suivants existent :

- dépôt SecFlowOps complet ;
- workflows CI exécutés ;
- au moins 300 runs exploitables ou justification si moins ;
- ground truth documenté ;
- logs bruts conservés ;
- résultats normalisés ;
- scripts statistiques reproductibles ;
- figures générées par script ;
- bibliographie vérifiée ;
- article `.tex` compilable ;
- README de reproduction ;
- limites clairement formulées.

## 14. Risques principaux et parades

| Risque | Impact | Parade |
|---|---|---|
| Trop peu de vrais dépôts | Généralisation faible | Assumer “controlled real-CI study”, pas étude industrielle |
| Agents peu efficaces | Résultat moins spectaculaire | Résultat scientifique valable : mesurer les limites réelles |
| Outils difficiles à normaliser | Perte de comparabilité | Schéma JSON commun + traces brutes conservées |
| Coût CI élevé | Expérience interrompue | Self-hosted runner + plan minimal 432 runs |
| Secrets accidentels | Risque sécurité | Secrets factices uniquement + scan avant publication |
| Claims trop forts | Rejet reviewer | Alignement strict promesses-preuves |

## 15. Livrables finaux

1. `PROTOCOL.md`
2. `THREAT_MODEL.md`
3. `ETHICS_AND_SAFETY.md`
4. workflows GitHub Actions
5. policies OPA/Rego + tests
6. normalizer JSON/SARIF
7. RemediatorAgent contrôlé
8. data brutes + data normalisées
9. scripts de statistiques et figures
10. `references.bib` vérifié
11. article LaTeX complet
12. archive reproductible
