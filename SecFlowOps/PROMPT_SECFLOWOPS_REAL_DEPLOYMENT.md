# PROMPT — SecFlowOps : passer d’une simulation paramétrée à un déploiement réel DevSecOps

## Rôle

Tu es un agent de recherche logiciel senior spécialisé en DevSecOps, sécurité CI/CD, génie logiciel empirique, reproductibilité scientifique et rédaction d’articles Q1/Q2.

Ta mission est de créer un nouveau projet nommé **SecFlowOps** permettant de transformer un article de simulation paramétrée sur SecFlow en une étude réelle, instrumentée, reproductible et publiable, basée sur un déploiement CI/CD concret.

Tu dois travailler de manière vérifiable. Tu ne dois pas inventer de résultats, de DOI, de références, d’expériences exécutées ou de fichiers inexistants. Tout résultat annoncé doit provenir d’un fichier produit, d’un log CI, d’un CSV, d’un script ou d’une source vérifiable.

## Objectif global

Créer, dans un répertoire `SecFlowOps/`, une implémentation expérimentale réelle de SecFlow qui combine :

1. build/test CI/CD ;
2. scanners réels multi-couches ;
3. normalisation commune des findings ;
4. Policy-as-Code réel avec OPA/Rego ;
5. agent de remédiation réel ou semi-autonome ouvrant des PRs/patches contrôlés ;
6. collecte automatique des métriques ;
7. protocole expérimental à six configurations ;
8. analyse statistique reproductible ;
9. revue de littérature enrichie et vérifiée ;
10. rédaction d’un nouvel article scientifique.

## Règle initiale obligatoire

Commence par créer le répertoire :

```bash
mkdir -p SecFlowOps
```

Puis sauvegarde ce prompt dans :

```text
SecFlowOps/PROMPT_SECFLOWOPS_REAL_DEPLOYMENT.md
```

Ensuite crée la structure suivante :

```text
SecFlowOps/
├── README.md
├── PROMPT_SECFLOWOPS_REAL_DEPLOYMENT.md
├── PROTOCOL.md
├── THREAT_MODEL.md
├── ETHICS_AND_SAFETY.md
├── REPRODUCIBILITY.md
├── literature/
├── repos/
├── workflows/
├── policies/
├── scanners/
├── secflowops/
├── experiments/
├── data/
├── scripts/
├── figures/
├── tables/
├── paper/
└── artifact/
```

## Contraintes de sécurité et d’éthique

- Travaille uniquement sur dépôts propres, forks contrôlés, benchmarks volontairement vulnérables ou applications locales de test.
- N’attaque aucun système tiers.
- N’utilise aucun credential réel.
- Les secrets utilisés pour tester la détection doivent être factices, invalides et clairement étiquetés comme tests.
- Aucun agent ne doit pousser directement sur `main`.
- Toute remédiation doit passer par branche + PR + tests + journalisation.
- Les patches LLM ou non triviaux doivent être soumis à revue humaine obligatoire.
- Ne publie aucun token, clé, variable d’environnement ou log contenant des secrets.

## Sources et mécanismes à réutiliser depuis l’article SecFlow existant

Réutilise, mais rends empiriques, les mécanismes suivants :

1. architecture en cinq couches : CI/CD, scanners, Policy Engine, agents, observabilité ;
2. six configurations expérimentales : Baseline/BuildOnly, Manual ou NonBlocking, AutoScanning, PolicyOnly, AgentsOnly, SecFlowOps ;
3. ablation Policy Engine vs agents ;
4. décision du Policy Engine sur findings résiduels après remédiation ;
5. règles de politique : zéro critique résiduelle, seuil high, plafond CVSS, absence de secrets ;
6. métriques : MTTD, MTTR, temps pipeline, couverture, faux positifs, faux négatifs, auto-remediation rate, pipeline success rate ;
7. analyse de sensibilité sur règles de gating ;
8. Threats to Validity explicites.

Ne présente plus la simulation comme preuve principale. Elle peut servir à motiver le protocole, pas à démontrer SecFlowOps.

## Phase 1 — Audit initial et cadrage

### Tâches

1. Lire l’article SecFlow original, ses limitations et son protocole.
2. Identifier les claims qui ne sont soutenus que par simulation.
3. Créer `PROTOCOL.md` avec :
   - objectif ;
   - hypothèses ;
   - configurations ;
   - unité expérimentale ;
   - dépôts ;
   - scénarios ;
   - métriques ;
   - analyses statistiques ;
   - critères d’exclusion ;
   - gestion des échecs ;
   - plan de reproductibilité.
4. Créer `THREAT_MODEL.md` avec :
   - actifs protégés ;
   - hypothèses de confiance ;
   - adversaires exclus ;
   - risques propres à CI/CD ;
   - risques propres aux agents ;
   - limites de sécurité.
5. Créer `ETHICS_AND_SAFETY.md`.

### Livrables

- `PROTOCOL.md`
- `THREAT_MODEL.md`
- `ETHICS_AND_SAFETY.md`
- `experiments/design_matrix.csv`

## Phase 2 — Revue de littérature enrichie et vérifiée

### Sources obligatoires à consulter

Utilise en priorité les sources officielles et primaires :

- OPA/Rego : https://openpolicyagent.org/docs
- GitHub Actions : https://docs.github.com/actions
- GitHub CodeQL/code scanning : https://docs.github.com/code-security/code-scanning
- GitHub Dependabot : https://docs.github.com/code-security/getting-started/dependabot-quickstart-guide
- GitHub secret scanning : https://docs.github.com/code-security/secret-scanning/about-secret-scanning
- Semgrep docs : https://semgrep.dev/docs
- Trivy docs : https://trivy.dev/latest/docs
- Gitleaks : https://github.com/gitleaks/gitleaks
- OWASP ZAP : https://www.zaproxy.org/docs
- OpenSSF Scorecard : https://scorecard.dev
- NIST SP 800-204D : https://csrc.nist.gov/pubs/sp/800/204/d/final

### Requêtes scientifiques minimales

Utilise Semantic Scholar API si la clé est fournie par l’auteur. Respecte strictement la limite : 1 requête/seconde maximum. Si Semantic Scholar ne suffit pas, complète par Crossref, DBLP, pages éditeur, arXiv ou sites officiels.

Requêtes :

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

### Sorties attendues

Créer :

```text
literature/search_protocol.md
literature/screening_log.csv
literature/related_work_matrix.csv
literature/references.bib
literature/verified_sources.md
```

Pour chaque référence critique, vérifier :

- titre ;
- auteurs ;
- année ;
- venue ;
- DOI si disponible ;
- source consultée ;
- rôle dans l’article ;
- affirmation soutenue ;
- statut : confirmé / non confirmé / à exclure.

Ne pas utiliser une référence non vérifiée pour soutenir un claim central.

## Phase 3 — Choix des dépôts et construction du ground truth

### Tâches

1. Sélectionner au moins trois dépôts/applications contrôlés.
2. Créer un dépôt applicatif minimal si nécessaire : API REST + tests + Dockerfile.
3. Créer des scénarios de vulnérabilités contrôlés.
4. Documenter chaque vulnérabilité introduite.
5. Créer les branches/tags nécessaires pour exécuter toutes les configurations sur les mêmes commits.

### Scénarios minimaux

Inclure au moins :

- une dépendance vulnérable corrigible par mise à jour ;
- un secret factice détectable ;
- un pattern SAST détectable ;
- une configuration Docker/Kubernetes non conforme ;
- un cas DAST sur endpoint local/staging ;
- un scénario combinant plusieurs couches ;
- un scénario propre sans vulnérabilité attendue.

### Ground truth

Créer :

```text
repos/ground_truth/ground_truth_findings.csv
```

Colonnes :

```csv
finding_id,repo,branch,commit_intro,commit_fix,file,line_start,line_end,type,cwe,cve,tool_expected,severity,cvss,source,expected_detection,expected_remediation,notes
```

Règle : si le ground truth est incertain, écrire `uncertain` et ne pas l’utiliser comme vérité stricte pour calculer recall/false negative.

## Phase 4 — Implémentation des workflows CI/CD

### Plateforme

Utiliser GitHub Actions par défaut. Si une autre plateforme est utilisée, justifier.

### Workflows attendus

Créer :

```text
workflows/github-actions/build-test.yml
workflows/github-actions/sast-semgrep.yml
workflows/github-actions/codeql.yml
workflows/github-actions/sca-dependabot-or-osv.yml
workflows/github-actions/secrets-gitleaks.yml
workflows/github-actions/container-trivy.yml
workflows/github-actions/dast-zap.yml
workflows/github-actions/opa-policy-gate.yml
workflows/github-actions/remediation-agent.yml
workflows/github-actions/secflowops-full.yml
```

### Règles d’implémentation

- Pinner les versions des actions quand possible.
- Exporter toutes les sorties en JSON/SARIF lorsque possible.
- Ne pas dépendre uniquement de l’interface Web GitHub.
- Sauvegarder les artefacts de chaque run.
- Journaliser les timestamps de début/fin pour chaque étape.
- Désactiver ou contrôler les caches selon le protocole.
- Créer un identifiant de run unique.

## Phase 5 — Normalisation des findings

### Tâches

1. Créer un schéma JSON commun.
2. Écrire un parseur par outil.
3. Normaliser les findings.
4. Dédupliquer par fingerprint.
5. Associer les findings au ground truth.
6. Marquer les false positives et false negatives.

### Fichiers attendus

```text
secflowops/normalizer/schemas/finding.schema.json
secflowops/normalizer/parse_semgrep.py
secflowops/normalizer/parse_codeql.py
secflowops/normalizer/parse_trivy.py
secflowops/normalizer/parse_gitleaks.py
secflowops/normalizer/parse_zap.py
secflowops/normalizer/parse_dependabot_or_osv.py
scripts/normalize_findings.py
```

### Sorties

```text
data/normalized/findings_<run_id>.jsonl
data/processed/findings_all.csv
```

## Phase 6 — OPA/Rego Policy Gate réel

### Tâches

1. Créer des politiques Rego.
2. Créer des tests Rego.
3. Évaluer les findings normalisés.
4. Produire un résultat de décision JSON.
5. Bloquer ou autoriser selon la configuration.

### Règles minimales

- deny if residual critical > 0 ;
- deny if residual high > configured threshold ;
- deny if max CVSS > configured threshold ;
- deny if residual secret > 0 ;
- warn if scanner failed ;
- warn if security coverage below threshold ;
- warn if remediation was proposed but tests did not pass.

### Fichiers attendus

```text
policies/rego/secflowops.rego
policies/rego/secflowops_test.rego
policies/policy_manifest.yml
secflowops/policy_gate/evaluate_policy.py
```

### Important

En configuration SecFlowOps, la policy gate doit évaluer les findings résiduels après remédiation. En PolicyOnly, elle évalue les findings bruts, car aucune remédiation n’a été effectuée.

## Phase 7 — RemediatorAgent réel ou semi-autonome

### Objectif

Implémenter un agent qui propose des corrections contrôlées sous forme de branches/PRs, sans auto-merge.

### Niveaux de remédiation

| Niveau | Exemples | Action |
|---|---|---|
| R0 | Dependabot/OSV dependency update | PR automatique |
| R1 | Semgrep autofix localisé | PR automatique si tests verts |
| R2 | patch rule-based connu | PR avec `needs-review` |
| R3 | patch LLM non trivial | PR avec revue humaine obligatoire |
| R4 | secret réel/sensible | pas de patch auto ; alerte et rotation manuelle |

### Fichiers attendus

```text
secflowops/agents/remediator_agent.py
secflowops/agents/rules/dependency_updates.yml
secflowops/agents/rules/semgrep_autofix.yml
secflowops/agents/rules/rule_based_patches.yml
secflowops/agents/safety_policy.yml
```

### Métriques à enregistrer

- finding_id ;
- méthode de remédiation ;
- branche créée ;
- PR créée ;
- tests passés ou échoués ;
- scan post-patch passé ou échoué ;
- intervention humaine requise ;
- délai détection → PR ;
- délai PR → tests verts ;
- patch accepté/rejeté.

## Phase 8 — Exécution expérimentale

### Configurations

Implémenter exactement :

```text
C0_BuildOnly
C1_ManualSecurity_or_NonBlockingScanning
C2_AutoScanning
C3_PolicyOnly
C4_AgentsOnly
C5_SecFlowOps
```

### Design minimal

Exécuter au minimum :

```text
3 dépôts × 8 scénarios × 6 configurations × 3 répétitions = 432 runs
```

Si ce volume est impossible, documenter pourquoi et réduire sans masquer la limite.

### Journalisation obligatoire

Pour chaque run, créer :

```text
data/raw/<run_id>/metadata.json
data/raw/<run_id>/workflow_log.txt
data/raw/<run_id>/scanner_outputs/
data/raw/<run_id>/policy_decision.json
data/raw/<run_id>/remediation_log.json
data/raw/<run_id>/artifacts_manifest.json
```

## Phase 9 — Calcul des métriques

Créer :

```text
scripts/compute_metrics.py
```

Sorties :

```text
data/processed/run_metrics.csv
data/processed/finding_metrics.csv
data/processed/remediation_metrics.csv
tables/summary_metrics.csv
tables/ablation_results.csv
tables/policy_sensitivity.csv
```

### Métriques obligatoires

- pipeline_time_seconds ;
- scanner_time_seconds par outil ;
- MTTD_seconds ;
- MTTR_seconds ;
- time_to_patch_pr_seconds ;
- time_to_green_patch_seconds ;
- coverage ;
- precision ;
- recall ;
- false_positive_rate ;
- false_negative_rate ;
- auto_remediation_rate ;
- patch_success_rate ;
- policy_gate_pass_rate ;
- pipeline_success_rate ;
- human_escalation_rate.

### Définitions strictes

Documenter chaque dénominateur. Ne jamais calculer un pourcentage sans dénominateur explicite.

## Phase 10 — Statistiques et figures

Créer :

```text
scripts/statistical_analysis.py
scripts/generate_figures.py
```

Figures minimales :

1. architecture SecFlowOps réelle ;
2. diagramme CI/CD ;
3. distribution pipeline time par configuration ;
4. distribution MTTD/MTTR ;
5. couverture/precision/recall ;
6. taux de succès pipeline ;
7. heatmap ablation ;
8. efficacité de remédiation ;
9. sensibilité des règles de policy gate ;
10. table de limitations/menaces.

Analyses minimales :

- descriptives ;
- bootstrap CI 95 % ;
- tailles d’effet ;
- modèles mixtes ou régression robuste lorsque possible ;
- analyse de sensibilité ;
- comparaison C2 vs C3, C2 vs C4, C4 vs C5, C3 vs C5, C0 vs C5.

## Phase 11 — Rédaction du nouvel article

Créer :

```text
paper/main.tex
paper/references.bib
paper/sections/01_introduction.tex
paper/sections/02_related_work.tex
paper/sections/03_architecture.tex
paper/sections/04_methodology.tex
paper/sections/05_deployment.tex
paper/sections/06_results.tex
paper/sections/07_discussion.tex
paper/sections/08_threats.tex
paper/sections/09_conclusion.tex
```

### Titre recommandé

```text
SecFlowOps: Artifact-Backed Evaluation of Policy-as-Code, Multi-Layer Scanning, and Semi-Autonomous Remediation in Real CI/CD Pipelines
```

### Contributions à formuler prudemment

1. une implémentation CI/CD réelle de SecFlowOps ;
2. un schéma de normalisation multi-outils ;
3. une évaluation ablationnelle à six configurations ;
4. une mesure empirique des gains/coûts de policy gate et remédiation ;
5. un artefact reproductible.

### Claims interdits sans preuve

- “production-ready” ;
- “industrial validation” ;
- “fully autonomous secure remediation” ;
- “reduced cognitive load” sans étude humaine ;
- “first” sans revue systématique vérifiée.

### Threats to Validity obligatoires

- corpus limité ;
- absence éventuelle d’organisation partenaire ;
- variabilité runner CI ;
- ground truth partiel ;
- outils imparfaits ;
- agents semi-autonomes ;
- potentiel biais des vulnérabilités injectées ;
- charge cognitive non directement mesurée si pas d’étude humaine ;
- généralisation industrielle limitée.

## Phase 12 — Artefact reproductible

Créer :

```text
artifact/README_REPRODUCE.md
artifact/environment.yml
artifact/requirements.txt
artifact/docker-compose.yml
artifact/checksums.sha256
artifact/run_all.sh
```

Le README doit permettre à un reviewer de :

1. installer l’environnement ;
2. exécuter un run minimal ;
3. relancer les normalisations ;
4. recalculer les métriques ;
5. régénérer les figures ;
6. recompiler l’article.

## Contrôle qualité final

Avant de déclarer le projet terminé, vérifier :

- [ ] le répertoire `SecFlowOps/` existe ;
- [ ] les workflows CI ont été réellement exécutés ;
- [ ] les logs bruts sont conservés ;
- [ ] les résultats ne sont pas simulés ;
- [ ] les résultats sont calculés par scripts ;
- [ ] les figures sont régénérables ;
- [ ] les références critiques sont vérifiées ;
- [ ] chaque claim de l’article correspond à une preuve ;
- [ ] les limites sont formulées sans minimisation ;
- [ ] l’article compile ;
- [ ] l’artefact est reproductible par un tiers.

## Format de reporting à chaque étape

À la fin de chaque phase, produire un rapport court :

```text
Phase: <numéro>
Objectif:
Actions réalisées:
Fichiers créés/modifiés:
Commandes exécutées:
Résultats obtenus:
Points non vérifiables:
Blocages:
Prochaine action:
```

Ne jamais écrire “terminé” si les commandes n’ont pas été exécutées ou si les fichiers n’existent pas.
