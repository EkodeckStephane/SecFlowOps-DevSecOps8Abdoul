package secflowops

import rego.v1

default allow := false

residual_findings := [f | f := input.findings[_]; not f.remediated]

critical_count := count([f | f := residual_findings[_]; lower(f.severity) == "critical"])
high_count := count([f | f := residual_findings[_]; lower(f.severity) == "high"])
secret_count := count([f | f := residual_findings[_]; f.category == "secret"])

max_cvss := value if {
  values := [cvss | f := residual_findings[_]; cvss := f.cvss]
  count(values) > 0
  value := max(values)
} else := 0

deny contains msg if {
  critical_count > input.policy.critical_tolerance
  msg := sprintf("residual critical findings: %d > tolerance %d", [critical_count, input.policy.critical_tolerance])
}

deny contains msg if {
  high_count > input.policy.high_threshold
  msg := sprintf("residual high findings: %d > threshold %d", [high_count, input.policy.high_threshold])
}

deny contains msg if {
  max_cvss > input.policy.cvss_ceiling
  msg := sprintf("max residual CVSS %.1f > ceiling %.1f", [max_cvss, input.policy.cvss_ceiling])
}

deny contains msg if {
  input.policy.block_on_secret
  secret_count > 0
  msg := sprintf("residual secret findings: %d", [secret_count])
}

warn contains msg if {
  failure := input.tool_failures[_]
  msg := sprintf("tool failure: %s", [failure])
}

allow if {
  count(deny) == 0
}

decision := {
  "allow": allow,
  "deny": deny,
  "warn": warn,
  "summary": {
    "critical_count": critical_count,
    "high_count": high_count,
    "secret_count": secret_count,
    "max_cvss": max_cvss,
    "residual_count": count(residual_findings),
  },
} if {
  true
}
