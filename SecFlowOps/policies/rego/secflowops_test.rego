package secflowops

import rego.v1

test_denies_residual_critical if {
  result := decision with input as {
    "findings": [{"severity": "critical", "category": "sca", "cvss": 9.8, "remediated": false}],
    "coverage": 1.0,
    "tool_failures": [],
    "policy": {"critical_tolerance": 0, "high_threshold": 3, "cvss_ceiling": 9.0, "block_on_secret": true, "min_coverage": 0.8},
  }
  not result.allow
}

test_allows_clean_residual_set if {
  result := decision with input as {
    "findings": [{"severity": "critical", "category": "sca", "cvss": 9.8, "remediated": true}],
    "coverage": 1.0,
    "tool_failures": [],
    "policy": {"critical_tolerance": 0, "high_threshold": 3, "cvss_ceiling": 9.0, "block_on_secret": true, "min_coverage": 0.8},
  }
  result.allow
}
