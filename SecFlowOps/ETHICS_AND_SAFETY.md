# Ethics and Safety

This artifact is defensive and controlled.

Rules:

- do not scan systems that are not owned or explicitly authorized;
- do not include real credentials;
- use only fake test secrets such as documented AWS example keys;
- do not run DAST against public third-party targets;
- preserve raw logs but inspect them before publication;
- do not auto-merge patches;
- label any human-review-required remediation explicitly.

The local sample application contains intentionally vulnerable code for scanner
evaluation. It must not be deployed to the public internet.

No human-subject study is included. Therefore the artifact must not claim direct
developer cognitive-load reduction.
