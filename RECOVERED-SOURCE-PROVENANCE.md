# Recovered source provenance

This repository begins with a clean recovery of the executable source found in
the immutable image
`sha256:db7dfcf1d8547d9daa9f1e1b7f7f834b0138b95e15fce95345e4e2e1211ed578`
on Server A on 2026-08-19.

The image carried no OCI source or revision labels. Its application and script
files were recovered from `/app/app` and `/app/scripts`; `requirements.txt` was
recovered from `/app/requirements.txt`. Build files, tests, and documentation
were reconstructed from local commit
`7504e9ffe40b880e1cbdbe61a5e0adfeaebee1a3` after a secret audit.

The running image differs from both that Git commit and its dirty worktree, so
this import is classified `RECOVERED_BASELINE`. It is not represented as the
original protected source and full running-image equivalence is not proven.

The original checkout remains untouched at `/root/codestra-provisioning-service`.
Its five tracked modifications and one untracked test are preserved separately
in root-only evidence at
`/root/codestra-provisioning-source-recovery-20260819` and are not included in
the baseline automatically.
