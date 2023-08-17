Use kdrfc to make the woking group draft.

rename files, replace author name with ietf, add working group prefix if necessary.

update name inside draft to match new document name.

```
kdrfc -3c draft-ietf-cose-merkle-tree-proofs-00.md
```

Google data tracker upload... go to https://datatracker.ietf.org/submit/

be logged in

upload the xml document

choose yourself as submitter

set the replaces to the original I-D.

ask the working group for a new work item repo in the wg github org:

Must be on branch main.

Then follow the setup https://github.com/martinthomson/i-d-template/blob/main/doc/REPO.md

