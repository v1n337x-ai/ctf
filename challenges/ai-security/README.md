# AI security

3 challenges in this category.

LLM application security: tool scoping, classifier boundaries and membership inference.

## Before you start

None of these need a GPU. They are about what an LLM application trusts, and each one is a real class of bug that ships in production systems.

## Challenges

| ID | Name | Flaw | Status |
|---|---|---|---|
| `SIM-32` | BHASKARA | Unscoped agent tool call | approach below |
| `SIM-33` | Core Zone | Classifier boundary | approach below |
| `SIM-34` | MMCFS | Membership inference | approach below |

---

## Approaches

### SIM-32 - BHASKARA

**Flaw.** Unscoped agent tool call

The tool call is scoped in the documentation to what operators can see, and the scope is not enforced in the code. OWASP's LLM Top 10 does not treat RAG or fine-tuning as a mitigation for prompt injection, and it lists excessive agency as a scoping failure between granted permission and enforced check. Ask what the tool is permitted to reach once the prompt is under your control.

**No published write-up for this one.** The solve was not verified before publication and a wrong offset in a memory corruption exploit is worse than no write-up at all - it fails and convinces you the challenge is broken.

### SIM-33 - Core Zone

**Flaw.** Classifier boundary

The classifier was trained only on examples of what to block, so it has never seen the boundary it is defending. The query budget is the constraint, not the obstacle. Probe the boundary rather than the label -- the interesting cases are the ones nearest it, and they are slower to answer.

**No published write-up for this one.** The solve was not verified before publication and a wrong offset in a memory corruption exploit is worse than no write-up at all - it fails and convinces you the challenge is broken.

### SIM-34 - MMCFS

**Flaw.** Membership inference

Two named results are relevant. Membership inference (Shokri et al., 2017) determines whether a specific record was in the training set from a model's outputs alone, and model extraction from a public prediction API is practical at roughly 1000 queries (Tramer et al.). Either reaches the objective; one is cheaper.

**No published write-up for this one.** The solve was not verified before publication and a wrong offset in a memory corruption exploit is worse than no write-up at all - it fails and convinces you the challenge is broken.

