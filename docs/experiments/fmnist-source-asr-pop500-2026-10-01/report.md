# Source-ASR: population 500, participation 100

## Scope

The author's `roles/attack3_fmnist.py` specifies population 500, sample size
100, adversaries 20 and 60 retraining rounds. This run uses that population
and participation scale, but **four rounds**, attacks in rounds 1 and 4,
four committee members, and isolated seeded individual participation. It is
not the author's complete 60-round/randomness transcript or classifier-MGF
experiment. The actual filter is the source ASR MMF (30–80% inclusive).

Original saved HPRF parameters/matrix, scalar keys, one-time author VSS,
client masking and normal-path BFT are retained. Masks are not rescaled to
the small-mask E2 MGF regime. The source scalar keyspace is research-only;
the [public key-search finding](../../reproduction/source-keyspace-privacy-2026-10-01.md)
still applies. No production privacy or full HotStuff liveness claim is made.

## Flower transport

100 masked 61,706-coordinate vectors exceed the existing 16 MiB payload
limit. ServerApp therefore forwards them through roughly 8 MiB Flower
`stage-vectors` batches. Aggregator ClientApp writes only received masked
envelopes to its inbox, records sender/digest references, and verifies those
references before source MMF selection. Neither plaintext training deltas
nor additional mask shares are sent. Ciphertext files are retained for
audit, roughly 120 MiB/round in this run. Shared local Ray storage is not a
measurement of independent remote-machine networking.

## Completed local execution

Fresh task `.cache/source-asr-pop500-q100-batched-local-20261001` used four
bounded process workers, author-loader training, two local epochs, learning
rate 0.001, the author round-300 checkpoint and attack boost 20/120 steps.
Partition staging is `.cache/source-pop500-inputs-20261001`; its `avg` mode
was **staged only**, not run or substituted for source-ASR results.

| Round | Selected | Selected attackers | Clean accuracy | Backdoor ASR |
| --- | ---: | ---: | ---: | ---: |
| 1 | 31 | 3 | 69.83% | 100.00% |
| 2 | 31 | 0 | 77.54% | 99.4140625% |
| 3 | 31 | 0 | 81.31% | 98.828125% |
| 4 | 34 | 7 | 77.76% | 24.0234375% |

Workflow time: 168.1151 s. One-time key-share deliveries: **2,000**;
additional mask-share deliveries: **0**. All four final model events were
committed through the source normal-path BFT adapter.

Independent offline verification retrained all **127 selected updates**,
validated input hashes and commit certificates, and obtained maximum model
error **0**, with tolerance 1e-12. This establishes the selected quantized
mean/model computation, not filter soundness or input privacy. High attack
success is a reproduced limitation, not a successful paper defense result.

## Official runtime

The separate fresh task
`.cache/source-asr-pop500-q100-batched-official-20261001` was staged with two
Ray workers and launched through official Flower SuperLink. It imports
public workload settings only, not old keys, contexts or shares.
All four rounds completed. Flower run ID: `15857092117809981885`.
Workflow time: **575.9410 s**; 2,000 one-time key-share deliveries and
0 additional mask shares. There were **68 masked batch deliveries**;
the largest canonical vector-batch body was **7,498,453 bytes**, below the
16 MiB payload cap (not a measurement of complete transport/network bytes).

| Round | Selected | Selected attackers | Clean accuracy | Backdoor ASR |
| --- | ---: | ---: | ---: | ---: |
| 1 | 31 | 5 | 14.81% | 100.00% |
| 2 | 31 | 0 | 42.56% | 100.00% |
| 3 | 31 | 0 | 55.11% | 100.00% |
| 4 | 30 | 7 | 47.41% | 0.00% |

Fresh random author scalar keys differ between the local and official
tasks. Source MMF measures mask-dominated norms, so different keys change
selection and the subsequent model trajectory. These runs are not an
equal-key transport comparison. In particular, the final 0% backdoor ASR
does not establish useful defense: clean accuracy is only 47.41%, and
previous rounds have 100% ASR. Offline verification retrained all **123
selected updates**, checked staged input hashes and normal-path BFT
certificates, and obtained maximum model error **0** (tolerance 1e-12).
The result and `verification.json` are both present in the official task.

## Regression checks

Existing source/official/dynamic/numeric/inbox suites: 51 passed before the
subsequent transport scheduling improvement. After adding the forced-batch
paper-adapter test and batch-delivery counters, inbox/numeric suites:
25 passed. After grouping discovery requests and concurrently delivering
each client's original shares to distinct committee nodes, the updated
full regression passed **52 tests** (70.37 s). This changes message
scheduling only: no concurrent mutation of the same node, no fresh shares,
and unchanged source share-recipient checks. Counts overlap and must not be
added together. The large runs above started before that scheduling change;
their staged source snapshots and measured runtimes remain unchanged.

The updated scheduling was additionally executed through official Flower
in a fresh synthetic population-10/participation-7 four-round smoke task:
`.cache/source-asr-control-batch-smoke-official-20261001`. Workflow time
22.2675 s; 40 original key-share deliveries, 0 additional mask shares;
11 selected training calls replayed with model error 0. Run ID
`5354745524054513389`. This is not a population-500 performance benchmark.
