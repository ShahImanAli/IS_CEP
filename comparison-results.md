# Pod Priority Preemption DoS — Before/After Mitigation Comparison

**Project:** Detecting and Mitigating Pod Priority Preemption DoS Attacks in Multi-Tenant Kubernetes Clusters
**Cluster:** Minikube `cep`, 3 nodes (`cep`, `cep-m02`, `cep-m03`), Kubernetes v1.37.0, 8 CPU/node
**Attacker namespace:** `bad-tenant`  •  **Victim workload:** `ds-no-priority` DaemonSet (1 pod/node, no PriorityClass)
**Attack command (identical in both runs):** `py evict.py -n bad-tenant -r 20 --cpu 1 -p high-priority -t 7`
**Generated:** 2026-10-25

---

## 1. Headline comparison table

| Metric | BEFORE (no mitigation) | AFTER (hardened) |
|---|---|---|
| **Attack outcome** | ✅ Succeeded — tenant DoS achieved | ❌ Blocked |
| **Where the attack was stopped** | Not stopped at all | **Admission** (Kyverno webhook), *before scheduling* |
| **Evictions (`Preempted` events)** | **3** | **0** |
| **Victim pods affected** | 3 of 3 (100% of victim tenant) | 0 of 3 |
| **Time to first eviction** | **≈ 6 s** after launch | N/A (never occurred) |
| **Attacker pods scheduled** | 21 (20 `deployment-stuffer` + 1 `evictor`) | 0 (Deployment *and* Pod rejected) |
| **Victim replacements left Pending** | 3 (indefinitely, until attacker removed) | 0 |
| **Pending duration of evicted workload** | Unbounded — replacements never scheduled while attack ran (≥ 30 s observed, DoS persistent) | 0 s (victims never disturbed) |
| **`FailedScheduling` events logged** | 11 | 0 |
| **Peak CPU *requests* (allocated)** | cep **99%**, m02 **88%**, m03 **90%** | cep 24%, m02 17%, m03 16% |
| **Peak CPU *usage* (`kubectl top`)** | cep 6%, m02 1%, m03 1% | cep 6%, m02 1%, m03 1% |
| **Peak memory requests (allocated)** | 12–15% per node | 12–15% per node |
| **Detector log** | `preemption_log_BEFORE.csv` — 3 Preempted + 11 FailedScheduling | `preemption_log_AFTER.csv` — empty (header only) |

---

## 2. What happened BEFORE mitigation (attack succeeds)

`evict.py` created a 20-replica `deployment-stuffer` of high-priority pods
(`priorityClassName: high-priority`, value **9999**, `PreemptLowerPriority`) plus a
high-priority `evictor` pod. Because each requests 1 CPU and the cluster's free CPU was
already consumed by the stuffer, the scheduler **preempted the no-priority victim pods**
to make room.

Observed from `detector.py` (`preemption_log_BEFORE.csv`):

| Evicted victim | Node | Preempting pod (attributed) |
|---|---|---|
| `ds-no-priority-hdsng` | cep | `bad-tenant/deployment-stuffer-…-plc5c` |
| `ds-no-priority-2ftkw` | cep-m03 | `bad-tenant/deployment-stuffer-…-ndtgx` |
| `ds-no-priority-mr6np` | cep-m02 | `bad-tenant/evictor` |

- **All 3 victim pods** (the entire victim tenant workload) were evicted, one per node.
- The DaemonSet controller recreated the victims, but they were stuck **`Pending`** with
  *"No preemption victims found … Preemption is not helpful for scheduling"* — i.e. the
  cluster was now full of equal/higher-priority pods and nothing lower remained to evict.
  **The victim tenant was denied service for the entire duration of the attack.**
- CPU **requests** were driven to **88–99%** across all nodes (scheduling saturation),
  even though live CPU **usage** stayed at ~1–6%. This confirms the attack is a
  **resource-reservation / scheduling DoS**, not a compute-exhaustion attack — the damage
  comes from *reserved* CPU and preemption rights, not actual load.

---

## 3. What happened AFTER mitigation (attack blocked)

The identical command failed immediately. `evict.py` crashed on its **first** API call
(`create_namespaced_deployment`) with HTTP 400:

```
admission webhook "validate.kyverno.svc-fail" denied the request:
resource Deployment/bad-tenant/deployment-stuffer was blocked due to policy
restrict-priority-class-bad-tenant →
  Pods in the 'bad-tenant' namespace are not allowed to use a preempting high-priority
  PriorityClass ('high-priority' or 'attacker-high-priority').
  Use 'high-priority-nonpreempting' instead.
```

A direct pod-level attempt (`kubectl run evictor-test … priorityClassName: high-priority`)
was rejected the same way (rule `block-high-priority-in-bad-tenant`).

- **0 pods** were created in `bad-tenant`; **0 evictions**; `preemption_log_AFTER.csv` is empty.
- All **3 victim pods stayed `Running`** throughout — zero disruption.
- The attack was stopped at **admission time, before the scheduler was ever involved**.

---

## 4. The three mitigation layers (defense in depth)

| Layer | File | Role | Verified |
|---|---|---|---|
| **1. ResourceQuota** | `resourcequota.yml` | Caps `bad-tenant` at 2 CPU / 2Gi requests, 4 CPU / 4Gi limits, **10 pods** — bounds the blast radius even if priority abuse were possible (20-replica stuff impossible: max 2 CPU / 10 pods). | `pods 0/10, requests.cpu 0/2` |
| **2. Non-preempting PriorityClass** | `nonpreempting-priorityclass.yml` | Provides `high-priority-nonpreempting` (value 1000000, `preemptionPolicy: Never`) — tenants can still get high scheduling priority but **cannot evict** other tenants' pods. | `PREEMPTIONPOLICY: Never` |
| **3. Kyverno admission policy** | `restrict-priority-class.yml` | `ClusterPolicy` (Enforce) denies any Pod in `bad-tenant` that uses the preempting `high-priority` / `attacker-high-priority` class — blocks the attack **at creation**, before scheduling. Kyverno autogen extends the rule to Deployments/ReplicaSets. | `ADMISSION true … READY True` |

**Primary blocker:** Layer 3 (Kyverno) stops the attack at admission.
**Backstop:** Layer 1 (ResourceQuota) would still cap stuffing to 2 CPU / 10 pods.
**Safe alternative:** Layer 2 gives tenants a legitimate high-priority option with no eviction rights.

---

## 5. Blocked at admission vs scheduling vs not at all

| Run | Classification |
|---|---|
| BEFORE | **Not blocked** — pods admitted, scheduled, and preempted victims. |
| AFTER | **Blocked at admission** — the Kyverno `validate.kyverno.svc-fail` webhook rejected the Deployment and Pod at creation; the scheduler/preemption path was never reached. |

Blocking at admission is strictly stronger than blocking at scheduling: the malicious
high-priority pods never exist, so no preemption, no `Pending` victims, and no scheduler
churn ever occur.

---

## 6. Evidence files

| File | Contents |
|---|---|
| `01-baseline-before.txt` | Healthy baseline — all pods Running |
| `02-attack-running.txt` | Attack launch output + timestamped victim-Pending watch |
| `03-pods-after-attack.txt` | 21 attacker pods Running, 3 victims Pending (DoS) |
| `04-node-usage-during-attack.txt` | Node CPU/mem — 88–99% requests, ~1–6% usage |
| `05-attack-blocked.txt` | Kyverno admission denial (Deployment + direct Pod) |
| `06-pods-after-mitigation.txt` | No attacker pods, victims all Running, quota 0 used |
| `preemption_log_BEFORE.csv` | 3 Preempted + 11 FailedScheduling, preemptors attributed |
| `preemption_log_AFTER.csv` | Empty — zero preemption activity |
| `detector.py` | Real-time Events-API detector (writes `preemption_log.csv`) |
