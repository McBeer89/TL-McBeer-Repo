# LM Studio Settings — Qwen3 30B A3B 2507

## Hardware Reference

| Component | Spec |
|-----------|------|
| CPU | Intel Core i9-14900 (8 P-cores / 16 E-cores, 32 threads) |
| GPU | NVIDIA RTX A2000 12GB GDDR6 (Ampere) |
| RAM | 64 GB DDR |
| OS | Windows 11 Pro |
| System | Lenovo ThinkStation P3 Tower |

**Key CPU note:** The i9-14900 has two core types. P-cores (Performance) are
fast and handle LLM inference well. E-cores (Efficiency) are slower and can
cause scheduling overhead when mixed with P-cores during inference. All thread
count settings below target P-core threads only (16 threads = 8 P-cores × 2
with hyperthreading).

**Key GPU note:** The A2000 12GB has 288 GB/s memory bandwidth — enough for
inference but not as fast as consumer RTX cards. With Qwen3-30B-A3B at Q4_K_M
(~17-18GB total model size), 44 GPU layers uses most of the 12GB VRAM. Run
`nvidia-smi` with the model loaded to check actual usage. If VRAM is under
11GB, try increasing to 46-48 layers for a speed boost. If above 11.5GB,
stay at 44.

## Model: Qwen3-30B-A3B-2507 (General / Research)

Use this profile for TRR research, detection strategy, analytical reasoning,
and technical writing.

### Load Settings

| Setting | Value | Notes |
|---------|-------|-------|
| Context Length | 32768 | Good balance of quality and memory. Don't go higher unless you test output quality — MoE models can degrade at extended contexts with quantization. |
| GPU Offload | 44 | Near maximum for A2000 12GB. Check with `nvidia-smi` — if VRAM usage is under 11GB, try 46-48. If above 11.5GB, stay at 44. |
| CPU Thread Pool Size | **16** | **Change from 12 to 16.** Your i9-14900 has 8 P-cores (16 threads) + 16 E-cores (16 threads). LLM inference runs best on P-cores only. 16 threads saturates all P-core threads without spilling onto the slower E-cores, which can cause scheduling overhead and reduce throughput. |
| Evaluation Batch Size | 512 | Good. 64GB RAM supports this easily. |
| Max Concurrency | 1 | **Change from 4 to 1.** You're running single conversations, not serving an API. Concurrency >1 splits resources and can degrade quality for long analytical responses. |
| Unified KV Cache | On | Keep. |
| RoPE Frequency Base | Auto | Keep. |
| RoPE Frequency Scale | Auto | Keep. |
| Offload KV Cache to GPU | On | Keep. |
| Keep Model in Memory | On | Keep. |
| Try mmap() | On | Keep. |
| Seed | Random | Keep. |
| Number of Experts | 8 | Keep. This is the model's designed active expert count. |
| Flash Attention | On | Keep. |
| K Cache Quantization | Off | Keep off for best quality. |
| V Cache Quantization | Off | Keep off for best quality. |

### Inference Settings

| Setting | Value | Notes |
|---------|-------|-------|
| Temperature | 0.4 | **Change from 0.3 to 0.4.** Research writing benefits from slightly more varied word choice than code generation. Still low enough for factual accuracy. |
| Context Overflow | Truncate Middle | Keep. Preserves the beginning (system prompt) and end (recent conversation). |
| CPU Threads | **16** | **Change from 12 to 16.** Same as Load settings — saturate P-cores, avoid E-cores. |
| Top K | 20 | Keep. Reasonable constraint. |
| Repeat Penalty | 1.1 | Keep. Prevents repetitive output in long responses. |
| Top P | 0.9 | Keep. |
| Min P | 0.05 | Keep. |

---

## Model: Qwen3-Coder-30B-A3B (Coding / Lab Work)

Use this profile for writing detection queries, Sysmon configs, PowerShell
scripts, lab setup automation, and code-heavy tasks.

### Load Settings

Same as above, except:

| Setting | Value | Notes |
|---------|-------|-------|
| Max Concurrency | 1 | Same change — set to 1 for single-user use. |

All other load settings remain identical.

### Inference Settings

| Setting | Value | Notes |
|---------|-------|-------|
| Temperature | 0.2 | **Lower than research.** Code needs precision and determinism. Less variation = fewer syntax errors. |
| Context Overflow | Truncate Middle | Keep. |
| CPU Threads | **16** | **Change from 12 to 16.** Same as Load settings — saturate P-cores, avoid E-cores. |
| Top K | 20 | Keep. |
| Repeat Penalty | 1.0 | **Change from 1.1 to 1.0.** Code legitimately repeats patterns (loops, similar function signatures). Penalizing repetition can break code structure. |
| Top P | 0.9 | Keep. |
| Min P | 0.05 | Keep. |

---

## Summary of Changes from Current Settings

| Setting | Current | Research Profile | Coding Profile | Why |
|---------|---------|-----------------|----------------|-----|
| CPU Thread Pool Size | 12 | **16** | **16** | i9-14900: 16 threads saturates P-cores without hitting slower E-cores |
| CPU Threads (Inference) | 12 | **16** | **16** | Same as above |
| Max Concurrency | 4 | **1** | **1** | Single user, no need to split resources |
| Temperature | 0.3 | **0.4** | **0.2** | Research needs slightly more nuance; code needs more precision |
| Repeat Penalty | 1.1 | 1.1 (keep) | **1.0** | Code has legitimate repetition patterns |

Everything else stays the same. Your hardware configuration and model loading
settings are solid — the main tuning is on the inference side to match the
task type.

---

## Tips for Getting the Best Results

**Front-load context.** Paste the local system prompt, then paste the relevant
documents (TRR, research notes, detection strategy) at the start of each
session. The model doesn't have memory between sessions.

**Keep conversations focused.** Don't try to do TRR research and lab scripting
in the same conversation. The model does better when the task is clear and
consistent throughout.

**Watch for hallucination on technical details.** A 3.3B active parameter
model will sometimes fabricate API names, registry paths, or event IDs with
confidence. Always verify technical claims against documentation. If it cites
a specific Sysmon event ID or Windows API, check it.

**Use shorter exchanges.** Rather than asking for a complete TRR section in one
shot, ask for one piece at a time and validate before continuing. This plays
to the model's strengths and catches errors early.
