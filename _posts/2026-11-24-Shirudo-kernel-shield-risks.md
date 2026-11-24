---
title: "Shirudo: When the Shield Lives in the Kernel"
date: 2026-11-24 12:00:00 +/-TTTT
tags: [ebpf, linux, security, ai]
author: stapat
---

# is the kernel safe
NO
# will shirudo make it safe
NO

## How it works

The operator (agent) generates a small program called “upatch.” This upatch can be either an eBPF program running inside a kernel hook or Java agent protecting the application code. The operator then signs it, pushes it to the OCI registry, and the target pulls using one-shot commands.

At boot time, on the target side, `bpf()` gets restricted such that only signed loaders are allowed to inject BPF programs into the kernel, including root. Loaded upatches are stored in the TPM; the operator can check the status of the target offline. Targets for production need a patched Linux kernel from Shirudo with TPM 2.0; upstream Linux does not have this ABI.

## 1. One kernel bug can take the shield with it

The enforcement of Shirudo happens through BPF LSM hooks in the kernel. The threat model relies on the correct behavior of the kernel — specifically, the BPF verifier and JIT, keyring and signature verification, dm-verity, and the TPM driver. This is not something that Shirudo checks for itself.

That means bugs in any one of those places could defeat the protection system. Bugs in the verifier or JIT could defeat the guarantee that makes the signed BPF code safe to execute. Bugs in the keyring or PKCS#7 implementation could defeat the gatekeeper that prevents unsigned BPF code from being loaded into the kernel. Kernel privilege escalation vulnerabilities could defeat the system by disabling the hooks, loading malicious code into the kernel, or shaping what is measured.

Shirudo does not need a bug in its implementation to defeat the system. A few bugs are all that is needed. This is true of any in-kernel security defense, but it becomes important with the "self-defending infrastructure" pitch line. Shirudo is not designed to protect itself against a kernel compromise, nor does it make the attack surface of the kernel smaller.


## 2. Signed does not mean safe

The signature attests to the source of the upatch and not to its behavior. The documentation asserts that the upatch "does what its author wrote, disabling enforcement included." The verifier looks only at memory safety and not at intent. Its maps cannot be written to by user space, but they can be accessed by BPF programs.

So the signing key becomes a code execution pathway into the kernel space. Any compromise of the key, the build machine, and the signing pipeline leads to an implant.

## 3. The agent is a new supply chain

Most interesting in Shirudo is that which is also least defined: agents craft the defenses. This loop parses vulnerabilities, constructs a reproducer, selects a mitigation point, tests the shield, and iterates until it works; then signs the shield and rolls it out, at machine speed.

This is highly effective, but also creates risks at the model level.

## 4. A shield can break what it defends

BPF Verifier is a safety checker, not a correctness oracle. Even if your valid, signed, memory safe program denies necessary system call, introduces a latency to a hot hook or blocks a single path but leaves a variant of the exploit open, you are still good. Upatches can be also neutralized with changes to their targets (binary replaced/unloaded module).

In most cases the problem is availability, not exploitation. Your failed shield crashes your service, and the no-restart speed which makes your deployment cost-effective also makes an all-at-once fleet crash cost-effective. This is why canary targets and rollbacks based on them are mandatory.

## 5. A central point of failure

Shirudo is packed with power: a single signing key, a single runtime, a single registry, a single TPM owner password per fleet. This is efficient, and this is precisely why it makes it such an attractive target. The very features that prevent the exploitation also prevent security tools from working, files from being hidden, and syscalls from being made. The signed uppatch is not a patch at all; it's a rootkit.



