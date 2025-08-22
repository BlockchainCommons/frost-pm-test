# Priority Task

## Question to Expert

```rust
    let (mark1, next_key1) = chain.append_mark_with_key(
        &["bob", "charlie"],
        Utc::now(),
        &obj_hash2,
        next_key0,
        1
    )?;
```

Creating a genesis mark of adding a mark returns the `nextKey` value. This is state required by the generation of the *next* mark. We would like to avoid storing state between generations, except for the FROST group shares held by the participants. We'd like to avoid storing `nextKey` in particular because anyone who holds it can generate a mark that appears to be a valid next mark. It's OK to have to do two signing ceremonies (if necessary) to generate marks 1 and beyond.

What approach would you recommend?

## Answer from Expert

Great question—and you’re right to treat `nextKey` as a high‑value capability you don’t want sitting anywhere at rest.

## Short answer

Stop returning or persisting `nextKey`. Instead, **derive `nextKey_j` from the Round‑1 commitment set for the *next* mark (`j+1`)**, and derive **`key_{j+1}` from that same commitment set** when you actually mint mark `j+1`. That way:

* No one needs to store `nextKey` between generations.
* The only cross‑mark state is the **Round‑1 nonces/commitments** (kept locally by each participant until Round‑2 completes). The coordinator/chain code can be completely stateless.
* You still force a quorum to collaborate before a valid next mark can be minted.

Concretely:

* Let `Root_{j+1} = H(commitments_map_{j+1})`, a hash of the BTreeMap\<Identifier, SigningCommitments> gathered in **Round‑1** for mark `j+1`.
* Define
  `nextKey_j = KDF("PM:v1/next", chain_id, seq=j+1, Root_{j+1})`
  `key_{j+1} = nextKey_j` (recomputed from the same `Root_{j+1}` when you’re ready to mint mark `j+1`).
* You finalize **mark j** only after you’ve run **Round‑1 for mark j+1** (so you can compute `nextKey_j`), and you mint **mark j+1** after the signers re‑send the *same* commitments and perform **Round‑2**. The coordinator never stores `nextKey`.

This fits cleanly with the FROST API you’re already using (Round‑1 `commit`, Round‑2 `sign`) and requires **no changes** to frost‑ed25519. It also stays within the Provenance Mark invariants and continues to hide that a threshold group was involved (no extra PM fields).

---

## Ceremony timeline (stateless coordinator)

I’ll name the mark being created **M<j>** and the next **M\<j+1>**.

1. **Precommit (for M\<j+1>, Round‑1 only)**

   * Selected signers run `frost_ed25519::round1::commit` and send their `SigningCommitments` for **seq = j+1**.
   * Coordinator computes `Root_{j+1}` over the *map* of commitments (see “Root computation” below).
   * Coordinator computes `nextKey_j = KDF("PM:v1/next", id, seq=j+1, Root_{j+1})`.
   * Coordinator **finalizes M<j>** right now using `nextKey_j` inside its `hash` preimage. `nextKey_j` is not returned to the caller and not persisted. It only exists transiently while computing the hash.

2. **Mint M\<j+1> (Round‑2 for seq=j+1)**

   * Signers **replay** the *same* `SigningCommitments` for **seq = j+1** (they kept their `SigningNonces` locally as required by FROST; nonces are one‑use, not to be regenerated).
   * Coordinator recomputes `Root_{j+1}` and then recomputes
     `key_{j+1} = KDF("PM:v1/next", id, seq=j+1, Root_{j+1})`.
   * Coordinator **verifies** that `key_{j+1}` matches what M<j> committed to by recomputing M<j>.hash with this candidate `nextKey_j` (a pure local check).
   * Coordinator constructs a `SigningPackage` with the replayed commitments and message `M_msg(j+1)` (e.g., date, seq, object hash; you can also include `Root_{j+1}` in the message to bind Round‑2 tightly to the same commitment set).
   * Signers run `frost_ed25519::round2::sign` to produce signature shares; coordinator aggregates.
   * **Optional:** you may derive anything you need internally from the final signature (e.g., an internal audit trail), but you do **not** expose or store it in the mark.
   * **Before** publishing M\<j+1>, kick off **Precommit for M\<j+2>** (Step 1 again) so you can compute `nextKey_{j+1}` to finish M\<j+1>’s `hash`. That’s where the “two ceremonies per mark” comes from:

     * Ceremony A: Round‑1 for j+2 (lets you finish M\<j+1>).
     * Ceremony B: Round‑2 for j+1 (lets you prove the quorum actually signed the thing you’re marking).

> In short: every mark ≥ 1 is finished after two quorum interactions: Round‑2 for its own seq, and Round‑1 for the *next* seq. No `nextKey` is ever stored.

---

## What changes in `frost-pm-test`

You can keep your friendly‑name wrappers and your use of `provenance-mark`. Replace the “return `nextKey`” pattern with two **explicit API stages**:

### 1) Precommit for next mark (compute and *consume* `nextKey_j` immediately)

```rust
/// Round-1 only; derives `nextKey` for the *previous* mark j
/// and finalizes its hash. Stores nothing sensitive.
///
/// - participants: friendly names for the next mark's quorum (seq = j+1)
/// - seq_next:     j+1
pub fn precommit_next_mark(
    &mut self,
    participants: &[&str],
    seq_next: u32,
) -> anyhow::Result<()> {
    // 1. Collect commitments for seq_next
    //    Each participant runs round1::commit and retains SigningNonces locally.
    //    You only get their SigningCommitments in a BTreeMap<Identifier, SigningCommitments>.
    //
    // 2. Compute Root_{j+1} = commitments_root(&commitments_map)
    //
    // 3. Compute nextKey_j = kdf_next(chain_id, seq_next, Root_{j+1})
    //
    // 4. Finalize the *previous* mark (j) by recomputing its hash with this nextKey_j.
    //    Do not return or persist nextKey_j.
    //
    // 5. Discard commitments_map here. Signers keep their SigningNonces for seq_next.
    Ok(())
}
```

### 2) Append the next mark without any stored `nextKey`

```rust
/// Replays Round-1 for `seq` and runs Round-2 to produce M<seq>.
/// (Verifies the precommit matches the previous mark.)
pub fn append_mark_stateless(
    &mut self,
    participants: &[&str],
    date: chrono::DateTime<chrono::Utc>,
    obj_hash: &[u8],
    seq: u32,
) -> anyhow::Result<provenance_mark::ProvenanceMark> {
    // 1. Ask the same participants to resend their SigningCommitments for this `seq`
    //    (they must reuse the same SigningNonces they generated in precommit_next_mark).
    //
    // 2. Root_seq = commitments_root(&commitments_map)
    //    key_seq  = kdf_next(chain_id, seq, Root_seq)
    //
    // 3. Verify that recomputing the previous mark's hash with `nextKey_prev = key_seq`
    //    matches the published hash of M<seq-1>. If not, abort.
    //
    // 4. Build a SigningPackage with `commitments_map` and message M_msg(seq)
    //    (recommend including Root_seq inside M_msg(seq) to bind Round-2 to the same commitments).
    //
    // 5. Collect signature shares with round2::sign(...) and aggregate with frost::aggregate(...).
    //
    // 6. Immediately run `precommit_next_mark(participants_for_seq_plus_one, seq+1)` BEFORE
    //    finalizing this mark’s `hash`, so you get `nextKey_seq` without storing it.
    //
    // 7. Use:
    //       key   = key_seq
    //       hash  = H(key || id || seq || date || obj_hash || nextKey_seq)
    //    and publish the mark.
    //
    // 8. Zeroize/discard any buffers; participants MUST zeroize their SigningNonces after
    //    Round-2 completes for this seq.
}
```

> Keep your current `Identifier` ↔ name mapping intact; nothing above touches FROST’s types beyond what you already use. The two steps simply change **when** you ask for Round‑1 and how you **consume** the resulting `nextKey`.

---

## How to compute `Root` and the KDF

* Use a deterministic root over the Round‑1 commitment map (sorted by `Identifier` thanks to `BTreeMap`). With `frost-ed25519` 2.1.0, the Round‑1 and Round‑2 types and flows are exactly as in their docs/example (commit → build `SigningPackage` → sign → aggregate). The crate exposes `round1::commit`, `round2::sign`, `SigningPackage::new`, etc. with serde/serialization on by default. ([Docs.rs][1])

* **Root computation (stateless & portable in Rust):**

  ```rust
  use std::collections::BTreeMap;
  use frost_ed25519 as frost;
  use frost::round1::SigningCommitments;
  use frost::Identifier;

  // Deterministic, encoder-agnostic root:
  fn commitments_root(
      commitments: &BTreeMap<Identifier, SigningCommitments>
  ) -> [u8; 32] {
      // Serialize canonically: iterate BTreeMap order and extract each commitment’s
      // two group elements in canonical bytes. frost-core exposes canonical
      // serialization helpers behind its "serialization"/"serde" features, which
      // are enabled by default in frost-ed25519 2.1.0. Then SHA-256 the stream.
      //
      // In practice: concatenate
      //   - identifier bytes (short, canonical)
      //   - hiding_commitment bytes
      //   - binding_commitment bytes
      // for each participant, then hash once.
      //
      // (Implementation detail: the round1.rs and serialization.rs in frost-core
      // provide SerializableElement/Scalar and serde support; the public
      // example shows that SigningCommitments live in a BTreeMap used to build
      // SigningPackage. These can be (de)serialized deterministically.) :contentReference[oaicite:1]{index=1}

      use bc_crypto::hash::sha256;

      let mut buf = Vec::with_capacity(commitments.len() * (2*32 + 2));
      for (id, sc) in commitments {
          // Pseudocode: get canonical bytes
          // id_bytes        = frost_core::serialization for Identifier
          // hide_bytes      = sc.hiding().serialize()?  // canonical group bytes
          // bind_bytes      = sc.binding().serialize()? // canonical group bytes
          // buf.extend_from_slice(&id_bytes);
          // buf.extend_from_slice(&hide_bytes);
          // buf.extend_from_slice(&bind_bytes);
      }
      sha256(&buf) // [u8; 32]
  }
  ```

  The exact few lines that extract canonical bytes vary minimally with the frost‑core helpers you choose, but it’s all public API with the default `serialization`/`serde` features.

* **KDF for `nextKey` / `key`:**

  Keep it simple and deterministic:

  ```rust
  // domain separation and binding to chain + seq
  fn kdf_next(chain_id: &[u8], seq: u32, root: [u8; 32]) -> [u8; 32] {
      use bc_crypto::hash::sha256;
      let mut msg = b"PM:v1/next".to_vec();
      msg.extend_from_slice(chain_id);
      msg.extend_from_slice(&seq.to_be_bytes());
      msg.extend_from_slice(&root);
      sha256(msg) // 32-byte key (use or truncate to the PM key length)
  }
  ```

  Use `bc-crypto`’s `sha256()` so you don’t need to pull in another digest crate.

---

## Why this fixes your concern

* **No centralized sensitive state:** the coordinator never writes `nextKey` anywhere. It appears only transiently during hash computation, then is discarded.
* **Participants’ state is local and limited:** each signer keeps their **`SigningNonces` and their own `SigningCommitments`** for the in‑flight `seq` until Round‑2 is done, per FROST (nonces are one‑use). That’s acceptable and far safer than storing a global seed/PRNG state or `nextKey`. The exact Round‑1 → Round‑2 flow and data ownership is straight from the FROST API and example. ([Docs.rs][1])
* **Gating remains thresholded:** you cannot finalize M<j> absent a real Round‑1 for M\<j+1>, because you won’t have `Root_{j+1}` and thus can’t compute `nextKey_j`. You cannot mint M\<j+1> absent a real Round‑2 for M\<j+1>, because you need the signers’ shares to produce/verify a proper signing ceremony (even though the final signature isn’t embedded in the mark).

---

## Practical call sequence (what your demo should look like)

Replacing this (which leaks a capability you don’t want to store):

```rust
let (mark1, next_key1) = chain.append_mark_with_key(
    &["bob", "charlie"], Utc::now(), &obj_hash2, next_key0, 1
)?;
```

with a **two‑step** sequence per mark:

```rust
// 1) Precommit for NEXT mark — Round‑1 only.
//    This computes and CONSUMES nextKey_j to finalize the PREVIOUS mark (j).
chain.precommit_next_mark(&["bob", "charlie"], 1)?; // j+1 = 1 here; finalizes mark 0 internally

// 2) Append this mark — replay Round‑1 for seq=1, run Round‑2 for seq=1,
//    recompute key_1 from Root_1, verify it matches mark 0’s precommit,
//    AND (inside) do precommit for seq=2 to finish mark 1 without exposing nextKey_1.
let mark1 = chain.append_mark_stateless(&["bob", "charlie"], Utc::now(), &obj_hash1, 1)?;
```

From there:

```rust
chain.precommit_next_mark(&["alice", "bob"], 2)?;
let mark2 = chain.append_mark_stateless(&["alice", "bob"], Utc::now(), &obj_hash2, 2)?;
```

…and so on. The demo crate can make this ergonomic with a higher‑level helper that does “append M<j> + precommit M\<j+1>” back‑to‑back if you want a single call.

---

## Notes and guardrails

* **Nonce handling:** participants **must** keep their `SigningNonces` for `seq` until Round‑2 completes for that same `seq`, then zeroize. This is the standard FROST rule; do not regenerate them. ([Docs.rs][1])
* **Replayed commitments check:** when you replay Round‑1 for `seq` before Round‑2, you recompute `Root_seq` and verify the previous mark’s hash recomputes correctly with `candidate_nextKey = kdf_next(id, seq, Root_seq)`. If it doesn’t, abort—the wrong commitments were presented.
* **Message binding:** include `Root_seq` inside the message bytes you pass to `SigningPackage::new(...)` for Round‑2, so the Round‑2 signature is unambiguously tied to that exact set of commitments you used for `key_seq`. (The FROST APIs let you pick arbitrary message bytes; you already pass a message to `SigningPackage::new`.) ([Docs.rs][1])
* **No new PM fields:** `nextKey` remains hidden (committed inside `hash` only), and the chain remains indistinguishable from a single‑signer PM chain.
* **APIs used are public:** `round1::commit`, `round2::sign`, `SigningPackage::new`, map types, and serde/serialization are all public in frost‑ed25519 2.1.0. ([Docs.rs][1])

---

## Why not just derive `key_{j+1}` from signature `z_j`?

You *could* (and that works), but then you’d need to keep `nextKey_j` or `z_j` somewhere to compute `key_{j+1}` later. Your requirement was **no state between generations except local FROST share material**; the “look‑ahead from Round‑1 commitments” pattern above is the clean way to achieve that without persisting a capability value (and it preserves the necessary threshold gating).

---

## References (APIs)

* **frost‑ed25519 2.1.0**: Round‑1/2 functions, SigningPackage construction, serde/serialization features (enabled by default). ([Docs.rs][1])
* **FROST core serialization helpers** used under the hood for canonical group/field bytes, enabling a stable `Root` computation. ([Docs.rs][2])
* **bc‑crypto**: simple `sha256()` you can call directly for both `Root` and the KDF construction.

---

**Bottom line:** move to a **no‑`nextKey`‑at‑rest**, **two‑ceremony** pipeline where `nextKey` is always a *function of the next mark’s Round‑1 commitments*. The only state anyone keeps is the per‑signer nonces and commitments for the in‑flight `seq`, which each signer holds privately until Round‑2 completes.

[1]: https://docs.rs/frost-ed25519/latest/frost_ed25519/round2/fn.sign.html "sign in frost_ed25519::round2 - Rust"
[2]: https://docs.rs/frost-ed25519/latest/frost_ed25519/round1/index.html "frost_ed25519::round1 - Rust"
