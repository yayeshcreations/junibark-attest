import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { JunibarkAttest } from "../target/types/junibark_attest";
import { assert } from "chai";
import { createHash, randomBytes } from "crypto";

// The security tests here are the point of this file. Anyone can prove the
// happy path works; what a donor needs proven is that nobody except the cause
// can write to its record — JuniBark very much included.

const CATEGORY_VET = 0;
const CATEGORY_OTHER = 4;

const sha256 = (s: string) => createHash("sha256").update(s).digest();
const profileHash = () => sha256(`profile-${randomBytes(8).toString("hex")}`);

describe("junibark-attest", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const program = anchor.workspace.JunibarkAttest as Program<JunibarkAttest>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;

  const causePda = (h: Buffer) =>
    anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("cause"), h],
      program.programId
    )[0];

  const attestPda = (cause: anchor.web3.PublicKey, index: number) => {
    const idx = Buffer.alloc(4);
    idx.writeUInt32LE(index);
    return anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("attest"), cause.toBuffer(), idx],
      program.programId
    )[0];
  };

  const fundedKeypair = async () => {
    const kp = anchor.web3.Keypair.generate();
    const sig = await provider.connection.requestAirdrop(kp.publicKey, 2e9);
    await provider.connection.confirmTransaction(sig);
    return kp;
  };

  async function newCause() {
    const h = profileHash();
    const authority = await fundedKeypair();
    const cause = causePda(h);
    await program.methods
      .initializeCause([...h])
      .accounts({ cause, authority: authority.publicKey })
      .signers([authority])
      .rpc();
    return { h, authority, cause };
  }

  it("initializes a cause with zeroed counters", async () => {
    const { authority, cause, h } = await newCause();
    const acct = await program.account.cause.fetch(cause);
    assert.equal(acct.authority.toBase58(), authority.publicKey.toBase58());
    assert.deepEqual(Buffer.from(acct.profileIdHash), h);
    assert.equal(acct.totalAttestedCents.toNumber(), 0);
    assert.equal(acct.attestationCount, 0);
  });

  it("records an attestation and advances the running total", async () => {
    const { authority, cause } = await newCause();
    const doc = sha256("vet-invoice-001.pdf");

    await program.methods
      .attestSpend(new anchor.BN(12_500), [...doc], CATEGORY_VET)
      .accounts({
        cause,
        attestation: attestPda(cause, 0),
        authority: authority.publicKey,
      })
      .signers([authority])
      .rpc();

    const a = await program.account.attestation.fetch(attestPda(cause, 0));
    assert.equal(a.amountCents.toNumber(), 12_500);
    assert.deepEqual(Buffer.from(a.docHash), doc);
    assert.equal(a.category, CATEGORY_VET);
    assert.isFalse(a.revoked);
    assert.isAbove(a.attestedAt.toNumber(), 0);

    const c = await program.account.cause.fetch(cause);
    assert.equal(c.totalAttestedCents.toNumber(), 12_500);
    assert.equal(c.attestationCount, 1);
  });

  // --- Security: only the cause may write its own record ---

  it("REJECTS an attestation signed by anyone but the cause authority", async () => {
    const { cause } = await newCause();
    const attacker = await fundedKeypair();

    try {
      await program.methods
        .attestSpend(new anchor.BN(999), [...sha256("forged.pdf")], CATEGORY_OTHER)
        .accounts({
          cause,
          attestation: attestPda(cause, 0),
          authority: attacker.publicKey,
        })
        .signers([attacker])
        .rpc();
      assert.fail("an attacker wrote to a cause they do not own");
    } catch (e: any) {
      assert.include(e.toString(), "Unauthorized");
    }

    const c = await program.account.cause.fetch(cause);
    assert.equal(c.attestationCount, 0, "counter moved on a rejected write");
  });

  it("REJECTS a revoke signed by anyone but the cause authority", async () => {
    const { authority, cause } = await newCause();
    await program.methods
      .attestSpend(new anchor.BN(500), [...sha256("r.pdf")], CATEGORY_VET)
      .accounts({ cause, attestation: attestPda(cause, 0), authority: authority.publicKey })
      .signers([authority])
      .rpc();

    const attacker = await fundedKeypair();
    try {
      await program.methods
        .revokeAttestation(0)
        .accounts({ cause, attestation: attestPda(cause, 0), authority: attacker.publicKey })
        .signers([attacker])
        .rpc();
      assert.fail("an attacker revoked an attestation belonging to someone else");
    } catch (e: any) {
      assert.include(e.toString(), "Unauthorized");
    }
  });

  // --- Input validation ---

  it("rejects a zero amount", async () => {
    const { authority, cause } = await newCause();
    try {
      await program.methods
        .attestSpend(new anchor.BN(0), [...sha256("x.pdf")], CATEGORY_VET)
        .accounts({ cause, attestation: attestPda(cause, 0), authority: authority.publicKey })
        .signers([authority])
        .rpc();
      assert.fail("accepted a zero-amount attestation");
    } catch (e: any) {
      assert.include(e.toString(), "ZeroAmount");
    }
  });

  it("rejects an all-zero document hash", async () => {
    // A client that forgot to hash the file would otherwise produce an
    // attestation that renders as verified but anchors nothing.
    const { authority, cause } = await newCause();
    try {
      await program.methods
        .attestSpend(new anchor.BN(100), new Array(32).fill(0), CATEGORY_VET)
        .accounts({ cause, attestation: attestPda(cause, 0), authority: authority.publicKey })
        .signers([authority])
        .rpc();
      assert.fail("accepted an empty document hash");
    } catch (e: any) {
      assert.include(e.toString(), "EmptyDocHash");
    }
  });

  it("rejects an out-of-range category", async () => {
    const { authority, cause } = await newCause();
    try {
      await program.methods
        .attestSpend(new anchor.BN(100), [...sha256("x.pdf")], 99)
        .accounts({ cause, attestation: attestPda(cause, 0), authority: authority.publicKey })
        .signers([authority])
        .rpc();
      assert.fail("accepted an invalid category");
    } catch (e: any) {
      assert.include(e.toString(), "InvalidCategory");
    }
  });

  // --- Revocation ---

  it("revokes: subtracts from the total but keeps the row readable", async () => {
    const { authority, cause } = await newCause();
    await program.methods
      .attestSpend(new anchor.BN(7_000), [...sha256("dup.pdf")], CATEGORY_VET)
      .accounts({ cause, attestation: attestPda(cause, 0), authority: authority.publicKey })
      .signers([authority])
      .rpc();

    await program.methods
      .revokeAttestation(0)
      .accounts({ cause, attestation: attestPda(cause, 0), authority: authority.publicKey })
      .signers([authority])
      .rpc();

    const c = await program.account.cause.fetch(cause);
    assert.equal(c.totalAttestedCents.toNumber(), 0, "total did not fall");
    assert.equal(c.attestationCount, 1, "count must not fall — the history is the point");

    const a = await program.account.attestation.fetch(attestPda(cause, 0));
    assert.isTrue(a.revoked);
    assert.equal(a.amountCents.toNumber(), 7_000, "the original amount stays on the record");
  });

  it("rejects a double revoke", async () => {
    const { authority, cause } = await newCause();
    await program.methods
      .attestSpend(new anchor.BN(200), [...sha256("d.pdf")], CATEGORY_VET)
      .accounts({ cause, attestation: attestPda(cause, 0), authority: authority.publicKey })
      .signers([authority])
      .rpc();
    await program.methods
      .revokeAttestation(0)
      .accounts({ cause, attestation: attestPda(cause, 0), authority: authority.publicKey })
      .signers([authority])
      .rpc();

    try {
      await program.methods
        .revokeAttestation(0)
        .accounts({ cause, attestation: attestPda(cause, 0), authority: authority.publicKey })
        .signers([authority])
        .rpc();
      assert.fail("a double revoke would subtract the amount twice");
    } catch (e: any) {
      assert.include(e.toString(), "AlreadyRevoked");
    }
  });
});
