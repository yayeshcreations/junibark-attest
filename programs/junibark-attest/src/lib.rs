// junibark-attest — on-chain spend attestation for charitable causes.
//
// This program moves no money and holds no funds. It records that a cause
// spent an amount, in a category, against a document whose SHA-256 is stored
// here. That hash is the whole point: the receipt itself lives off-chain in
// Cloudinary, but it cannot be swapped after the fact without the hash
// disagreeing, and anyone can check that in a browser.
//
// There is deliberately no admin authority. JuniBark cannot write, edit or
// revoke a cause's attestations. If it could, the guarantee this program
// exists to provide would be worth nothing.
//
// See docs/ETERNAL_SPRINT.md in the JuniBark repo for the rationale.

use anchor_lang::prelude::*;

declare_id!("GLncvCsbvDHdT3844L9mhEYXAGZY1BY7mz3yBawmHFFy");

/// Highest valid `Category` discriminant. Bump when adding a variant.
const MAX_CATEGORY: u8 = 4;

#[program]
pub mod junibark_attest {
    use super::*;

    /// One per verified profile. The signer becomes the only account that can
    /// ever attest against it.
    pub fn initialize_cause(ctx: Context<InitializeCause>, profile_id_hash: [u8; 32]) -> Result<()> {
        let cause = &mut ctx.accounts.cause;
        cause.authority = ctx.accounts.authority.key();
        cause.profile_id_hash = profile_id_hash;
        cause.total_attested_cents = 0;
        cause.attestation_count = 0;
        cause.bump = ctx.bumps.cause;
        Ok(())
    }

    /// Record a spend. Signed by the cause authority only.
    pub fn attest_spend(
        ctx: Context<AttestSpend>,
        amount_cents: u64,
        doc_hash: [u8; 32],
        category: u8,
    ) -> Result<()> {
        require!(amount_cents > 0, AttestError::ZeroAmount);
        require!(category <= MAX_CATEGORY, AttestError::InvalidCategory);
        // A client that forgot to hash the file would otherwise write an
        // attestation that renders as verified while anchoring nothing.
        require!(doc_hash != [0u8; 32], AttestError::EmptyDocHash);

        let cause = &mut ctx.accounts.cause;
        let attestation = &mut ctx.accounts.attestation;

        attestation.cause = cause.key();
        attestation.amount_cents = amount_cents;
        attestation.doc_hash = doc_hash;
        attestation.category = category;
        attestation.attested_at = Clock::get()?.unix_timestamp;
        attestation.revoked = false;
        attestation.bump = ctx.bumps.attestation;

        // Checked: a cause that attested u64::MAX would otherwise wrap the
        // public total around to a small number.
        cause.total_attested_cents = cause
            .total_attested_cents
            .checked_add(amount_cents)
            .ok_or(AttestError::TotalOverflow)?;
        cause.attestation_count = cause
            .attestation_count
            .checked_add(1)
            .ok_or(AttestError::TotalOverflow)?;

        Ok(())
    }

    /// Void an attestation without erasing it.
    ///
    /// Causes make honest bookkeeping mistakes — a receipt entered twice, a
    /// figure typed wrong. Without this the public ledger stays permanently
    /// wrong and the first error destroys the trust the feature exists to
    /// create. The row remains readable and keeps its original amount: the
    /// correction is part of the record, not a deletion from it. That is also
    /// why `attestation_count` never decreases.
    pub fn revoke_attestation(ctx: Context<RevokeAttestation>, _index: u32) -> Result<()> {
        let attestation = &mut ctx.accounts.attestation;
        require!(!attestation.revoked, AttestError::AlreadyRevoked);

        attestation.revoked = true;

        let cause = &mut ctx.accounts.cause;
        cause.total_attested_cents = cause
            .total_attested_cents
            .checked_sub(attestation.amount_cents)
            .ok_or(AttestError::TotalUnderflow)?;

        Ok(())
    }
}

// ---------------------------------------------------------------- accounts

#[account]
#[derive(InitSpace)]
pub struct Cause {
    /// The cause's wallet. The only key that may attest or revoke here.
    pub authority: Pubkey,
    /// SHA-256 of `Profile.id`. Keeps the database id off-chain while still
    /// letting the platform derive this PDA deterministically.
    pub profile_id_hash: [u8; 32],
    /// Sum of live (non-revoked) attestations, in USD cents.
    pub total_attested_cents: u64,
    /// Also the index of the next attestation. Never decreases.
    pub attestation_count: u32,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Attestation {
    pub cause: Pubkey,
    /// USD cents. Integer — no floats on-chain.
    pub amount_cents: u64,
    /// SHA-256 of the receipt file.
    pub doc_hash: [u8; 32],
    /// 0 VetCare · 1 Food · 2 Shelter · 3 Transport · 4 Other
    pub category: u8,
    pub attested_at: i64,
    pub revoked: bool,
    pub bump: u8,
}

// ------------------------------------------------------------ instructions

#[derive(Accounts)]
#[instruction(profile_id_hash: [u8; 32])]
pub struct InitializeCause<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Cause::INIT_SPACE,
        seeds = [b"cause", profile_id_hash.as_ref()],
        bump
    )]
    pub cause: Account<'info, Cause>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AttestSpend<'info> {
    #[account(
        mut,
        seeds = [b"cause", cause.profile_id_hash.as_ref()],
        bump = cause.bump,
        constraint = cause.authority == authority.key() @ AttestError::Unauthorized
    )]
    pub cause: Account<'info, Cause>,

    #[account(
        init,
        payer = authority,
        space = 8 + Attestation::INIT_SPACE,
        seeds = [b"attest", cause.key().as_ref(), cause.attestation_count.to_le_bytes().as_ref()],
        bump
    )]
    pub attestation: Account<'info, Attestation>,

    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(index: u32)]
pub struct RevokeAttestation<'info> {
    #[account(
        mut,
        seeds = [b"cause", cause.profile_id_hash.as_ref()],
        bump = cause.bump,
        constraint = cause.authority == authority.key() @ AttestError::Unauthorized
    )]
    pub cause: Account<'info, Cause>,

    #[account(
        mut,
        seeds = [b"attest", cause.key().as_ref(), index.to_le_bytes().as_ref()],
        bump = attestation.bump,
        // Belt and braces: the seeds already bind it, but an explicit check
        // means a future seed change cannot silently detach the two.
        constraint = attestation.cause == cause.key() @ AttestError::Unauthorized
    )]
    pub attestation: Account<'info, Attestation>,

    pub authority: Signer<'info>,
}

// ----------------------------------------------------------------- errors

#[error_code]
pub enum AttestError {
    #[msg("Unauthorized: only the cause authority may write to this record")]
    Unauthorized,
    #[msg("ZeroAmount: an attestation must record a non-zero amount")]
    ZeroAmount,
    #[msg("EmptyDocHash: the document hash is all zeroes")]
    EmptyDocHash,
    #[msg("InvalidCategory: category is out of range")]
    InvalidCategory,
    #[msg("AlreadyRevoked: this attestation was already revoked")]
    AlreadyRevoked,
    #[msg("TotalOverflow: the running total would overflow")]
    TotalOverflow,
    #[msg("TotalUnderflow: the running total would go negative")]
    TotalUnderflow,
}
