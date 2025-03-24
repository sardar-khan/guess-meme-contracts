use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer};
use anchor_spl::token::{spl_token::instruction::AuthorityType, SetAuthority};
use anchor_spl::{
    associated_token::{self, AssociatedToken},
    metadata::{self, mpl_token_metadata::types::DataV2, CreateMetadataAccountsV3},
    token::{self, Mint, MintTo, Token, TokenAccount},
};

declare_id!("9HtryVvUYVdJpuX9GA6rD11m4RbrThdZQp2CSfjCLTV6");

pub mod native_mint {
    use anchor_lang::declare_id;

    declare_id!("So11111111111111111111111111111111111111112");
}

pub mod config_feature {
    pub mod withdraw_authority {
        use anchor_lang::declare_id;
        declare_id!("7QMH9DWpavmAP4q3D4maqHwVGh6NA4dZ3kstmVBwmjCX");
    }
}

#[program]
pub mod hype {
    use super::*;

    /// Creates the global state.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        require!(
            !ctx.accounts.global.initialized,
            HypeError::AlreadyInitialized
        );

        ctx.accounts.global.authority = *ctx.accounts.user.key;
        ctx.accounts.global.initialized = true;

        Ok(())
    }

    /// Sets the global state parameters.
    pub fn set_params(
        ctx: Context<SetParams>,
        token_fee_recipient: Pubkey,
        fee_recipient: Pubkey,
        initial_virtual_token_reserves: u64,
        initial_virtual_sol_reserves: u64,
        initial_real_token_reserves: u64,
        token_total_supply: u64,
        fee_basis_points: u64,
    ) -> Result<()> {
        require!(ctx.accounts.global.initialized, HypeError::NotInitialized);
        require_keys_eq!(
            ctx.accounts.user.key(),
            ctx.accounts.global.authority,
            HypeError::NotAuthorized
        );

        ctx.accounts.global.token_fee_recipient = token_fee_recipient;
        ctx.accounts.global.fee_recipient = fee_recipient;
        ctx.accounts.global.initial_virtual_token_reserves = initial_virtual_token_reserves;
        ctx.accounts.global.initial_virtual_sol_reserves = initial_virtual_sol_reserves;
        ctx.accounts.global.initial_real_token_reserves = initial_real_token_reserves;
        ctx.accounts.global.token_total_supply = token_total_supply;
        ctx.accounts.global.fee_basis_points = fee_basis_points;

        emit!(SetParamsEvent {
            token_fee_recipient,
            fee_recipient,
            initial_virtual_token_reserves,
            initial_virtual_sol_reserves,
            initial_real_token_reserves,
            token_total_supply,
            fee_basis_points,
        });

        Ok(())
    }

    /// Creates a new coin and bonding curve.
    pub fn create(
        ctx: Context<Create>,
        name: String,
        symbol: String,
        uri: String,
        max_supply_percent: u8,
    ) -> Result<()> {
        // initialize the bonding curve parameters
        ctx.accounts.bonding_curve.virtual_token_reserves = ctx.accounts.global.initial_virtual_token_reserves;
        ctx.accounts.bonding_curve.virtual_sol_reserves =
            ctx.accounts.global.initial_virtual_sol_reserves;
        ctx.accounts.bonding_curve.real_token_reserves = ctx.accounts.global.initial_real_token_reserves;
        ctx.accounts.bonding_curve.real_sol_reserves = 0;
        ctx.accounts.bonding_curve.token_total_supply = ctx.accounts.global.token_total_supply;

        require!(
            (max_supply_percent > 0) && (max_supply_percent <= 100),
            HypeError::InvalidMaxSupply
        );

        ctx.accounts.bonding_curve.max_supply_percent = max_supply_percent;

        // set the metadata for the token
        helpers::set_metadata(&ctx, name.clone(), symbol.clone(), uri.clone())?;

        // mint tokens to the bonding curve
        helpers::mint_to_bonding_curve(&ctx, ctx.accounts.global.token_total_supply)?;

        // revoke the mint authority
       

        emit!(CreateEvent {
            name,
            symbol,
            uri,
            mint: ctx.accounts.mint.key(),
            bonding_curve: ctx.accounts.bonding_curve.key(),
            user: ctx.accounts.user.key(),
            max_percent_supply: ctx.accounts.bonding_curve.max_supply_percent
        });

        Ok(())
    }
    pub fn meta(
        ctx: Context<UpdateMetadata>,
        name: String,
        symbol: String,
        uri: String,
    ) -> Result<()> {
        // initialize the bonding curve parameters
        require_keys_eq!(
            ctx.accounts.user.key(),
            ctx.accounts.global.authority,
            HypeError::NotAuthorized
        );
        // set the metadata for the token
        helpers::update_metadata(&ctx, name.clone(), symbol.clone(), uri.clone())?;
        helpers::revoke_mint_authority(&ctx)?;
        Ok(())
    }
    /// Buys tokens from a bonding curve.
    pub fn buy(ctx: Context<Buy>, amount: u64, max_sol_cost: u64) -> Result<()> {
        let mut famount = amount;

        if amount > ctx.accounts.bonding_curve.real_token_reserves {
            famount = ctx.accounts.bonding_curve.real_token_reserves;
        }

        if ctx.accounts.bonding_curve.max_supply_percent < 100 {
            let max_allowed_amount: u64 = (ctx.accounts.bonding_curve.initial_real_token_reserves
                * ctx.accounts.bonding_curve.max_supply_percent as u64)
                / 100;

            require!(
                (ctx.accounts.associated_user.amount + famount) <= max_allowed_amount,
                HypeError::MaxSupplyExceeded
            );
        }

        // calculate the sol cost and fee
        let sol_cost = ctx.accounts.bonding_curve.buy_quote(famount as u128);
        let fee = ctx.accounts.global.get_fee(sol_cost);

        // check that the sol cost is within the slippage tolerance
        require!(
            sol_cost + fee <= max_sol_cost,
            HypeError::TooMuchSolRequired
        );
        require_keys_eq!(
            ctx.accounts.associated_bonding_curve.mint,
            ctx.accounts.mint.key(),
            HypeError::MintDoesNotMatchBondingCurve
        );
        require!(
            !ctx.accounts.bonding_curve.complete,
            HypeError::BondingCurveComplete
        );

        // update the bonding curve parameters
        ctx.accounts.bonding_curve.virtual_token_reserves -= famount;
        ctx.accounts.bonding_curve.real_token_reserves -= famount;
        ctx.accounts.bonding_curve.virtual_sol_reserves += sol_cost;
        ctx.accounts.bonding_curve.real_sol_reserves += sol_cost;

        if ctx.accounts.bonding_curve.real_token_reserves == 0 {
            ctx.accounts.bonding_curve.complete = true;

            emit!(CompleteEvent {
                mint: ctx.accounts.mint.key(),
                user: ctx.accounts.user.key(),
                bonding_curve: ctx.accounts.bonding_curve.key(),
                timestamp: Clock::get()?.unix_timestamp,
            });
        }

        // transfer the tokens from the bonding curve to the user
        helpers::transfer_tokens_from_bonding_curve_to_user(&ctx, famount)?;

        // transfer the sol from the user to the bonding curve
        helpers::transfer_sol_from_user_to_bonding_curve(&ctx, sol_cost)?;

        // transfer the sol fee to the fee recipient
        helpers::transfer_sol_from_user_to_fee_recipient(&ctx, fee)?;

        emit!(TradeEvent {
            user: ctx.accounts.user.key(),
            sol_amount: sol_cost,
            token_amount: famount,
            is_buy: true,
            mint: ctx.accounts.mint.key(),
            timestamp: Clock::get()?.unix_timestamp,
            virtual_sol_reserves: ctx.accounts.bonding_curve.virtual_sol_reserves,
            virtual_token_reserves: ctx.accounts.bonding_curve.virtual_token_reserves,
        });

        Ok(())
    }

    /// Sells tokens into a bonding curve.
    pub fn sell(ctx: Context<Sell>, amount: u64, min_sol_output: u64) -> Result<()> {
        let sol_output = ctx.accounts.bonding_curve.sell_quote(amount as u128);
        let fee = ctx.accounts.global.get_fee(sol_output);

        // check that the sol cost is within the slippage tolerance
        require!(
            sol_output - fee >= min_sol_output,
            HypeError::TooLittleSolReceived
        );
        require_keys_eq!(
            ctx.accounts.associated_bonding_curve.mint,
            ctx.accounts.mint.key(),
            HypeError::MintDoesNotMatchBondingCurve
        );
        require!(
            !ctx.accounts.bonding_curve.complete,
            HypeError::BondingCurveComplete
        );

        // update the bonding curve parameters
        ctx.accounts.bonding_curve.virtual_token_reserves += amount;
        ctx.accounts.bonding_curve.real_token_reserves += amount;
        ctx.accounts.bonding_curve.virtual_sol_reserves -= sol_output;
        ctx.accounts.bonding_curve.real_sol_reserves -= sol_output;

        // transfer the tokens from the user to the bonding curve
        helpers::transfer_tokens_from_user_to_bonding_curve(&ctx, amount)?;

        // transfer the sol from the bonding curve to the user
        helpers::transfer_sol_from_bonding_curve_to_user(&ctx, sol_output - fee)?;

        // transfer the sol fee to the fee recipient
        helpers::transfer_sol_from_bonding_curve_to_fee_recipient(&ctx, fee)?;

        emit!(TradeEvent {
            user: ctx.accounts.user.key(),
            sol_amount: sol_output,
            token_amount: amount,
            is_buy: false,
            mint: ctx.accounts.mint.key(),
            timestamp: Clock::get()?.unix_timestamp,
            virtual_sol_reserves: ctx.accounts.bonding_curve.virtual_sol_reserves,
            virtual_token_reserves: ctx.accounts.bonding_curve.virtual_token_reserves,
        });

        Ok(())
    }

    /// Allows the admin to withdraw liquidity for a migration once the bonding curve completes
    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
        require!(
            ctx.accounts.bonding_curve.complete,
            HypeError::BondingCurveNotComplete
        );
        require_keys_eq!(
            config_feature::withdraw_authority::ID,
            ctx.accounts.user.key(),
            HypeError::NotAuthorized
        );

        require_keys_eq!(
            ctx.accounts.global.token_fee_recipient,
            ctx.accounts.token_fee_recipient.key(),
            HypeError::NotAuthorized
        );

        // transfer the tokens from the bonding curve to the admin
        helpers::transfer_tokens_from_bonding_curve_to_admin(
            &ctx,
            ctx.accounts.associated_bonding_curve.amount,
        )?;

        // transfer the sol from the bonding curve to the admin
        helpers::transfer_sol_from_bonding_curve_to_admin(
            &ctx,
            ctx.accounts.bonding_curve.real_sol_reserves,
        )?;

        // update the bonding curve parameters
        ctx.accounts.bonding_curve.real_sol_reserves = 0;
        ctx.accounts.bonding_curve.virtual_sol_reserves = 0;
        ctx.accounts.bonding_curve.real_token_reserves = 0;
        ctx.accounts.bonding_curve.virtual_token_reserves = 0;

          emit!(WithdrawEvent {
                mint: ctx.accounts.mint.key(),
                admin: ctx.accounts.user.key(),
                bonding_curve: ctx.accounts.bonding_curve.key(),
                timestamp: Clock::get()?.unix_timestamp,
                amount_solana: Clock::get()?.unix_timestamp,
                amount_eth: Clock::get()?.unix_timestamp,
            });

        Ok(())
    }
}

mod helpers {
    use super::*;

    pub fn transfer_tokens_from_bonding_curve_to_admin(
        ctx: &Context<Withdraw>,
        token_amount: u64,
    ) -> Result<()> {
        let mint_key = ctx.accounts.mint.key();
        let authority_seed = &[
            b"bonding-curve".as_ref(),
            mint_key.as_ref(),
            &[ctx.bumps.bonding_curve],
        ];
        let seeds = [authority_seed.as_slice()];

        let token_fee: u64 = (ctx.accounts.global.token_total_supply * 1) / 100;

        let new_token_amount: u64 = token_amount - token_fee;

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.associated_bonding_curve.to_account_info(),
                    to: ctx.accounts.associated_user.to_account_info(),
                    authority: ctx.accounts.bonding_curve.to_account_info(),
                },
                &seeds,
            ),
            new_token_amount,
        ).ok();

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.associated_bonding_curve.to_account_info(),
                    to: ctx
                        .accounts
                        .associated_token_fee_recipient
                        .to_account_info(),
                    authority: ctx.accounts.bonding_curve.to_account_info(),
                },
                &seeds,
            ),
            token_fee,
        )
    }

    pub fn transfer_sol_from_bonding_curve_to_admin(
        ctx: &Context<Withdraw>,
        sol_amount: u64,
    ) -> Result<()> {
        ctx.accounts.bonding_curve.sub_lamports(sol_amount)?;
        ctx.accounts.user.add_lamports(sol_amount)?;

        Ok(())
    }

    pub fn transfer_sol_from_bonding_curve_to_user(
        ctx: &Context<Sell>,
        sol_amount: u64,
    ) -> Result<()> {
        ctx.accounts.bonding_curve.sub_lamports(sol_amount)?;
        ctx.accounts.user.add_lamports(sol_amount)?;

        Ok(())
    }

    pub fn transfer_sol_from_bonding_curve_to_fee_recipient(
        ctx: &Context<Sell>,
        sol_amount: u64,
    ) -> Result<()> {
        // check the fee recipient matches the global state fee recipient
        require_keys_eq!(
            ctx.accounts.global.fee_recipient,
            ctx.accounts.fee_recipient.key(),
            HypeError::NotAuthorized
        );

        ctx.accounts.bonding_curve.sub_lamports(sol_amount)?;
        ctx.accounts.fee_recipient.add_lamports(sol_amount)?;

        Ok(())
    }

    pub fn transfer_tokens_from_user_to_bonding_curve(
        ctx: &Context<Sell>,
        token_amount: u64,
    ) -> Result<()> {
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.associated_user.to_account_info(),
                    to: ctx.accounts.associated_bonding_curve.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            token_amount,
        )
    }

    pub fn transfer_tokens_from_bonding_curve_to_user(
        ctx: &Context<Buy>,
        token_amount: u64,
    ) -> Result<()> {
        let mint_key = ctx.accounts.mint.key();
        let authority_seed = &[
            b"bonding-curve".as_ref(),
            mint_key.as_ref(),
            &[ctx.bumps.bonding_curve],
        ];
        let seeds = [authority_seed.as_slice()];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.associated_bonding_curve.to_account_info(),
                    to: ctx.accounts.associated_user.to_account_info(),
                    authority: ctx.accounts.bonding_curve.to_account_info(),
                },
                &seeds,
            ),
            token_amount,
        )
    }

    pub fn transfer_sol_from_user_to_bonding_curve(
        ctx: &Context<Buy>,
        sol_amount: u64,
    ) -> Result<()> {
        // transfer sol to associated account
        transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.user.to_account_info(),
                    to: ctx.accounts.bonding_curve.to_account_info(),
                },
            ),
            sol_amount,
        )
    }

    pub fn transfer_sol_from_user_to_fee_recipient(
        ctx: &Context<Buy>,
        sol_amount: u64,
    ) -> Result<()> {
        // check the fee recipient matches the global state fee recipient
        require_keys_eq!(
            ctx.accounts.global.fee_recipient,
            ctx.accounts.fee_recipient.key(),
            HypeError::NotAuthorized
        );

        // transfer sol to associated account
        transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.user.to_account_info(),
                    to: ctx.accounts.fee_recipient.to_account_info(),
                },
            ),
            sol_amount,
        )
    }

    pub fn mint_to_bonding_curve<'info>(
        ctx: &Context<Create>,
        token_total_supply: u64,
    ) -> Result<()> {
        let authority_seed = &[b"mint-authority".as_ref(), &[ctx.bumps.mint_authority]];
        let seeds = [authority_seed.as_slice()];

        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.associated_bonding_curve.to_account_info(),
                authority: ctx.accounts.mint_authority.to_account_info(),
            },
            &seeds,
        );

        token::mint_to(cpi_ctx, token_total_supply)
    }

    pub fn set_metadata<'info>(
        ctx: &Context<Create>,
        name: String,
        symbol: String,
        uri: String,
    ) -> Result<()> {
        // set the metadata for the token
        let data = DataV2 {
            name,
            symbol,
            uri,
            seller_fee_basis_points: 0,
            creators: None,
            collection: None,
            uses: None,
        };

        let authority_seed = &[b"mint-authority".as_ref(), &[ctx.bumps.mint_authority]];
        let seeds = [authority_seed.as_slice()];

        let metadata_ctx = CreateMetadataAccountsV3 {
            metadata: ctx.accounts.metadata.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            mint_authority: ctx.accounts.mint_authority.to_account_info(),
            payer: ctx.accounts.user.to_account_info(),
            update_authority: ctx.accounts.mint_authority.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
            rent: ctx.accounts.rent.to_account_info(),
        };

        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.mpl_token_metadata.to_account_info(),
            metadata_ctx,
            &seeds,
        );

        metadata::create_metadata_accounts_v3(cpi_ctx, data, true, true, None)
    }
    pub fn update_metadata<'info>(
        ctx: &Context<UpdateMetadata>,
        name: String,
        symbol: String,
        uri: String,
    ) -> Result<()> {
        // Create a new DataV2 with the provided values (or "test" if you want to hardcode)
        let new_data = DataV2 {
            name,
            symbol,
            uri,
            seller_fee_basis_points: 0,
            creators: None,
            collection: None,
            uses: None,
        };

        // Build the signer seeds for the PDA update authority.
        // Make sure that in your UpdateMetadata context you have a bump for the PDA (here we assume it's stored under ctx.bumps.mint_authority)
        let authority_seed = &[b"mint-authority".as_ref(), &[ctx.bumps.mint_authority]];
        let seeds = [authority_seed.as_slice()];

        // Build the CPI context using new_with_signer so that the PDA can "sign" the instruction.
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.mpl_token_metadata.to_account_info(),
            metadata::UpdateMetadataAccountsV2 {
                metadata: ctx.accounts.metadata.to_account_info(),
                // Use the PDA as the update authority.
                update_authority: ctx.accounts.mint_authority.to_account_info(),
            },
            &seeds,
        );

        // Call the update function.
        // The parameters here:
        // - new_update_authority: None (update authority remains the same)
        // - new_data: Some(new_data) to update the metadata data,
        // - primary_sale_happened: None (unchanged, or Some(true) if desired),
        // - is_mutable: Some(false) (or Some(true) as needed)
        metadata::update_metadata_accounts_v2(cpi_ctx, None, Some(new_data), None, Some(false))?;
        Ok(())
    }

    pub fn revoke_mint_authority(ctx: &Context<UpdateMetadata>) -> Result<()> {
        // renounce the mint authority
        let renounce_accounts = SetAuthority {
            account_or_mint: ctx.accounts.mint.to_account_info(),
            current_authority: ctx.accounts.mint_authority.to_account_info(),
        };

        let authority_seed = &[b"mint-authority".as_ref(), &[ctx.bumps.mint_authority]];
        let seeds = [authority_seed.as_slice()];
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            renounce_accounts,
            &seeds,
        );

        token::set_authority(cpi_ctx, AuthorityType::MintTokens, None)
    }
}

#[error_code]
pub enum HypeError {
    #[msg("The given account is not authorized to execute this instruction.")]
    NotAuthorized,
    #[msg("The program is already initialized.")]
    AlreadyInitialized,
    #[msg("slippage: Too much SOL required to buy the given amount of tokens.")]
    TooMuchSolRequired,
    #[msg("slippage: Too little SOL received to sell the given amount of tokens.")]
    TooLittleSolReceived,
    #[msg("The mint does not match the bonding curve.")]
    MintDoesNotMatchBondingCurve,
    #[msg("The bonding curve has completed and liquidity migrated to raydium.")]
    BondingCurveComplete,
    #[msg("The bonding curve has not completed.")]
    BondingCurveNotComplete,
    #[msg("The program is not initialized.")]
    NotInitialized,
    #[msg("Max buy supply percentage provided is invalid")]
    InvalidMaxSupply,
    #[msg("Max buy supply percentage set by token creator has been exceeded")]
    MaxSupplyExceeded,
}

#[account]
pub struct Global {
    pub initialized: bool,
    pub authority: Pubkey,
    pub token_fee_recipient: Pubkey,
    pub fee_recipient: Pubkey,
    pub initial_virtual_token_reserves: u64,
    pub initial_virtual_sol_reserves: u64,
    pub initial_real_token_reserves: u64,
    pub token_total_supply: u64,
    pub fee_basis_points: u64,
}

impl Global {
    // 8 (discriminator) + 1 (initialized) + 32 (authority)  + 8 (initial_virtual_token_reserves) + 8 (initial_virtual_sol_reserves) + 8 (initial_real_token_reserves) + 8 (token_total_supply)
    pub const SIZE: usize = 8 + 32 + 1 + 32 + 8 + 8 + 8 + 8 + 8 + 32;

    pub fn get_fee(&self, amount: u64) -> u64 {
        let fee = (amount as u128 * self.fee_basis_points as u128) / 10_000;
        return fee as u64;
    }
}

#[account]
pub struct BondingCurve {
    pub virtual_token_reserves: u64,
    pub virtual_sol_reserves: u64,
    pub real_token_reserves: u64,
    pub real_sol_reserves: u64,
    pub token_total_supply: u64,
    pub complete: bool,
    pub max_supply_percent: u8,
}

impl BondingCurve {
    pub fn buy_quote(&self, amount: u128) -> u64 {
        let virtual_sol_reserves = self.virtual_sol_reserves as u128;
        let virtual_token_reserves = self.virtual_token_reserves as u128;
        let sol_cost: u64 =
            ((amount * virtual_sol_reserves) / (virtual_token_reserves - amount)) as u64;

        return sol_cost + 1; // always round up
    }

    pub fn sell_quote(&self, amount: u128) -> u64 {
        let virtual_sol_reserves = self.virtual_sol_reserves as u128;
        let virtual_token_reserves = self.virtual_token_reserves as u128;
        let sol_output: u64 =
            ((amount * virtual_sol_reserves) / (virtual_token_reserves + amount)) as u64;

        return sol_output;
    }
}

impl BondingCurve {
    // 8 (discriminator)
    // + 8 (virtual_token_reserves)
    // + 8 (virtual_sol_reserves)
    // + 8 (real_token_reserves)
    // + 8 (real_sol_reserves)
    // + 8 (token_total_supply)
    // + 1 (complete)
    // + 1 (max_supply_percent)
    pub const SIZE: usize = 8 + 8 + 8 + 8 + 8 + 8 + 1 + 1;
}

#[event]
pub struct CreateEvent {
    pub name: String,
    pub symbol: String,
    pub uri: String,
    pub mint: Pubkey,
    pub bonding_curve: Pubkey,
    pub user: Pubkey,
    pub max_percent_supply: u8,
}

#[event]
pub struct TradeEvent {
    mint: Pubkey,
    sol_amount: u64,
    token_amount: u64,
    is_buy: bool,
    user: Pubkey,
    timestamp: i64,
    virtual_sol_reserves: u64,
    virtual_token_reserves: u64,
}

#[event]
pub struct CompleteEvent {
    pub user: Pubkey,
    pub mint: Pubkey,
    pub bonding_curve: Pubkey,
    pub timestamp: i64,
}
#[event]
pub struct WithdrawEvent {
    pub admin: Pubkey,
    pub mint: Pubkey,
    pub bonding_curve: Pubkey,
    pub timestamp: i64,
    pub amount_solana: u64,
    pub amount_token: u64,
}

#[event]
pub struct SetParamsEvent {
    pub token_fee_recipient: Pubkey,
    pub fee_recipient: Pubkey,
    pub initial_virtual_token_reserves: u64,
    pub initial_virtual_sol_reserves: u64,
    pub initial_real_token_reserves: u64,
    pub token_total_supply: u64,
    pub fee_basis_points: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = user, space = Global::SIZE, seeds = [b"global"], bump)]
    pub global: Account<'info, Global>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetParams<'info> {
    #[account(mut, seeds = [b"global"], bump)]
    pub global: Account<'info, Global>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Create<'info> {
    #[account(
        init,
        payer = user,
        mint::decimals = 6,
        mint::authority = mint_authority,
    )]
    pub mint: Box<Account<'info, Mint>>,
    #[account(seeds = [b"mint-authority"], bump)]
    /// CHECK: The mint authority is the program derived address.
    pub mint_authority: UncheckedAccount<'info>,
    #[account(
        init,
        payer = user,
        space = BondingCurve::SIZE,
        seeds = [b"bonding-curve", mint.key().as_ref()], 
        bump
    )]
    pub bonding_curve: Box<Account<'info, BondingCurve>>,
    #[account(
        init,
        payer = user,
        associated_token::mint = mint,
        associated_token::authority = bonding_curve,
    )]
    pub associated_bonding_curve: Box<Account<'info, TokenAccount>>,
    #[account(seeds = [b"global"], bump)]
    pub global: Box<Account<'info, Global>>,
    #[account(address = metadata::ID)]
    /// CHECK: We already check the address matches the mpl_token_metadata program id.
    pub mpl_token_metadata: UncheckedAccount<'info>,
    #[account(
        mut,
        seeds = [b"metadata", metadata::ID.as_ref(),  mint.key().as_ref()],
        bump,
        seeds::program = metadata::ID
    )]

    /// CHECK: No need to check this
    pub metadata: UncheckedAccount<'info>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub rent: Sysvar<'info, Rent>,
}
#[derive(Accounts)]
pub struct UpdateMetadata<'info> {
    #[account(
        mut,
        
        mint::decimals = 6,
        mint::authority = mint_authority,
    )]
    pub mint: Box<Account<'info, Mint>>,
    #[account(seeds = [b"mint-authority"], bump)]
    /// CHECK: The mint authority is the program derived address.
    pub mint_authority: UncheckedAccount<'info>,
    #[account(
        mut,
       
        seeds = [b"bonding-curve", mint.key().as_ref()], 
        bump
    )]
    pub bonding_curve: Box<Account<'info, BondingCurve>>,
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = bonding_curve,
    )]
    pub associated_bonding_curve: Box<Account<'info, TokenAccount>>,
    #[account(seeds = [b"global"], bump)]
    pub global: Box<Account<'info, Global>>,
    #[account(address = metadata::ID)]
    /// CHECK: We already check the address matches the mpl_token_metadata program id.
    pub mpl_token_metadata: UncheckedAccount<'info>,
    #[account(
        mut,
        seeds = [b"metadata", metadata::ID.as_ref(),  mint.key().as_ref()],
        bump,
        seeds::program = metadata::ID
    )]

    /// CHECK: No need to check this
    pub metadata: UncheckedAccount<'info>,
    #[account(mut)]
    pub user: Signer<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct Buy<'info> {
    #[account(seeds = [b"global"], bump)]
    pub global: Box<Account<'info, Global>>,
    #[account(mut)]
    /// CHECK: destination address
    pub fee_recipient: UncheckedAccount<'info>,
    pub mint: Box<Account<'info, Mint>>,
    #[account(mut, seeds = [b"bonding-curve", mint.key().as_ref()], bump)]
    pub bonding_curve: Box<Account<'info, BondingCurve>>,
    #[account(
        mut,
        seeds = [bonding_curve.key().as_ref(), token::ID.as_ref(), mint.key().as_ref()],
        bump,
        seeds::program = associated_token::ID
    )]
    pub associated_bonding_curve: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
         associated_token::mint = mint,
        associated_token::authority = user,
    )]
    pub associated_user: Box<Account<'info, TokenAccount>>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct Sell<'info> {
    #[account(seeds = [b"global"], bump)]
    pub global: Box<Account<'info, Global>>,
    #[account(mut)]
    /// CHECK: destination address
    pub fee_recipient: UncheckedAccount<'info>,
    pub mint: Box<Account<'info, Mint>>,
    #[account(mut, seeds = [b"bonding-curve", mint.key().as_ref()], bump)]
    pub bonding_curve: Box<Account<'info, BondingCurve>>,
    #[account(
        mut,
        seeds = [bonding_curve.key().as_ref(), token::ID.as_ref(), mint.key().as_ref()],
        bump,
        seeds::program = associated_token::ID
    )]
    pub associated_bonding_curve: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = user,
    )]
    pub associated_user: Box<Account<'info, TokenAccount>>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(seeds = [b"global"], bump)]
    pub global: Box<Account<'info, Global>>,
    pub mint: Box<Account<'info, Mint>>,
    #[account(mut, seeds = [b"bonding-curve", mint.key().as_ref()], bump)]
    pub bonding_curve: Box<Account<'info, BondingCurve>>,
    #[account(
        mut,
        seeds = [bonding_curve.key().as_ref(), token::ID.as_ref(), mint.key().as_ref()],
        bump,
        seeds::program = associated_token::ID
    )]
    pub associated_bonding_curve: Box<Account<'info, TokenAccount>>,
    #[account(mut)]
    /// CHECK: destination address
    pub token_fee_recipient: UncheckedAccount<'info>,
    #[account(mut)]
    pub associated_token_fee_recipient: Box<Account<'info, TokenAccount>>,
    #[account(mut)]
    pub associated_user: Box<Account<'info, TokenAccount>>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub rent: Sysvar<'info, Rent>,
}
