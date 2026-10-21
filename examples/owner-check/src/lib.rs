use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction,
    sysvar::{clock::Clock, rent::Rent, Sysvar},
};

const SPL_TOKEN_ID: Pubkey = Pubkey::new_from_array([
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
]);
const TOKEN_2022_ID: Pubkey = Pubkey::new_from_array([
    0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde, 0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd, 0xda,
    0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27, 0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1, 0x8b, 0xfc,
]);

entrypoint!(process_instruction);

#[inline(never)]
#[no_mangle]
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match data.first().copied().unwrap_or(0) {
        // instruction 0: the BUG -- missing owner check
        0 => withdraw_vulnerable(program_id, accounts),
        // instruction 1: the FIX -- owner checked
        1 => withdraw_safe(program_id, accounts),
        // instruction 2: SPL Token Transfer with the same missing record check
        2 => transfer_token_vulnerable(program_id, accounts),
        // instruction 3: Token-2022 TransferChecked after validating the record
        3 => transfer_token_checked_safe(program_id, accounts),
        // instruction 4: move SOL via a System-program transfer CPI
        4 => system_transfer_vulnerable(program_id, accounts),
        // instruction 5: read the Clock and Rent sysvars, then transfer
        5 => check_clock(program_id, accounts),
        // instruction 6: read sysvars and assert their canonical values
        6 => assert_clock(program_id, accounts),
        // instruction 7: allocate space on a system-owned account via CPI
        7 => system_allocate(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// Reads Clock and Rent and returns Ok only if the modeled canonical values
// arrive (slot 100, rent 3480), isolating the sysvar read from any transfer.
#[inline(never)]
#[no_mangle]
pub fn assert_clock(_program_id: &Pubkey, _accounts: &[AccountInfo]) -> ProgramResult {
    let clock = Clock::get()?;
    let rent = Rent::get()?;
    if clock.slot == 100 && rent.lamports_per_byte_year == 3480 {
        Ok(())
    } else {
        Err(ProgramError::InvalidArgument)
    }
}

// Transfers lamports through a System-program CPI, using an amount taken from
// the untrusted record (same missing-owner-check bug, but via the runtime).
#[inline(never)]
#[no_mangle]
pub fn system_transfer_vulnerable(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let withdrawal_record = next_account_info(it)?;
    let payer = next_account_info(it)?;
    let recipient = next_account_info(it)?;
    let system_program = next_account_info(it)?;

    let amount = read_amount(withdrawal_record)?;
    invoke(
        &system_instruction::transfer(payer.key, recipient.key, amount),
        &[payer.clone(), recipient.clone(), system_program.clone()],
    )
}

// Allocates 100 bytes on a system-owned account via a System-program CPI, then
// checks the account's data length reflects the allocation. Agave's allocate
// calls set_data_length(space), and the caller's AccountInfo sees the new len.
#[inline(never)]
#[no_mangle]
pub fn system_allocate(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let target = next_account_info(it)?;
    let system_program = next_account_info(it)?;

    invoke(
        &system_instruction::allocate(target.key, 100),
        &[target.clone(), system_program.clone()],
    )?;
    if target.data_len() == 100 {
        Ok(())
    } else {
        Err(ProgramError::InvalidAccountData)
    }
}

// Reads the Clock and Rent sysvars and transfers only once they look sane.
#[inline(never)]
#[no_mangle]
pub fn check_clock(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let clock = Clock::get()?;
    let rent = Rent::get()?;
    let it = &mut accounts.iter();
    let treasury = next_account_info(it)?;
    let recipient = next_account_info(it)?;

    if clock.slot >= 1 && rent.lamports_per_byte_year > 0 {
        transfer_lamports(treasury, recipient, 1)?;
    }
    Ok(())
}

// VULNERABLE: reads an untrusted withdrawal record without verifying its owner.
#[inline(never)]
#[no_mangle]
pub fn withdraw_vulnerable(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let withdrawal_record = next_account_info(it)?;
    let treasury = next_account_info(it)?;
    let recipient = next_account_info(it)?;

    if treasury.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // BUG: no `withdrawal_record.owner == program_id` check before trusting data.
    let amount = read_amount(withdrawal_record)?;
    transfer_lamports(treasury, recipient, amount)
}

// SAFE: validates both record and treasury owners before moving lamports.
#[inline(never)]
#[no_mangle]
pub fn withdraw_safe(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let withdrawal_record = next_account_info(it)?;
    let treasury = next_account_info(it)?;
    let recipient = next_account_info(it)?;

    if withdrawal_record.owner != program_id || treasury.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    let amount = read_amount(withdrawal_record)?;
    transfer_lamports(treasury, recipient, amount)
}

#[inline(never)]
fn read_amount(account: &AccountInfo) -> Result<u64, ProgramError> {
    let data = account.try_borrow_data()?;
    let amount_bytes: [u8; 8] = data
        .get(..8)
        .ok_or(ProgramError::InvalidAccountData)?
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(u64::from_le_bytes(amount_bytes))
}

#[inline(never)]
fn transfer_lamports(
    treasury: &AccountInfo,
    recipient: &AccountInfo,
    amount: u64,
) -> ProgramResult {
    let treasury_after = treasury
        .lamports()
        .checked_sub(amount)
        .ok_or(ProgramError::InsufficientFunds)?;
    let recipient_after = recipient
        .lamports()
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // Acquire both borrows before mutating, so aliasing can't leave a partial transfer.
    let mut treasury_lamports = treasury.try_borrow_mut_lamports()?;
    let mut recipient_lamports = recipient.try_borrow_mut_lamports()?;
    **treasury_lamports = treasury_after;
    **recipient_lamports = recipient_after;
    Ok(())
}

// VULNERABLE: same trust bug as withdraw_vulnerable, but value leaves via an SPL Token CPI.
#[inline(never)]
#[no_mangle]
pub fn transfer_token_vulnerable(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let withdrawal_record = next_account_info(it)?;
    let source = next_account_info(it)?;
    let destination = next_account_info(it)?;
    let authority = next_account_info(it)?;
    let token_program = next_account_info(it)?;

    if token_program.key != &SPL_TOKEN_ID
        || source.owner != token_program.key
        || destination.owner != token_program.key
    {
        return Err(ProgramError::IllegalOwner);
    }

    // BUG: the record owner is never checked before its amount is trusted.
    let amount = read_amount(withdrawal_record)?;
    invoke_token_transfer(
        source,
        None,
        destination,
        authority,
        token_program,
        amount,
        0,
    )
}

// SAFE: checks the record owner before the Token-2022 TransferChecked; only the amount is attacker-controlled.
#[inline(never)]
#[no_mangle]
pub fn transfer_token_checked_safe(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let withdrawal_record = next_account_info(it)?;
    let source = next_account_info(it)?;
    let mint = next_account_info(it)?;
    let destination = next_account_info(it)?;
    let authority = next_account_info(it)?;
    let token_program = next_account_info(it)?;

    if withdrawal_record.owner != program_id
        || token_program.key != &TOKEN_2022_ID
        || source.owner != token_program.key
        || mint.owner != token_program.key
        || destination.owner != token_program.key
    {
        return Err(ProgramError::IllegalOwner);
    }

    let amount = read_amount(withdrawal_record)?;
    invoke_token_transfer(
        source,
        Some(mint),
        destination,
        authority,
        token_program,
        amount,
        6,
    )
}

#[inline(never)]
fn invoke_token_transfer<'a>(
    source: &AccountInfo<'a>,
    mint: Option<&AccountInfo<'a>>,
    destination: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    token_program: &AccountInfo<'a>,
    amount: u64,
    decimals: u8,
) -> ProgramResult {
    let (data, metas, infos) = if let Some(mint) = mint {
        let mut data = Vec::with_capacity(10);
        data.push(12); // TokenInstruction::TransferChecked
        data.extend_from_slice(&amount.to_le_bytes());
        data.push(decimals);
        (
            data,
            vec![
                AccountMeta::new(*source.key, false),
                AccountMeta::new_readonly(*mint.key, false),
                AccountMeta::new(*destination.key, false),
                AccountMeta::new_readonly(*authority.key, true),
            ],
            vec![
                source.clone(),
                mint.clone(),
                destination.clone(),
                authority.clone(),
                token_program.clone(),
            ],
        )
    } else {
        let mut data = Vec::with_capacity(9);
        data.push(3); // TokenInstruction::Transfer
        data.extend_from_slice(&amount.to_le_bytes());
        (
            data,
            vec![
                AccountMeta::new(*source.key, false),
                AccountMeta::new(*destination.key, false),
                AccountMeta::new_readonly(*authority.key, true),
            ],
            vec![
                source.clone(),
                destination.clone(),
                authority.clone(),
                token_program.clone(),
            ],
        )
    };

    invoke(
        &Instruction {
            program_id: *token_program.key,
            accounts: metas,
            data,
        },
        &infos,
    )
}
