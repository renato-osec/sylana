"""Fetch a transaction and its accounts' state AT TRANSACTION TIME, then simulate.

Account state is read with Alchemy's Solana Account Archive: getAccountInfo with
`lastUpdateBeforeSlot = <tx slot>` returns each account as it was just before the
transaction ran, which is what a faithful replay needs. That is a paid Alchemy
feature; on a plain RPC you would fall back to current state plus the
transaction's meta.preBalances.

Uses only solders + raw JSON-RPC (no solana-py needed).

Prerequisites:
  solana program dump <PROGRAM_ID> program.so
  nix-shell && ./build.sh
  export ALCHEMY_RPC=https://solana-mainnet.g.alchemy.com/v2/<KEY>

Usage:
  python fetch_and_simulate.py <TX_SIGNATURE> <PROGRAM_ID> program.so
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.request

from solders.account import Account
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction

import sylana
from sylana import sym

RPC_URL = os.environ.get("ALCHEMY_RPC", "https://api.mainnet-beta.solana.com")


def rpc(method: str, params: list) -> dict:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC_URL, data=body, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)["result"]


def account_at_slot(pubkey: Pubkey, slot: int) -> Account | None:
    """getAccountInfo for `pubkey` as of just before `slot` (Account Archive)."""
    result = rpc("getAccountInfo",
                 [str(pubkey), {"encoding": "base64", "lastUpdateBeforeSlot": slot}])
    value = result["value"]
    if value is None:
        return None
    data = base64.b64decode(value["data"][0]) if value.get("data") else b""
    return Account(
        lamports=int(value["lamports"]),
        data=data,
        owner=Pubkey.from_string(value["owner"]),
        executable=bool(value["executable"]),
        rent_epoch=int(value["rentEpoch"]),
    )


def main(signature: str, program_id_str: str, elf_path: str) -> None:
    program_id = Pubkey.from_string(program_id_str)

    # 1. fetch the transaction; decode it and note the slot it landed in
    result = rpc("getTransaction",
                 [signature, {"encoding": "base64", "maxSupportedTransactionVersion": 0}])
    slot = int(result["slot"])
    tx = VersionedTransaction.from_bytes(base64.b64decode(result["transaction"][0]))
    message = tx.message

    # 2. find the instruction that targets our program
    target_ix = next(
        i for i, ix in enumerate(message.instructions)
        if message.account_keys[ix.program_id_index] == program_id
    )

    # 3. account state as of just before this transaction ran, for the accounts
    # the target instruction touches. Program ids (System, Token, ...) are not
    # archived state: they only need to look executable for Anchor's checks.
    program_ids = {message.account_keys[ix.program_id_index] for ix in message.instructions}
    accounts = {}
    for index in message.instructions[target_ix].accounts:
        key = message.account_keys[index]
        if key in accounts:
            continue
        if key in program_ids:
            accounts[key] = Account(lamports=1, data=b"", owner=Pubkey.default(),
                                    executable=True, rent_epoch=0)
            continue
        state = account_at_slot(key, slot)
        if state is not None:
            accounts[key] = state

    # sysvars the program may read (Rent::get / Clock::get) as of the same slot
    sysvars = {}
    for name, sysvar in (("rent", "SysvarRent111111111111111111111111111111111"),
                         ("clock", "SysvarC1ock11111111111111111111111111111111")):
        state = account_at_slot(Pubkey.from_string(sysvar), slot)
        if state is not None:
            sysvars[name] = state

    # 4. make the instruction arguments symbolic; keep the fetched state
    # concrete. The first 8 bytes (Anchor discriminator) stay fixed: freeing
    # them turns every argument length into a symbolic allocation.
    data_len = len(message.instructions[target_ix].data)
    args = sym.instruction_data(target_ix, (min(8, data_len), data_len))
    sm = sylana.to_symbolic(message, symbolic=[args], accounts=accounts, sysvars=sysvars)

    # 5. simulate the whole transaction against the program
    elf = sylana.SymbolicElf.load(elf_path, program_id=bytes(program_id))
    result = elf.simulate_full_tx(sm)

    print(f"tx slot {slot}: {len(result.paths)} feasible path(s), {len(result.dropped)} dropped")
    for name in result.dropped:
        print(f"  dropped: {name}")
    for n, path in enumerate(result.paths):
        chosen = path.witness.get(args.name)
        data_hex = chosen.concrete.hex() if chosen and chosen.concrete else "-"
        status = "ok" if path.succeeded else f"err 0x{path.return_value:x}"
        print(f"  path {n}: {status}  ix_data={data_hex}")
        for line in path.log.strip().splitlines()[-4:]:
            print(f"      log: {line}")
        for account in path.accounts_after:
            print(f"    {Pubkey(bytes(account.key))} lamports={account.lamports}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2], sys.argv[3])
