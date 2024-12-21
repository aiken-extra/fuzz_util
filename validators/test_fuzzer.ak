//// @hidden

use aiken/builtin
use aiken/cbor
use aiken/collection/list
use aiken/crypto.{ScriptHash, VerificationKeyHash}
use aiken/fuzz
use cardano/address.{Address, VerificationKey}
use cardano/assets
use cardano/transaction
use fuzz_util/fuzzer.{
  FromKey, FromScript, Fuzzed, Specified, WithDelegationKey,
  WithDelegationScript, WithNoDelegation, WithTheSameDelegationScriptOrKey,
  address_fuzzer, datum_fuzzer, inputs_with_an_authentic_script_input_fuzzer,
  mint_fuzzer, script_hash_fuzzer, script_input_fuzzer,
  specific_script_input_fuzzer, user_outputs_fuzzer,
  verification_key_hash_fuzzer,
}

// ## Address Fuzzers

// ### Specified Script Address Fuzzers

fn test_specified_script_address_with_no_delegation_fuzzer() -> Fuzzer<
  (ScriptHash, Address),
> {
  let script_hash <- fuzz.and_then(script_hash_fuzzer())
  let address <-
    fuzz.map(
      address_fuzzer(FromScript(Specified(script_hash)), WithNoDelegation),
    )
  (script_hash, address)
}

test testing_specified_script_address_with_no_delegation_fuzzer(
  (script_hash, address) via test_specified_script_address_with_no_delegation_fuzzer(),
) {
  address == address.from_script(script_hash)
}

fn test_specified_script_address_with_specified_delegation_script_fuzzer() -> Fuzzer<
  (ScriptHash, ScriptHash, Address),
> {
  let payment_script_hash <- fuzz.and_then(script_hash_fuzzer())
  let stake_script_hash <- fuzz.and_then(script_hash_fuzzer())
  let address <-
    fuzz.map(
      address_fuzzer(
        FromScript(Specified(payment_script_hash)),
        WithDelegationScript(Specified(stake_script_hash)),
      ),
    )
  (payment_script_hash, stake_script_hash, address)
}

test testing_specified_script_address_with_specified_delegation_script_fuzzer(
  (payment_script_hash, stake_script_hash, address) via test_specified_script_address_with_specified_delegation_script_fuzzer(),
) {
  address == (
    address.from_script(payment_script_hash)
      |> address.with_delegation_script(stake_script_hash)
  )
}

fn test_specified_script_address_with_fuzzed_delegation_script_fuzzer() -> Fuzzer<
  (ScriptHash, Address),
> {
  let payment_script_hash <- fuzz.and_then(script_hash_fuzzer())
  let address <-
    fuzz.map(
      address_fuzzer(
        FromScript(Specified(payment_script_hash)),
        WithDelegationScript(Fuzzed),
      ),
    )
  (payment_script_hash, address)
}

test testing_specified_script_address_with_fuzzed_delegation_script_fuzzer(
  (payment_script_hash, address) via test_specified_script_address_with_fuzzed_delegation_script_fuzzer(),
) {
  //   address.stake_credential |> cbor.diagnostic |> fuzz.label
  address.payment_credential == address.Script(payment_script_hash)
}

fn test_specified_script_address_with_specified_delegation_key_fuzzer() -> Fuzzer<
  (ScriptHash, VerificationKeyHash, Address),
> {
  let payment_script_hash <- fuzz.and_then(script_hash_fuzzer())
  let stake_key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
  let address <-
    fuzz.map(
      address_fuzzer(
        FromScript(Specified(payment_script_hash)),
        WithDelegationKey(Specified(stake_key_hash)),
      ),
    )
  (payment_script_hash, stake_key_hash, address)
}

test testing_specified_script_address_with_specified_delegation_key_fuzzer(
  (payment_script_hash, stake_key_hash, address) via test_specified_script_address_with_specified_delegation_key_fuzzer(),
) {
  address == (
    address.from_script(payment_script_hash)
      |> address.with_delegation_key(stake_key_hash)
  )
}

fn test_specified_script_address_with_fuzzed_delegation_key_fuzzer() -> Fuzzer<
  (ScriptHash, Address),
> {
  let payment_script_hash <- fuzz.and_then(script_hash_fuzzer())
  let address <-
    fuzz.map(
      address_fuzzer(
        FromScript(Specified(payment_script_hash)),
        WithDelegationKey(Fuzzed),
      ),
    )
  (payment_script_hash, address)
}

test testing_specified_script_address_with_fuzzed_delegation_key_fuzzer(
  (payment_script_hash, address) via test_specified_script_address_with_fuzzed_delegation_key_fuzzer(),
) {
  //   address.stake_credential |> cbor.diagnostic |> fuzz.label
  address.payment_credential == address.Script(payment_script_hash)
}

fn test_specified_script_address_with_the_same_delegation_script_fuzzer() -> Fuzzer<
  (ScriptHash, Address),
> {
  let payment_script_hash <- fuzz.and_then(script_hash_fuzzer())
  let address <-
    fuzz.map(
      address_fuzzer(
        FromScript(Specified(payment_script_hash)),
        WithTheSameDelegationScriptOrKey,
      ),
    )
  (payment_script_hash, address)
}

test testing_specified_script_address_with_the_same_delegation_script_fuzzer(
  (script_hash, address) via test_specified_script_address_with_the_same_delegation_script_fuzzer(),
) {
  address == (
    address.from_script(script_hash)
      |> address.with_delegation_script(script_hash)
  )
}

// ### Specified Key Address Fuzzers

fn test_specified_key_address_with_no_delegation_fuzzer() -> Fuzzer<
  (VerificationKeyHash, Address),
> {
  let key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
  let address <-
    fuzz.map(address_fuzzer(FromKey(Specified(key_hash)), WithNoDelegation))
  (key_hash, address)
}

test testing_specified_key_address_with_no_delegation_fuzzer(
  (key_hash, address) via test_specified_key_address_with_no_delegation_fuzzer(),
) {
  address == address.from_verification_key(key_hash)
}

fn test_specified_key_address_with_specified_delegation_script_fuzzer() -> Fuzzer<
  (VerificationKeyHash, ScriptHash, Address),
> {
  let payment_key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
  let stake_script_hash <- fuzz.and_then(script_hash_fuzzer())
  let address <-
    fuzz.map(
      address_fuzzer(
        FromKey(Specified(payment_key_hash)),
        WithDelegationScript(Specified(stake_script_hash)),
      ),
    )
  (payment_key_hash, stake_script_hash, address)
}

test testing_specified_key_address_with_specified_delegation_script_fuzzer(
  (payment_key_hash, stake_script_hash, address) via test_specified_key_address_with_specified_delegation_script_fuzzer(),
) {
  address == (
    address.from_verification_key(payment_key_hash)
      |> address.with_delegation_script(stake_script_hash)
  )
}

fn test_specified_key_address_with_fuzzed_delegation_script_fuzzer() -> Fuzzer<
  (VerificationKeyHash, Address),
> {
  let payment_key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
  let address <-
    fuzz.map(
      address_fuzzer(
        FromKey(Specified(payment_key_hash)),
        WithDelegationScript(Fuzzed),
      ),
    )
  (payment_key_hash, address)
}

test testing_specified_key_address_with_fuzzed_delegation_script_fuzzer(
  (payment_key_hash, address) via test_specified_key_address_with_fuzzed_delegation_script_fuzzer(),
) {
  //   address.stake_credential |> cbor.diagnostic |> fuzz.label
  address.payment_credential == VerificationKey(payment_key_hash)
}

fn test_specified_key_address_with_specified_delegation_key_fuzzer() -> Fuzzer<
  (VerificationKeyHash, VerificationKeyHash, Address),
> {
  let payment_key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
  let stake_key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
  let address <-
    fuzz.map(
      address_fuzzer(
        FromKey(Specified(payment_key_hash)),
        WithDelegationKey(Specified(stake_key_hash)),
      ),
    )
  (payment_key_hash, stake_key_hash, address)
}

test testing_specified_key_address_with_specified_delegation_key_fuzzer(
  (payment_key_hash, stake_key_hash, address) via test_specified_key_address_with_specified_delegation_key_fuzzer(),
) {
  address == (
    address.from_verification_key(payment_key_hash)
      |> address.with_delegation_key(stake_key_hash)
  )
}

fn test_specified_key_address_with_fuzzed_delegation_key_fuzzer() -> Fuzzer<
  (VerificationKeyHash, Address),
> {
  let payment_key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
  let address <-
    fuzz.map(
      address_fuzzer(
        FromKey(Specified(payment_key_hash)),
        WithDelegationKey(Fuzzed),
      ),
    )
  (payment_key_hash, address)
}

test testing_specified_key_address_with_fuzzed_delegation_key_fuzzer(
  (payment_key_hash, address) via test_specified_key_address_with_fuzzed_delegation_key_fuzzer(),
) {
  //   address.stake_credential |> cbor.diagnostic |> fuzz.label
  address.payment_credential == VerificationKey(payment_key_hash)
}

fn test_specified_key_address_with_the_same_delegation_key_fuzzer() -> Fuzzer<
  (VerificationKeyHash, Address),
> {
  let payment_key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
  let address <-
    fuzz.map(
      address_fuzzer(
        FromKey(Specified(payment_key_hash)),
        WithTheSameDelegationScriptOrKey,
      ),
    )
  (payment_key_hash, address)
}

test testing_specified_key_address_with_the_same_delegation_key_fuzzer(
  (key_hash, address) via test_specified_key_address_with_the_same_delegation_key_fuzzer(),
) {
  address == (
    address.from_verification_key(key_hash)
      |> address.with_delegation_key(key_hash)
  )
}

// ### Fuzzed Script Address Fuzzers

test testing_fuzzed_script_address_with_no_delegation_fuzzer(
  Address(payment_credential, stake_credential) via address_fuzzer(
    FromScript(Fuzzed),
    WithNoDelegation,
  ),
) {
  expect address.Script(payment_script_hash) = payment_credential
  payment_script_hash |> builtin.decode_utf8 |> fuzz.label
  stake_credential == None
}

// fn test_specified_script_address_with_specified_delegation_script_fuzzer() -> Fuzzer<
//   (ScriptHash, ScriptHash, Address),
// > {
//   let payment_script_hash <- fuzz.and_then(script_hash_fuzzer())
//   let stake_script_hash <- fuzz.and_then(script_hash_fuzzer())
//   let address <-
//     fuzz.map(
//       address_fuzzer(
//         FromScript(Specified(payment_script_hash)),
//         WithDelegationScript(Specified(stake_script_hash)),
//       ),
//     )
//   (payment_script_hash, stake_script_hash, address)
// }

// test testing_specified_script_address_with_specified_delegation_script_fuzzer(
//   (payment_script_hash, stake_script_hash, address) via test_specified_script_address_with_specified_delegation_script_fuzzer(),
// ) {
//   address == (
//     address.from_script(payment_script_hash)
//       |> address.with_delegation_script(stake_script_hash)
//   )
// }

// fn test_specified_script_address_with_fuzzed_delegation_script_fuzzer() -> Fuzzer<
//   (ScriptHash, Address),
// > {
//   let payment_script_hash <- fuzz.and_then(script_hash_fuzzer())
//   let address <-
//     fuzz.map(
//       address_fuzzer(
//         FromScript(Specified(payment_script_hash)),
//         WithDelegationScript(Fuzzed),
//       ),
//     )
//   (payment_script_hash, address)
// }

// test testing_specified_script_address_with_fuzzed_delegation_script_fuzzer(
//   (payment_script_hash, address) via test_specified_script_address_with_fuzzed_delegation_script_fuzzer(),
// ) {
//   //   address.stake_credential |> cbor.diagnostic |> fuzz.label
//   address.payment_credential == address.Script(payment_script_hash)
// }

// fn test_specified_script_address_with_specified_delegation_key_fuzzer() -> Fuzzer<
//   (ScriptHash, VerificationKeyHash, Address),
// > {
//   let payment_script_hash <- fuzz.and_then(script_hash_fuzzer())
//   let stake_key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
//   let address <-
//     fuzz.map(
//       address_fuzzer(
//         FromScript(Specified(payment_script_hash)),
//         WithDelegationKey(Specified(stake_key_hash)),
//       ),
//     )
//   (payment_script_hash, stake_key_hash, address)
// }

// test testing_specified_script_address_with_specified_delegation_key_fuzzer(
//   (payment_script_hash, stake_key_hash, address) via test_specified_script_address_with_specified_delegation_key_fuzzer(),
// ) {
//   address == (
//     address.from_script(payment_script_hash)
//       |> address.with_delegation_key(stake_key_hash)
//   )
// }

// fn test_specified_script_address_with_fuzzed_delegation_key_fuzzer() -> Fuzzer<
//   (ScriptHash, Address),
// > {
//   let payment_script_hash <- fuzz.and_then(script_hash_fuzzer())
//   let address <-
//     fuzz.map(
//       address_fuzzer(
//         FromScript(Specified(payment_script_hash)),
//         WithDelegationKey(Fuzzed),
//       ),
//     )
//   (payment_script_hash, address)
// }

// test testing_specified_script_address_with_fuzzed_delegation_key_fuzzer(
//   (payment_script_hash, address) via test_specified_script_address_with_fuzzed_delegation_key_fuzzer(),
// ) {
//   //   address.stake_credential |> cbor.diagnostic |> fuzz.label
//   address.payment_credential == address.Script(payment_script_hash)
// }

// fn test_specified_script_address_with_the_same_delegation_script_fuzzer() -> Fuzzer<
//   (ScriptHash, Address),
// > {
//   let payment_script_hash <- fuzz.and_then(script_hash_fuzzer())
//   let address <-
//     fuzz.map(
//       address_fuzzer(
//         FromScript(Specified(payment_script_hash)),
//         WithTheSameDelegationScriptOrKey,
//       ),
//     )
//   (payment_script_hash, address)
// }

// test testing_specified_script_address_with_the_same_delegation_script_fuzzer(
//   (script_hash, address) via test_specified_script_address_with_the_same_delegation_script_fuzzer(),
// ) {
//   address == (
//     address.from_script(script_hash)
//       |> address.with_delegation_script(script_hash)
//   )
// }

// // ### Specified Key Address Fuzzers

// fn test_specified_key_address_with_no_delegation_fuzzer() -> Fuzzer<
//   (VerificationKeyHash, Address),
// > {
//   let key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
//   let address <-
//     fuzz.map(address_fuzzer(FromKey(Specified(key_hash)), WithNoDelegation))
//   (key_hash, address)
// }

// test testing_specified_key_address_with_no_delegation_fuzzer(
//   (key_hash, address) via test_specified_key_address_with_no_delegation_fuzzer(),
// ) {
//   address == address.from_verification_key(key_hash)
// }

// fn test_specified_key_address_with_specified_delegation_script_fuzzer() -> Fuzzer<
//   (VerificationKeyHash, ScriptHash, Address),
// > {
//   let payment_key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
//   let stake_script_hash <- fuzz.and_then(script_hash_fuzzer())
//   let address <-
//     fuzz.map(
//       address_fuzzer(
//         FromKey(Specified(payment_key_hash)),
//         WithDelegationScript(Specified(stake_script_hash)),
//       ),
//     )
//   (payment_key_hash, stake_script_hash, address)
// }

// test testing_specified_key_address_with_specified_delegation_script_fuzzer(
//   (payment_key_hash, stake_script_hash, address) via test_specified_key_address_with_specified_delegation_script_fuzzer(),
// ) {
//   address == (
//     address.from_verification_key(payment_key_hash)
//       |> address.with_delegation_script(stake_script_hash)
//   )
// }

// fn test_specified_key_address_with_fuzzed_delegation_script_fuzzer() -> Fuzzer<
//   (VerificationKeyHash, Address),
// > {
//   let payment_key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
//   let address <-
//     fuzz.map(
//       address_fuzzer(
//         FromKey(Specified(payment_key_hash)),
//         WithDelegationScript(Fuzzed),
//       ),
//     )
//   (payment_key_hash, address)
// }

// test testing_specified_key_address_with_fuzzed_delegation_script_fuzzer(
//   (payment_key_hash, address) via test_specified_key_address_with_fuzzed_delegation_script_fuzzer(),
// ) {
//   //   address.stake_credential |> cbor.diagnostic |> fuzz.label
//   address.payment_credential == VerificationKey(payment_key_hash)
// }

// fn test_specified_key_address_with_specified_delegation_key_fuzzer() -> Fuzzer<
//   (VerificationKeyHash, VerificationKeyHash, Address),
// > {
//   let payment_key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
//   let stake_key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
//   let address <-
//     fuzz.map(
//       address_fuzzer(
//         FromKey(Specified(payment_key_hash)),
//         WithDelegationKey(Specified(stake_key_hash)),
//       ),
//     )
//   (payment_key_hash, stake_key_hash, address)
// }

// test testing_specified_key_address_with_specified_delegation_key_fuzzer(
//   (payment_key_hash, stake_key_hash, address) via test_specified_key_address_with_specified_delegation_key_fuzzer(),
// ) {
//   address == (
//     address.from_verification_key(payment_key_hash)
//       |> address.with_delegation_key(stake_key_hash)
//   )
// }

// fn test_specified_key_address_with_fuzzed_delegation_key_fuzzer() -> Fuzzer<
//   (VerificationKeyHash, Address),
// > {
//   let payment_key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
//   let address <-
//     fuzz.map(
//       address_fuzzer(
//         FromKey(Specified(payment_key_hash)),
//         WithDelegationKey(Fuzzed),
//       ),
//     )
//   (payment_key_hash, address)
// }

// test testing_specified_key_address_with_fuzzed_delegation_key_fuzzer(
//   (payment_key_hash, address) via test_specified_key_address_with_fuzzed_delegation_key_fuzzer(),
// ) {
//   //   address.stake_credential |> cbor.diagnostic |> fuzz.label
//   address.payment_credential == VerificationKey(payment_key_hash)
// }

// fn test_specified_key_address_with_the_same_delegation_key_fuzzer() -> Fuzzer<
//   (VerificationKeyHash, Address),
// > {
//   let payment_key_hash <- fuzz.and_then(verification_key_hash_fuzzer())
//   let address <-
//     fuzz.map(
//       address_fuzzer(
//         FromKey(Specified(payment_key_hash)),
//         WithTheSameDelegationScriptOrKey,
//       ),
//     )
//   (payment_key_hash, address)
// }

// test testing_specified_key_address_with_the_same_delegation_key_fuzzer(
//   (key_hash, address) via test_specified_key_address_with_the_same_delegation_key_fuzzer(),
// ) {
//   address == (
//     address.from_verification_key(key_hash)
//       |> address.with_delegation_key(key_hash)
//   )
// }

// //////////////////////////////////////////////////////////////////////////////////////////////// //

pub fn trace_mint(mint: assets.Value) -> Void {
  let (policy_id, asset_name, quantity) <- list.for_each(mint |> assets.flatten)
  (policy_id, asset_name, quantity) |> cbor.diagnostic |> fuzz.label
}

test testing_mint_fuzzer(mint via mint_fuzzer()) {
  //   mint |> trace_mint
  mint |> assets.negate |> assets.merge(mint) |> assets.is_zero
}

test testing_inputs_with_an_authentic_script_input_fuzzer(
  (_spend_script_hash, _script_input, _sorted_inputs) via fuzz.and_then(
    datum_fuzzer(),
    inputs_with_an_authentic_script_input_fuzzer,
  ),
) {
  //   (spend_script_hash, script_input, sorted_inputs)
  //     |> cbor.diagnostic
  //     |> fuzz.label
  True
}

test testing_user_outputs_fuzzer(_user_outputs via user_outputs_fuzzer()) {
  //   user_outputs |> cbor.diagnostic |> fuzz.label
  True
}

test testing_script_input_fuzzer(
  (_script_hash, _transaction_input) via fuzz.and_then(
    datum_fuzzer(),
    script_input_fuzzer,
  ),
) {
  //   (script_hash, transaction_input) |> cbor.diagnostic |> fuzz.label
  True
}

fn test_specific_script_input_fuzzer() -> Fuzzer<transaction.Input> {
  let script_hash <- fuzz.and_then(script_hash_fuzzer())
  let datum <- fuzz.and_then(datum_fuzzer())
  specific_script_input_fuzzer(script_hash, datum)
}

test testing_specific_script_input_fuzzer(
  _specific_script_input via test_specific_script_input_fuzzer(),
) {
  //   specific_script_input |> cbor.diagnostic |> fuzz.label
  True
}
