//// Copied from [Anastasia-Labs/aiken-design-patterns](https://github.com/Anastasia-Labs/aiken-design-patterns/blob/main/lib/aiken-design-patterns/utils.ak)
//// with a few additions that might be useful.

use aiken/collection/list
use aiken/crypto.{Blake2b_224, DataHash, Hash, ScriptHash, VerificationKeyHash}
use aiken/fuzz
use cardano/address.{Address, VerificationKey}
use cardano/assets.{AssetName, PolicyId}
use cardano/transaction.{
  DatumHash, InlineDatum, NoDatum, OutputReference, TransactionId,
}
use cardano/transaction/output_reference

// ## Address Fuzzers

pub type AddressCredentialHash {
  Specified(Hash<Blake2b_224, ByteArray>)
  Fuzzed
}

pub type AddressFrom {
  FromScript(AddressCredentialHash)
  FromKey(AddressCredentialHash)
}

pub type AddressWithDelegation {
  WithNoDelegation
  WithDelegationScript(AddressCredentialHash)
  WithDelegationKey(AddressCredentialHash)
  WithTheSameDelegationScriptOrKey
}

/// Fuzzes an address.
pub fn address_fuzzer(
  from: AddressFrom,
  with_delegation: AddressWithDelegation,
) -> Fuzzer<Address> {
  let p =
    when from is {
      FromScript(hash) ->
        when hash is {
          Specified(script_hash) ->
            address.from_script(script_hash) |> fuzz.constant
          Fuzzed -> {
            let script_hash <- fuzz.map(script_hash_fuzzer())
            address.from_script(script_hash)
          }
        }
      FromKey(hash) ->
        when hash is {
          Specified(verification_key_hash) ->
            address.from_verification_key(verification_key_hash)
              |> fuzz.constant
          Fuzzed -> {
            let verification_key_hash <-
              fuzz.map(verification_key_hash_fuzzer())
            address.from_verification_key(verification_key_hash)
          }
        }
    }
  when with_delegation is {
    WithNoDelegation -> p
    WithDelegationScript(hash) ->
      when hash is {
        Specified(s) -> {
          let p <- fuzz.map(p)
          p |> address.with_delegation_script(s)
        }
        Fuzzed -> {
          let p, s <- fuzz.map2(p, script_hash_fuzzer())
          p |> address.with_delegation_script(s)
        }
      }
    WithDelegationKey(hash) ->
      when hash is {
        Specified(s) -> {
          let p <- fuzz.map(p)
          p |> address.with_delegation_key(s)
        }
        Fuzzed -> {
          let p, s <- fuzz.map2(p, verification_key_hash_fuzzer())
          p |> address.with_delegation_key(s)
        }
      }
    WithTheSameDelegationScriptOrKey -> {
      let p <- fuzz.map(p)
      when p.payment_credential is {
        address.Script(s) -> p |> address.with_delegation_script(s)
        VerificationKey(s) -> p |> address.with_delegation_key(s)
      }
    }
  }
}

/// Fuzzes either `Script(script_hash)` | `VerificationKey(verification_key_hash)`
///
/// Where,
/// - `script_hash` `<-` [`script_hash_fuzzer`](#script_hash_fuzzer)`()`
/// - `verification_key_hash` `<-` [`verification_key_hash_fuzzer`](#verification_key_hash_fuzzer)`()`
pub fn credential_fuzzer() -> Fuzzer<address.Credential> {
  fuzz.either(
    {
      let script_hash <- fuzz.map(script_hash_fuzzer())
      address.Script(script_hash)
    },
    {
      let verification_key_hash <- fuzz.map(verification_key_hash_fuzzer())
      VerificationKey(verification_key_hash)
    },
  )
}

/// Script Hash with 28 bytes fuzzer.
pub fn script_hash_fuzzer() -> Fuzzer<ScriptHash> {
  fuzz.bytearray_fixed(28)
}

/// Verification Key Hash with 28 bytes fuzzer.
pub fn verification_key_hash_fuzzer() -> Fuzzer<VerificationKeyHash> {
  fuzz.bytearray_fixed(28)
}

// ## Asset Fuzzers

/// Policy ID with 28 bytes fuzzer.
pub fn policy_id_fuzzer() -> Fuzzer<PolicyId> {
  fuzz.bytearray_fixed(28)
}

/// Asset Name with 0-32 bytes fuzzer.
pub fn asset_name_fuzzer() -> Fuzzer<AssetName> {
  fuzz.bytearray_between(0, 32)
}

/// A `Value` fuzzer,
/// guaranteed to include some amount of ADA (minimum must be specified)
///
/// Fuzzes a minimum specified ADA and 0-10 tokens:
/// ```aiken
/// assets.from_asset_list([
///   Pair("", [Pair("", lovelace_count)]),
///   ..,
///   Pair(policy_id, [Pair(token_name, quantity), ..])
/// ])
/// ```
/// Where,
/// - `lovelace_count` `<-` [`fuzz.int_at_least`](https://aiken-lang.github.io/fuzz/aiken/fuzz.html#int_at_least)`(min_lovelaces)`
/// - `policy_id` `<-` [`policy_id_fuzzer`](#policy_id_fuzzer)`()`
/// - `token_name` `<-` [`asset_name_fuzzer`](#asset_name_fuzzer)`()`
/// - `quantiy` `<-` [`fuzz.int_at_least`](https://aiken-lang.github.io/fuzz/aiken/fuzz.html#int_at_least)`(1)`
pub fn value_fuzzer(min_lovelaces: assets.Lovelace) -> Fuzzer<assets.Value> {
  let lovelace_count <- fuzz.and_then(fuzz.int_at_least(min_lovelaces))
  let lovelace_value = assets.from_lovelace(lovelace_count)

  let other_assets_values <-
    fuzz.map(fuzz.list_at_most(single_asset_value_fuzzer(), 10))
  other_assets_values |> list.foldl(lovelace_value, assets.merge)
}

/// A `Value` fuzzer with a single asset.
/// Randomly generates the Policy ID.
///
/// Fuzzes the following token:
/// ```aiken
/// policy_id |> assets.from_asset(token_name, quantity)
/// ```
/// Where,
/// - `policy_id` `<-` [`policy_id_fuzzer`](#policy_id_fuzzer)`()`
/// - `token_name` `<-` [`asset_name_fuzzer`](#asset_name_fuzzer)`()`
/// - `quantiy` `<-` [`fuzz.int_at_least`](https://aiken-lang.github.io/fuzz/aiken/fuzz.html#int_at_least)`(1)`
pub fn single_asset_value_fuzzer() -> Fuzzer<assets.Value> {
  let policy_id <- fuzz.and_then(policy_id_fuzzer())
  policy_id |> single_specific_asset_value_fuzzer
}

/// A fuzzer for `Value` with a single asset.
/// Unsafely expects 28 bytes long Policy ID to be provided.
///
/// Fuzzes the following token:
/// ```aiken
/// policy_id |> assets.from_asset(token_name, quantity)
/// ```
/// Where,
/// - `token_name` `<-` [`asset_name_fuzzer`](#asset_name_fuzzer)`()`
/// - `quantiy` `<-` [`fuzz.int_at_least`](https://aiken-lang.github.io/fuzz/aiken/fuzz.html#int_at_least)`(1)`
pub fn single_specific_asset_value_fuzzer(
  policy_id: PolicyId,
) -> Fuzzer<assets.Value> {
  let
    token_name: AssetName,
    quantity: Int,
  <- fuzz.map2(asset_name_fuzzer(), fuzz.int_at_least(1))

  policy_id |> assets.from_asset(token_name, quantity)
}

/// A `Value` fuzzer without any lovelaces.
///
/// Fuzzes 1-10 tokens:
/// ```aiken
/// assets.from_asset_list([
///   Pair(policy_id, [Pair(token_name, quantity), ..])
///   ..,
/// ])
/// ```
/// Where,
/// - `policy_id` `<-` [`policy_id_fuzzer`](#policy_id_fuzzer)`()`
/// - `token_name` `<-` [`asset_name_fuzzer`](#asset_name_fuzzer)`()`
/// - `quantiy` `<-` [`fuzz.int_at_least`](https://aiken-lang.github.io/fuzz/aiken/fuzz.html#int_at_least)`(1)`
pub fn mint_fuzzer() -> Fuzzer<assets.Value> {
  let other_assets_values <-
    fuzz.map(fuzz.list_between(single_asset_value_fuzzer(), 1, 10))
  other_assets_values |> list.foldl(assets.zero, assets.merge)
}

// ## Transaction Fuzzers

/// Fuzzes either `NoDatum` | `DatumHash(data_hash)` | `InlineDatum(data)`
///
/// Where,
/// - `data_hash` `<-` [`data_hash_fuzzer`](#data_hash_fuzzer)`()`
/// - `data` `<-` [`data_fuzzer`](#data_fuzzer)`()`
pub fn datum_fuzzer() -> Fuzzer<transaction.Datum> {
  fuzz.either3(
    NoDatum |> fuzz.constant,
    {
      let data_hash <- fuzz.map(data_hash_fuzzer())
      data_hash |> DatumHash
    },
    {
      let data <- fuzz.map(data_fuzzer())
      data |> InlineDatum
    },
  )
}

/// Data Hash with 32 bytes fuzzer.
pub fn data_hash_fuzzer() -> Fuzzer<DataHash> {
  fuzz.bytearray_fixed(32)
}

/// Fuzzes either upcasted `Bool` | `Byte` | `ByteArray` | `Int`
///
/// Where,
/// |   Data                                                                     |   Possible Value    | Chance |
/// |----------------------------------------------------------------------------|---------------------|--------|
/// | [`Bool`](https://aiken-lang.github.io/fuzz/aiken/fuzz.html#bool)           |  `True` \| `False`  |    25% |
/// | [`Byte`](https://aiken-lang.github.io/fuzz/aiken/fuzz.html#byte)           |      `0`-`255`      |    25% |
/// | [`ByteArray`](https://aiken-lang.github.io/fuzz/aiken/fuzz.html#bytearray) | `"random 32 bytes"` |    25% |
/// | [`Int`](https://aiken-lang.github.io/fuzz/aiken/fuzz.html#int)             |   `-255`-`16383`    |    25% |
pub fn data_fuzzer() -> Fuzzer<Data> {
  fuzz.either4(
    {
      let bool <- fuzz.map(fuzz.bool())
      let data: Data = bool
      data
    },
    {
      let byte <- fuzz.map(fuzz.byte())
      let data: Data = byte
      data
    },
    {
      let bytearray <- fuzz.map(fuzz.bytearray())
      let data: Data = bytearray
      data
    },
    {
      let int <- fuzz.map(fuzz.int())
      let data: Data = int
      data
    },
  )
}

// ### Output Reference Fuzzers

/// Output Reference fuzzer,
/// Transaction ID with 32 bytes,
/// and output index between 0 and 512.
pub fn output_reference_fuzzer() -> Fuzzer<OutputReference> {
  let
    transaction_id: TransactionId,
    output_index: Int,
  <- fuzz.map2(transaction_id_fuzzer(), fuzz.int_between(0, 512))

  OutputReference(transaction_id, output_index)
}

/// Transaction ID with 32 bytes fuzzer.
pub fn transaction_id_fuzzer() -> Fuzzer<TransactionId> {
  fuzz.bytearray_fixed(32)
}

// ### Transaction Output Fuzzers

/// Simple wallet UTxO fuzzer,
/// with a random number of tokens/NFTs.
///
/// Fuzzes the following UTxO:
/// ```aiken
/// transaction.Output {
///   address: Address(Fuzzed |> FromKey, Fuzzed |> WithDelegationKey),
///   value: 2 or more ADA and 0-10 tokens/NFTs,
///   datum: NoDatum,
///   reference_script: None,
/// }
/// ```
pub fn user_output_fuzzer() -> Fuzzer<transaction.Output> {
  let
    address: Address,
    value: assets.Value,
  <-
    fuzz.map2(
      address_fuzzer(Fuzzed |> FromKey, Fuzzed |> WithDelegationKey),
      value_fuzzer(2_000_000),
    )

  transaction.Output { address, value, datum: NoDatum, reference_script: None }
}

/// Simple (non-script) outputs fuzzer.
///
/// Fuzzes a list between 1-10 elements of the following UTxO:
/// ```aiken
/// transaction.Output {
///   address: Address(FromKey, WithDelegationKey),
///   value: 2 or more ADA and 0-10 tokens/NFTs,
///   datum: NoDatum,
///   reference_script: None,
/// }
/// ```
pub fn user_outputs_fuzzer() -> Fuzzer<List<transaction.Output>> {
  user_output_fuzzer() |> fuzz.list_between(1, 10)
}

/// Given a script hash and datum,
/// this fuzzer generates a UTxO at an address which its payment part is the same as the given script hash.
///
/// Fuzzes the following UTxO:
/// ```aiken
/// transaction.Output {
///   address: from_script(script_hash),
///   value: 2 or more ADA and 0-10 tokens/NFTs,
///   datum: transaction.Datum,
///   reference_script: None,
/// }
/// ```
pub fn specific_script_output_fuzzer(
  script_hash: ScriptHash,
  datum: transaction.Datum,
) -> Fuzzer<transaction.Output> {
  let value <- fuzz.map(value_fuzzer(2_000_000))
  transaction.Output {
    address: address.from_script(script_hash),
    value,
    datum,
    reference_script: None,
  }
}

/// Returns a tuple where its first element is the random script hash (payment part of the UTxO's address).
/// UTxO value is also random, with 2 ADA.
///
/// Fuzzes the following tuple:
/// ```aiken
/// (script_hash, utxo)
/// ```
/// Where,
/// - `script_hash` `<-` [`script_hash_fuzzer`](#script_hash_fuzzer)`()`
/// - `utxo` `<-` [`specific_script_output_fuzzer`](#specific_script_output_fuzzer)`(script_hash, datum)`
///   ```aiken
///   transaction.Output {
///     address: from_script(script_hash),
///     value: 2 or more ADA and 0-10 tokens/NFTs,
///     datum: transaction.Datum,
///     reference_script: None,
///   }
///   ```
pub fn script_output_fuzzer(
  datum: transaction.Datum,
) -> Fuzzer<(ScriptHash, transaction.Output)> {
  let script_hash <- fuzz.and_then(script_hash_fuzzer())
  let utxo <- fuzz.map(specific_script_output_fuzzer(script_hash, datum))
  (script_hash, utxo)
}

/// UTxO fuzzer, where the value is composed of 2 ADA and a Beacon NFT,
/// such that its Policy ID is equal to the script credential of the payment part of UTxO's address.
/// This script hash is also returned.
///
/// Fuzzes the following tuple:
/// ```aiken
/// (script_hash, utxo)
/// ```
/// Where,
/// - `policy_id: script_hash` `<-` [`script_hash_fuzzer`](#script_hash_fuzzer)`()`
/// - `asset_name` `<-` [`asset_name_fuzzer`](#asset_name_fuzzer)`()`
/// - `utxo` `=`
///   ```aiken
///   transaction.Output {
///     address: address.from_script(script_hash),
///     value: 2 ADA and a Beacon NFT (policy_id: script_hash, asset_name, quantity: 1),
///     datum,
///     reference_script: None,
///   }
///   ```
pub fn authentic_script_output_fuzzer(
  datum: transaction.Datum,
) -> Fuzzer<(ScriptHash, transaction.Output)> {
  let lovelace_value = assets.from_lovelace(2_000_000)

  let
    script_hash: ScriptHash,
    token_name: AssetName,
  <- fuzz.map2(script_hash_fuzzer(), asset_name_fuzzer())

  let beacon = assets.from_asset(script_hash, token_name, 1)
  let utxo =
    transaction.Output {
      address: address.from_script(script_hash),
      value: assets.merge(lovelace_value, beacon),
      datum,
      reference_script: None,
    }

  (script_hash, utxo)
}

// ### Transaction Input Fuzzers

/// Simple wallet UTxO fuzzer,
/// with a random reference output and a random number of tokens/NFTs.
///
/// Fuzzes the following Transaction Input:
/// ```aiken
/// transaction.Input(output_reference, output)
/// ```
/// Where,
/// - `output_reference` `<-` [`output_reference_fuzzer`](#output_reference_fuzzer)`()`
/// - `output` `<-` [`user_output_fuzzer`](#user_output_fuzzer)`()`
///   ```aiken
///   transaction.Output {
///     address: Address(FromKey, WithDelegationKey),
///     value: 2 or more ADA and 0-10 tokens/NFTs,
///     datum: NoDatum,
///     reference_script: None,
///   }
///   ```
pub fn user_input_fuzzer() -> Fuzzer<transaction.Input> {
  let
    output_reference: OutputReference,
    output: transaction.Output,
  <- fuzz.map2(output_reference_fuzzer(), user_output_fuzzer())

  transaction.Input(output_reference, output)
}

/// Simple (non-script) inputs fuzzer.
///
/// Fuzzes a list between 1-10 elements of the following Transaction Input:
/// ```aiken
/// transaction.Input(output_reference, output)
/// ```
/// Where,
/// - `output_reference` `<-` [`output_reference_fuzzer`](#output_reference_fuzzer)`()`
/// - `output` `<-` [`user_output_fuzzer`](#user_output_fuzzer)`()`
///   ```aiken
///   transaction.Output {
///     address: Address(FromKey, WithDelegationKey),
///     value: 2 or more ADA and 0-10 tokens/NFTs,
///     datum: NoDatum,
///     reference_script: None,
///   }
///   ```
pub fn user_inputs_fuzzer() -> Fuzzer<List<transaction.Input>> {
  user_input_fuzzer() |> fuzz.list_between(1, 10)
}

/// Similar to [`specific_script_output_fuzzer`](#specific_script_output_fuzzer),
/// with an additional randomized wrapper for output reference.
///
/// Fuzzes the following Transaction Input:
/// ```aiken
/// transaction.Input(output_reference, output)
/// ```
/// Where,
/// - `output_reference` `<-` [`output_reference_fuzzer`](#output_reference_fuzzer)`()`
/// - `output` `=`
///   ```aiken
///   transaction.Output {
///     address: from_script(script_hash),
///     value: 2 or more ADA and 0-10 tokens/NFTs,
///     datum: transaction.Datum,
///     reference_script: None,
///   }
///   ```
pub fn specific_script_input_fuzzer(
  script_hash: ScriptHash,
  datum: transaction.Datum,
) -> Fuzzer<transaction.Input> {
  let
    output_reference: OutputReference,
    output: transaction.Output,
  <-
    fuzz.map2(
      output_reference_fuzzer(),
      specific_script_output_fuzzer(script_hash, datum),
    )

  transaction.Input(output_reference, output)
}

/// Similar to [`script_output_fuzzer`](#script_output_fuzzer),
/// with an additional randomized wrapper for output reference.
///
/// Fuzzes the following tuple:
/// ```aiken
/// (script_hash, script_input)
/// ```
/// Where,
/// - `script_hash` `<-` [`script_hash_fuzzer`](#script_hash_fuzzer)`()`
/// - `output_reference` `<-` [`output_reference_fuzzer`](#output_reference_fuzzer)`()`
/// - `output` `<-` [`specific_script_output_fuzzer`](#specific_script_output_fuzzer)`(script_hash, datum)`
///   ```aiken
///   transaction.Output {
///     address: from_script(script_hash),
///     value: 2 or more ADA and 0-10 tokens/NFTs,
///     datum: transaction.Datum,
///     reference_script: None,
///   }
///   ```
/// - `script_input` `=`
///   ```aiken
///   transaction.Input(output_reference, output)
///   ```
pub fn script_input_fuzzer(
  datum: transaction.Datum,
) -> Fuzzer<(ScriptHash, transaction.Input)> {
  let
    output_reference: OutputReference,
    (script_hash, output),
  <- fuzz.map2(output_reference_fuzzer(), script_output_fuzzer(datum))

  let script_input = transaction.Input(output_reference, output)

  (script_hash, script_input)
}

/// Similar to [`authentic_script_output_fuzzer`](#script_output_fuzzer),
/// with and additional randomized wrapper for output reference.
///
/// Fuzzes the following tuple:
/// ```aiken
/// (script_hash, script_input)
/// ```
/// Where,
/// - `policy_id: script_hash` `<-` [`script_hash_fuzzer`](#script_hash_fuzzer)`()`
/// - `asset_name` `<-` [`asset_name_fuzzer`](#asset_name_fuzzer)`()`
/// - `output_reference` `<-` [`output_reference_fuzzer`](#output_reference_fuzzer)`()`
/// - `output` `=`
///   ```aiken
///   transaction.Output {
///     address: address.from_script(script_hash),
///     value: 2 ADA and a Beacon NFT (policy_id: script_hash, asset_name, quantity: 1),
///     datum,
///     reference_script: None,
///   }
///   ```
/// - `script_input` `=`
///   ```aiken
///   transaction.Input(output_reference, output)
///   ```
pub fn authentic_script_input_fuzzer(
  datum: transaction.Datum,
) -> Fuzzer<(ScriptHash, transaction.Input)> {
  let
    output_reference: OutputReference,
    (script_hash, output),
  <- fuzz.map2(output_reference_fuzzer(), authentic_script_output_fuzzer(datum))

  let script_input = transaction.Input(output_reference, output)

  (script_hash, script_input)
}

/// Fuzzer for a sorted list of user/wallet inputs,
/// with the addition of one authentic script input.
///
/// Fuzzes the following tuple:
/// ```aiken
/// (script_hash, script_input, sorted_inputs)
/// ```
/// Where,
/// - `policy_id: script_hash` `<-` [`script_hash_fuzzer`](#script_hash_fuzzer)`()`
/// - `asset_name` `<-` [`asset_name_fuzzer`](#asset_name_fuzzer)`()`
/// - `output_reference` `<-` [`output_reference_fuzzer`](#output_reference_fuzzer)`()`
/// - `output` `=`
///   ```aiken
///   transaction.Output {
///     address: address.from_script(script_hash),
///     value: 2 ADA and a Beacon NFT (policy_id: script_hash, asset_name, quantity: 1),
///     datum,
///     reference_script: None,
///   }
///   ```
/// - `script_input` `=`
///   ```aiken
///   transaction.Input(output_reference, output)
///   ```
/// - `wallet_inputs` `<-` a list between 1-10 elements of `transaction.Input(output_reference, output)` where,
///     - `output_reference` `<-` [`output_reference_fuzzer`](#output_reference_fuzzer)`()`
///     - `output` `<-` [`user_output_fuzzer`](#user_output_fuzzer)`()`
///       ```aiken
///       transaction.Output {
///         address: Address(FromKey, WithDelegationKey),
///         value: 2 or more ADA and 0-10 tokens/NFTs,
///         datum: NoDatum,
///         reference_script: None,
///       }
///       ```
/// - `sorted_inputs` `=` `sorted_by_output_reference([script_input, ..wallet_inputs])`
pub fn inputs_with_an_authentic_script_input_fuzzer(
  datum: transaction.Datum,
) -> Fuzzer<(ScriptHash, transaction.Input, List<transaction.Input>)> {
  let sort_inputs =
    fn(transaction_inputs) {
      let
        transaction.Input(l_o_ref, _),
        transaction.Input(r_o_ref, _),
      <- list.sort(transaction_inputs)

      l_o_ref |> output_reference.compare(r_o_ref)
    }

  let
    wallet_inputs: List<transaction.Input>,
    (script_hash, script_input),
  <- fuzz.map2(user_inputs_fuzzer(), authentic_script_input_fuzzer(datum))

  let sorted_inputs = [script_input, ..wallet_inputs] |> sort_inputs

  (script_hash, script_input, sorted_inputs)
}
