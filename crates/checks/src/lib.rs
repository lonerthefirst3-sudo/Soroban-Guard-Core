//! Vulnerability detectors for Soroban smart contracts.

pub mod address_cmp_instead_of_auth;
pub mod address_from_str;
pub mod admin;
pub mod admin_eq_instead_of_auth;
pub mod admin_in_temp;
pub mod admin_key_removal;
pub mod admin_no_event;
pub mod admin_no_group_auth;
pub mod admin_no_remove;
pub mod admin_overwrite;
pub mod admin_stored_unused;
pub mod admin_zero_address;
pub mod allowance_clear;
pub mod amount_mul_overflow;
pub mod approve_race;
pub mod assert_for_auth;
pub mod auth;
pub mod auth_loop_dos;
pub mod auth_shadow;
pub mod auth_temp_storage;
pub mod authorize_as_contract;
pub mod authorize_empty;
pub mod balance_negative_check;
pub mod balance_not_verified_after_transfer;
pub mod balance_overflow;
pub mod batch_partial_write;
pub mod broken_pause;
pub mod bump_after_read;
pub mod bump_to_ttl;
pub mod burn_auth;
pub mod burn_no_event;
pub mod bytes_not_bytesn;
pub mod bytes_oversized;
pub mod catch_unwind;
pub mod contracterror_attr;
pub mod contracttype;
pub mod cross_token_provenance_mix;
pub mod crypto_no_cache;
pub mod current_contract_unwrap;
pub mod dead_storage_code;
pub mod debug_entrypoint;
pub mod decimals_mismatch;
pub mod deploy_arg_auth;
pub mod deploy_salt_predictable;
pub mod deploy_unverified;
pub mod deployer_reuse;
pub mod double_init;
pub mod dynamic_symbol_key;
pub mod ed25519_key_in_temp;
pub mod env_in_struct;
pub mod event_duplicate;
pub mod event_no_topics;
pub mod event_topic_runtime_string;
pub mod expect_leaks;
pub mod extend_ttl_in_loop;
pub mod float_arithmetic;
pub mod governance_threshold_drift;
pub mod hash_as_storage_key;
pub mod host_result_ignored;
pub mod i128_to_u64;
pub mod instance_domain_mixing;
pub mod instance_remove_critical;
pub mod instance_set_no_has;
pub mod instance_ttl;
pub mod instance_vec_growth;
pub mod interprocedural_storage_toctou;
pub mod interprocedural_supply_cap;
pub mod invalid_address_literal;
pub mod invoke_func_from_input;
pub mod invoke_nonexistent_func;
pub mod invoke_result_untrusted;
pub mod invoke_store_no_event;
pub mod invoke_unchecked_cast;
pub mod keccak_misuse;
pub mod key_length_exceeded;
pub mod key_prefix_collision;
pub mod linear_whitelist_scan;
pub mod lock_period_truncation;
pub mod loop_bound_no_cap;
pub mod map_get_unwrap;
pub mod map_key_explosion;
pub mod map_user_key_bloat;
pub mod migration_guard;
pub mod mint_auth;
pub mod mint_no_cap;
pub mod missing_ttl;
pub mod mul_before_div;
pub mod negative_deposit;
pub mod nested_loop_storage;
pub mod no_admin;
pub mod no_param_no_auth;
pub mod no_std;
pub mod nonce_in_temp;
pub mod nonce_increment_order;
pub mod oracle_price_staleness;
pub mod overflow;
pub mod ownership_immediate;
pub mod ownership_no_approval_invalidation;
pub mod ownership_no_event;
pub mod ownership_pending_not_cleared;
pub mod ownership_transfer;
pub mod panic_raw_int;
pub mod panic_usage;
pub mod partial_write_on_error;
pub mod persistent_for_temp;
pub mod persistent_overwrite;
pub mod redundant_auth_args;
pub mod reentrancy;
pub mod renounce_no_backup;
pub mod result_err_ignored;
pub mod result_non_exhaustive;
pub mod revoked_admin_reuse;
pub mod runtime_symbol;
pub mod scale_factor_drift;
pub mod secp256k1_unchecked;
pub mod self_transfer;
pub mod sequence_as_key;
pub mod sequence_nonce;
pub mod sha256_empty;
pub mod sig_verify_inverted;
pub mod storage;
pub mod storage_has_get_mismatch;
pub mod storage_key_collision;
pub mod storage_no_cache;
pub mod storage_type_confusion;
pub mod storage_type_version;
pub mod temp_get_no_has;
pub mod temp_read_in_view;
pub mod temp_set_no_ttl;
pub mod tier_key_collision;
pub mod timestamp_as_nonce;
pub mod timestamp_expiry_no_min;
pub mod timestamp_truncation;
pub mod token_burn_auth;
pub mod token_shared_storage;
pub mod token_transfer_unchecked;
pub mod transfer_to_self;
pub mod try_into_unwrap;
pub mod ttl_arg_order;
pub mod ttl_before_write;
pub mod ttl_duration_provenance;
pub mod ttl_every_call;
pub mod ttl_min_zero;
pub mod ttl_uniform;
pub mod unauth_address_in_struct;
pub mod unauth_fee_setter;
pub mod unauth_sensitive_read;
pub mod unauthorized_storage_read;
pub mod unbounded_batch;
pub mod unbounded_input_storage;
pub mod unbounded_storage;
pub mod uncapped_fee;
pub mod uncapped_slippage;
pub mod unintended_public_method;
pub mod unlimited_allowance;
pub mod unvalidated_invoke_target;
pub mod unvalidated_price;
pub mod upgrade_atomicity_order;
pub mod upgrade_no_event;
pub mod upgrade_no_schema_version;
pub mod vec_get_unwrap;
pub mod vec_map_tuple_convert;
pub mod vec_mutate_in_loop;
pub mod vec_push_in_loop;
pub mod vesting_cliff;
pub mod weak_commitment_known;
pub mod weak_randomness;
pub mod while_host_condition;
pub mod while_no_bound;
pub mod withdraw_auth;
pub mod withdrawal_aggregate_bypass;
pub mod wrapping_balance_op;
pub mod zero_amount;
pub mod zero_divisor;
pub mod zero_transfer_event;
pub mod callgraph;
mod cfg;
mod provenance;
mod util;

pub use address_cmp_instead_of_auth::AddressCmpInsteadOfAuthCheck;
pub use address_from_str::AddressFromStrCheck;
pub use admin::UnprotectedAdminCheck;
pub use admin_eq_instead_of_auth::AdminEqInsteadOfAuthCheck;
pub use admin_in_temp::AdminInTempCheck;
pub use admin_key_removal::AdminKeyRemovalCheck;
pub use admin_no_event::AdminNoEventCheck;
pub use admin_no_group_auth::AdminNoGroupAuthCheck;
pub use admin_no_remove::AdminNoRemoveCheck;
pub use admin_overwrite::AdminOverwriteCheck;
pub use admin_stored_unused::AdminStoredUnusedCheck;
pub use admin_zero_address::AdminZeroAddressCheck;
pub use allowance_clear::AllowanceClearCheck;
pub use amount_mul_overflow::AmountMulOverflowCheck;
pub use approve_race::ApproveRaceCheck;
pub use assert_for_auth::AssertForAuthCheck;
pub use auth::MissingRequireAuthCheck;
pub use auth_loop_dos::AuthLoopDosCheck;
pub use auth_shadow::AuthShadowCheck;
pub use auth_temp_storage::AuthTempStorageCheck;
pub use authorize_as_contract::AuthorizeAsContractCheck;
pub use authorize_empty::AuthorizeEmptyCheck;
pub use balance_negative_check::BalanceNegativeCheck;
pub use balance_not_verified_after_transfer::BalanceNotVerifiedAfterTransferCheck;
pub use balance_overflow::BalanceOverflowCheck;
pub use batch_partial_write::BatchPartialWriteCheck;
pub use broken_pause::BrokenPauseCheck;
pub use bump_after_read::BumpAfterReadCheck;
pub use bump_to_ttl::BumpToTtlCheck;
pub use burn_auth::BurnAuthCheck;
pub use burn_no_event::BurnNoEventCheck;
pub use bytes_not_bytesn::BytesNotBytesNCheck;
pub use bytes_oversized::BytesOversizedCheck;
pub use catch_unwind::CatchUnwindCheck;
pub use contracterror_attr::ContracterrorAttrCheck;
pub use contracttype::MissingContracttypeCheck;
pub use cross_token_provenance_mix::CrossTokenProvenanceMixCheck;
pub use crypto_no_cache::CryptoNoCacheCheck;
pub use current_contract_unwrap::CurrentContractUnwrapCheck;
pub use dead_storage_code::DeadStorageCodeCheck;
pub use debug_entrypoint::DebugEntrypointCheck;
pub use decimals_mismatch::DecimalsMismatchCheck;
pub use deploy_arg_auth::DeployArgAuthCheck;
pub use deploy_salt_predictable::DeploySaltPredictableCheck;
pub use deploy_unverified::DeployUnverifiedCheck;
pub use deployer_reuse::DeployerReuseCheck;
pub use double_init::DoubleInitCheck;
pub use dynamic_symbol_key::DynamicSymbolKeyCheck;
pub use ed25519_key_in_temp::Ed25519KeyInTempCheck;
pub use env_in_struct::EnvInStructCheck;
pub use event_duplicate::EventDuplicateCheck;
pub use event_no_topics::EventNoTopicsCheck;
pub use event_topic_runtime_string::EventTopicRuntimeStringCheck;
pub use expect_leaks::ExpectLeaksCheck;
pub use extend_ttl_in_loop::ExtendTtlInLoopCheck;
pub use float_arithmetic::FloatArithmeticCheck;
pub use governance_threshold_drift::GovernanceThresholdDriftCheck;
pub use hash_as_storage_key::HashAsStorageKeyCheck;
pub use host_result_ignored::HostResultIgnoredCheck;
pub use i128_to_u64::I128ToU64Check;
pub use instance_domain_mixing::InstanceDomainMixingCheck;
pub use instance_remove_critical::InstanceRemoveCriticalCheck;
pub use instance_set_no_has::InstanceSetNoHasCheck;
pub use instance_ttl::InstanceTtlCheck;
pub use instance_vec_growth::InstanceVecGrowthCheck;
pub use interprocedural_storage_toctou::InterproceduralStorageTocTouCheck;
pub use interprocedural_supply_cap::InterproceduralSupplyCapCheck;
pub use invalid_address_literal::InvalidAddressLiteralCheck;
pub use invoke_func_from_input::InvokeFuncFromInputCheck;
pub use invoke_nonexistent_func::InvokeNonexistentFuncCheck;
pub use invoke_result_untrusted::InvokeResultUntrustedCheck;
pub use invoke_store_no_event::InvokeStoreNoEventCheck;
pub use invoke_unchecked_cast::InvokeUncheckedCastCheck;
pub use keccak_misuse::KeccakMisuseCheck;
pub use key_length_exceeded::KeyLengthExceededCheck;
pub use key_prefix_collision::KeyPrefixCollisionCheck;
pub use linear_whitelist_scan::LinearWhitelistScanCheck;
pub use lock_period_truncation::LockPeriodTruncationCheck;
pub use loop_bound_no_cap::LoopBoundNoCapCheck;
pub use map_get_unwrap::MapGetUnwrapCheck;
pub use map_key_explosion::MapKeyExplosionCheck;
pub use map_user_key_bloat::MapUserKeyBloatCheck;
pub use migration_guard::MigrationGuardCheck;
pub use mint_auth::MintAuthCheck;
pub use mint_no_cap::MintNoCapCheck;
pub use missing_ttl::MissingTtlExtensionCheck;
pub use mul_before_div::MulBeforeDivCheck;
pub use negative_deposit::NegativeDepositCheck;
pub use nested_loop_storage::NestedLoopStorageCheck;
pub use no_admin::NoAdminCheck;
pub use no_param_no_auth::NoParamNoAuthCheck;
pub use no_std::NoStdCheck;
pub use nonce_in_temp::NonceInTempCheck;
pub use nonce_increment_order::NonceIncrementOrderCheck;
pub use oracle_price_staleness::OraclePriceStalenessCheck;
pub use overflow::UncheckedArithmeticCheck;
pub use ownership_immediate::OwnershipImmediateCheck;
pub use ownership_no_approval_invalidation::OwnershipNoApprovalInvalidationCheck;
pub use ownership_no_event::OwnershipNoEventCheck;
pub use ownership_pending_not_cleared::OwnershipPendingNotClearedCheck;
pub use ownership_transfer::OwnershipTransferCheck;
pub use panic_raw_int::PanicRawIntCheck;
pub use panic_usage::PanicUsageCheck;
pub use partial_write_on_error::PartialWriteOnErrorCheck;
pub use persistent_for_temp::PersistentForTempCheck;
pub use persistent_overwrite::PersistentOverwriteCheck;
pub use redundant_auth_args::RedundantAuthArgsCheck;
pub use reentrancy::ReentrancyCheck;
pub use renounce_no_backup::RenounceNoBackupCheck;
pub use result_err_ignored::ResultErrIgnoredCheck;
pub use result_non_exhaustive::ResultNonExhaustiveCheck;
pub use revoked_admin_reuse::RevokedAdminReuseCheck;
pub use runtime_symbol::RuntimeSymbolCheck;
pub use scale_factor_drift::ScaleFactorDriftCheck;
pub use secp256k1_unchecked::Secp256k1UncheckedCheck;
pub use self_transfer::SelfTransferCheck;
pub use sequence_as_key::SequenceAsKeyCheck;
pub use sequence_nonce::SequenceNonceCheck;
pub use sha256_empty::Sha256EmptyCheck;
pub use sig_verify_inverted::SigVerifyInvertedCheck;
pub use storage::UnsafeStoragePatternsCheck;
pub use storage_has_get_mismatch::StorageHasGetMismatchCheck;
pub use storage_key_collision::StorageKeyCollisionCheck;
pub use storage_no_cache::StorageNoCacheCheck;
pub use storage_type_confusion::StorageTypeConfusionCheck;
pub use storage_type_version::StorageTypeVersionCheck;
pub use temp_get_no_has::TempGetNoHasCheck;
pub use temp_read_in_view::TempReadInViewCheck;
pub use temp_set_no_ttl::TempSetNoTtlCheck;
pub use tier_key_collision::TierKeyCollisionCheck;
pub use timestamp_as_nonce::TimestampAsNonceCheck;
pub use timestamp_expiry_no_min::TimestampExpiryNoMinCheck;
pub use timestamp_truncation::TimestampTruncationCheck;
pub use token_burn_auth::TokenBurnAuthCheck;
pub use token_shared_storage::TokenSharedStorageCheck;
pub use token_transfer_unchecked::TokenTransferUncheckedCheck;
pub use transfer_to_self::TransferToSelfCheck;
pub use try_into_unwrap::TryIntoUnwrapCheck;
pub use ttl_arg_order::TtlArgOrderCheck;
pub use ttl_before_write::TtlBeforeWriteCheck;
pub use ttl_duration_provenance::TtlDurationProvenanceCheck;
pub use ttl_every_call::TtlEveryCallCheck;
pub use ttl_min_zero::TtlMinZeroCheck;
pub use ttl_uniform::TtlUniformCheck;
pub use unauth_address_in_struct::UnauthAddressInStructCheck;
pub use unauth_fee_setter::UnauthFeeSetterCheck;
pub use unauth_sensitive_read::UnauthSensitiveReadCheck;
pub use unauthorized_storage_read::UnauthorizedStorageReadCheck;
pub use unbounded_batch::UnboundedBatchCheck;
pub use unbounded_input_storage::UnboundedInputStorageCheck;
pub use unbounded_storage::UnboundedStorageCheck;
pub use uncapped_fee::UncappedFeeCheck;
pub use uncapped_slippage::UncappedSlippageCheck;
pub use unintended_public_method::UnintendedPublicMethodCheck;
pub use unlimited_allowance::UnlimitedAllowanceCheck;
pub use unvalidated_invoke_target::UnvalidatedInvokeTargetCheck;
pub use unvalidated_price::UnvalidatedPriceCheck;
pub use upgrade_atomicity_order::UpgradeAtomicityOrderCheck;
pub use upgrade_no_event::UpgradeNoEventCheck;
pub use upgrade_no_schema_version::UpgradeNoSchemaVersionCheck;
pub use vec_get_unwrap::VecGetUnwrapCheck;
pub use vec_map_tuple_convert::VecMapTupleConvertCheck;
pub use vec_mutate_in_loop::VecMutateInLoopCheck;
pub use vec_push_in_loop::VecPushInLoopCheck;
pub use vesting_cliff::VestingCliffCheck;
pub use weak_commitment_known::WeakCommitmentKnownCheck;
pub use weak_randomness::WeakRandomnessCheck;
pub use while_host_condition::WhileHostConditionCheck;
pub use while_no_bound::WhileNoBoundCheck;
pub use withdraw_auth::WithdrawAuthCheck;
pub use withdrawal_aggregate_bypass::WithdrawalAggregateBypassCheck;
pub use wrapping_balance_op::WrappingBalanceOpCheck;
pub use zero_amount::ZeroAmountCheck;
pub use zero_divisor::ZeroDivisorCheck;
pub use zero_transfer_event::ZeroTransferEventCheck;
pub use callgraph::CallGraph;

use serde::Serialize;
use syn::File;

/// Severity of a finding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    High,
    Medium,
    Low,
}

/// One issue reported by a check.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Finding {
    pub check_name: String,
    pub severity: Severity,
    pub file_path: String,
    pub line: usize,
    pub function_name: String,
    pub description: String,
}

/// A static analyzer check implemented against a parsed `syn::File`.
pub trait Check {
    fn name(&self) -> &str;
    fn run(&self, file: &File, source: &str) -> Vec<Finding>;
}

/// All checks executed by the analyzer (extend here as you add detectors).
///
/// Checks are **stateless and isolated**: implementations must not use shared mutable
/// static state or assume a particular invocation order. The analyzer runs each check
/// against the same parsed `syn::File` independently and concatenates `Finding`s.
pub fn default_checks() -> Vec<Box<dyn Check + Send + Sync>> {
    vec![
        Box::new(AddressCmpInsteadOfAuthCheck),
        Box::new(AddressFromStrCheck),
        Box::new(UnprotectedAdminCheck),
        Box::new(AdminEqInsteadOfAuthCheck),
        Box::new(AdminInTempCheck),
        Box::new(AdminKeyRemovalCheck),
        Box::new(AdminNoEventCheck),
        Box::new(AdminNoGroupAuthCheck),
        Box::new(AdminNoRemoveCheck),
        Box::new(AdminOverwriteCheck),
        Box::new(AdminStoredUnusedCheck),
        Box::new(AdminZeroAddressCheck),
        Box::new(AllowanceClearCheck),
        Box::new(AmountMulOverflowCheck),
        Box::new(ApproveRaceCheck),
        Box::new(AssertForAuthCheck),
        Box::new(MissingRequireAuthCheck),
        Box::new(AuthLoopDosCheck),
        Box::new(AuthShadowCheck),
        Box::new(AuthTempStorageCheck),
        Box::new(AuthorizeAsContractCheck),
        Box::new(AuthorizeEmptyCheck),
        Box::new(BalanceNegativeCheck),
        Box::new(BalanceNotVerifiedAfterTransferCheck),
        Box::new(BalanceOverflowCheck),
        Box::new(BatchPartialWriteCheck),
        Box::new(BrokenPauseCheck),
        Box::new(BumpAfterReadCheck),
        Box::new(BumpToTtlCheck),
        Box::new(BurnAuthCheck),
        Box::new(BurnNoEventCheck),
        Box::new(BytesNotBytesNCheck),
        Box::new(BytesOversizedCheck),
        Box::new(CatchUnwindCheck),
        Box::new(ContracterrorAttrCheck),
        Box::new(MissingContracttypeCheck),
        Box::new(CrossTokenProvenanceMixCheck),
        Box::new(CryptoNoCacheCheck),
        Box::new(CurrentContractUnwrapCheck),
        Box::new(DeadStorageCodeCheck),
        Box::new(DebugEntrypointCheck),
        Box::new(DecimalsMismatchCheck),
        Box::new(DeployArgAuthCheck),
        Box::new(DeploySaltPredictableCheck),
        Box::new(DeployUnverifiedCheck),
        Box::new(DeployerReuseCheck),
        Box::new(DoubleInitCheck),
        Box::new(DynamicSymbolKeyCheck),
        Box::new(Ed25519KeyInTempCheck),
        Box::new(EnvInStructCheck),
        Box::new(EventDuplicateCheck),
        Box::new(EventNoTopicsCheck),
        Box::new(EventTopicRuntimeStringCheck),
        Box::new(ExpectLeaksCheck),
        Box::new(ExtendTtlInLoopCheck),
        Box::new(FloatArithmeticCheck),
        Box::new(GovernanceThresholdDriftCheck),
        Box::new(HashAsStorageKeyCheck),
        Box::new(HostResultIgnoredCheck),
        Box::new(I128ToU64Check),
        Box::new(InstanceDomainMixingCheck),
        Box::new(InstanceRemoveCriticalCheck),
        Box::new(InstanceSetNoHasCheck),
        Box::new(InstanceTtlCheck),
        Box::new(InstanceVecGrowthCheck),
        Box::new(InterproceduralStorageTocTouCheck),
        Box::new(InterproceduralSupplyCapCheck),
        Box::new(InvalidAddressLiteralCheck),
        Box::new(InvokeFuncFromInputCheck),
        Box::new(InvokeNonexistentFuncCheck),
        Box::new(InvokeResultUntrustedCheck),
        Box::new(InvokeStoreNoEventCheck),
        Box::new(InvokeUncheckedCastCheck),
        Box::new(KeccakMisuseCheck),
        Box::new(KeyLengthExceededCheck),
        Box::new(KeyPrefixCollisionCheck),
        Box::new(LinearWhitelistScanCheck),
        Box::new(LockPeriodTruncationCheck),
        Box::new(LoopBoundNoCapCheck),
        Box::new(MapGetUnwrapCheck),
        Box::new(MapKeyExplosionCheck),
        Box::new(MapUserKeyBloatCheck),
        Box::new(MigrationGuardCheck),
        Box::new(MintAuthCheck),
        Box::new(MintNoCapCheck),
        Box::new(MissingTtlExtensionCheck),
        Box::new(MulBeforeDivCheck),
        Box::new(NegativeDepositCheck),
        Box::new(NestedLoopStorageCheck),
        Box::new(NoAdminCheck),
        Box::new(NoParamNoAuthCheck),
        Box::new(NoStdCheck),
        Box::new(NonceInTempCheck),
        Box::new(NonceIncrementOrderCheck),
        Box::new(OraclePriceStalenessCheck),
        Box::new(UncheckedArithmeticCheck),
        Box::new(OwnershipImmediateCheck),
        Box::new(OwnershipNoApprovalInvalidationCheck),
        Box::new(OwnershipNoEventCheck),
        Box::new(OwnershipPendingNotClearedCheck),
        Box::new(OwnershipTransferCheck),
        Box::new(PanicRawIntCheck),
        Box::new(PanicUsageCheck),
        Box::new(PartialWriteOnErrorCheck),
        Box::new(PersistentForTempCheck),
        Box::new(PersistentOverwriteCheck),
        Box::new(RedundantAuthArgsCheck),
        Box::new(ReentrancyCheck),
        Box::new(RenounceNoBackupCheck),
        Box::new(ResultErrIgnoredCheck),
        Box::new(ResultNonExhaustiveCheck),
        Box::new(RevokedAdminReuseCheck),
        Box::new(RuntimeSymbolCheck),
        Box::new(ScaleFactorDriftCheck),
        Box::new(Secp256k1UncheckedCheck),
        Box::new(SelfTransferCheck),
        Box::new(SequenceAsKeyCheck),
        Box::new(SequenceNonceCheck),
        Box::new(Sha256EmptyCheck),
        Box::new(SigVerifyInvertedCheck),
        Box::new(UnsafeStoragePatternsCheck),
        Box::new(StorageHasGetMismatchCheck),
        Box::new(StorageKeyCollisionCheck),
        Box::new(StorageNoCacheCheck),
        Box::new(StorageTypeConfusionCheck),
        Box::new(StorageTypeVersionCheck),
        Box::new(TempGetNoHasCheck),
        Box::new(TempReadInViewCheck),
        Box::new(TempSetNoTtlCheck),
        Box::new(TierKeyCollisionCheck),
        Box::new(TimestampAsNonceCheck),
        Box::new(TimestampExpiryNoMinCheck),
        Box::new(TimestampTruncationCheck),
        Box::new(TokenBurnAuthCheck),
        Box::new(TokenSharedStorageCheck),
        Box::new(TokenTransferUncheckedCheck),
        Box::new(TransferToSelfCheck),
        Box::new(TryIntoUnwrapCheck),
        Box::new(TtlArgOrderCheck),
        Box::new(TtlBeforeWriteCheck),
        Box::new(TtlDurationProvenanceCheck),
        Box::new(TtlEveryCallCheck),
        Box::new(TtlMinZeroCheck),
        Box::new(TtlUniformCheck),
        Box::new(UnauthAddressInStructCheck),
        Box::new(UnauthFeeSetterCheck),
        Box::new(UnauthSensitiveReadCheck),
        Box::new(UnauthorizedStorageReadCheck),
        Box::new(UnboundedBatchCheck),
        Box::new(UnboundedInputStorageCheck),
        Box::new(UnboundedStorageCheck),
        Box::new(UncappedFeeCheck),
        Box::new(UncappedSlippageCheck),
        Box::new(UnintendedPublicMethodCheck),
        Box::new(UnlimitedAllowanceCheck),
        Box::new(UnvalidatedInvokeTargetCheck),
        Box::new(UnvalidatedPriceCheck),
        Box::new(UpgradeAtomicityOrderCheck),
        Box::new(UpgradeNoEventCheck),
        Box::new(UpgradeNoSchemaVersionCheck),
        Box::new(VecGetUnwrapCheck),
        Box::new(VecMapTupleConvertCheck),
        Box::new(VecMutateInLoopCheck),
        Box::new(VecPushInLoopCheck),
        Box::new(VestingCliffCheck),
        Box::new(WeakCommitmentKnownCheck),
        Box::new(WeakRandomnessCheck),
        Box::new(WhileHostConditionCheck),
        Box::new(WhileNoBoundCheck),
        Box::new(WithdrawAuthCheck),
        Box::new(WithdrawalAggregateBypassCheck),
        Box::new(WrappingBalanceOpCheck),
        Box::new(ZeroAmountCheck),
        Box::new(ZeroDivisorCheck),
        Box::new(ZeroTransferEventCheck),
    ]
}
