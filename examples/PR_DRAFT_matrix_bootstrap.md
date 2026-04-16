# PR: Auto-bootstrap E2EE for fresh Matrix bots

## Summary
- **Problem**: When hermes-agent connects a fresh Matrix bot account with MATRIX_ENCRYPTION=true, the gateway can verify an existing recovery key but cannot bootstrap one. A fresh account requires manual intervention via Element web to set up secure backup and copy the recovery key.

- **Solution**: Added auto-bootstrap code path that calls olm.generate_recovery_key() when MATRIX_AUTO_BOOTSTRAP_E2EE=true and no existing recovery key is set.

- **Key Changes**:
  - New MATRIX_AUTO_BOOTSTRAP_E2EE environment variable controls the feature
  - Automatic recovery key generation for fresh accounts
  - Atomic write of generated key to $HERMES_HOME/.env
  - Safe fallback to existing behavior when key already exists or SSSS is configured

## Test plan
- [x] test_bootstrap_writes_recovery_key_to_env: Verifies key generation and .env persistence
- [x] test_bootstrap_idempotent: Ensures no duplicate keys on repeated runs
- [x] test_existing_recovery_key_takes_precedence: Confirms manual keys override auto-bootstrap
- [x] test_bootstrap_disabled_by_default: Verifies default behavior unchanged
- [x] test_bootstrap_skips_when_ssss_key_exists: Respects existing server-side SSSS keys

## Implementation details
- Checks for existing m.secret_storage.default_key on server before bootstrapping
- Uses atomic file write (.env.tmp + os.replace) to prevent corruption
- Logs INFO message when bootstrap succeeds with file path
- Preserves existing MATRIX_RECOVERY_KEY verification behavior
- Idempotent: checks for existing key in .env before writing

## PR command
```bash
gh pr create --title "feat: Auto-bootstrap E2EE for fresh Matrix bots" --body "## Summary
When hermes-agent connects a fresh Matrix bot account with MATRIX_ENCRYPTION=true, the gateway can verify an existing recovery key but cannot bootstrap one. A fresh account requires manual intervention via Element web to set up secure backup and copy the recovery key.

## Solution
Added auto-bootstrap code path that calls olm.generate_recovery_key() when MATRIX_AUTO_BOOTSTRAP_E2EE=true and no existing recovery key is set.

## Key Changes
- New MATRIX_AUTO_BOOTSTRAP_E2EE environment variable controls the feature
- Automatic recovery key generation for fresh accounts
- Atomic write of generated key to HERMES_HOME/.env
- Safe fallback to existing behavior when key already exists or SSSS is configured

## Test plan
- test_bootstrap_writes_recovery_key_to_env: Verifies key generation and .env persistence
- test_bootstrap_idempotent: Ensures no duplicate keys on repeated runs
- test_existing_recovery_key_takes_precedence: Confirms manual keys override auto-bootstrap
- test_bootstrap_disabled_by_default: Verifies default behavior unchanged
- test_bootstrap_skips_when_ssss_key_exists: Respects existing server-side SSSS keys

## Implementation details
- Checks for existing m.secret_storage.default_key on server before bootstrapping
- Uses atomic file write (.env.tmp + os.replace) to prevent corruption
- Logs INFO message when bootstrap succeeds with file path
- Preserves existing MATRIX_RECOVERY_KEY verification behavior
- Idempotent: checks for existing key in .env before writing" --base NousResearch/hermes-agent:main
```
