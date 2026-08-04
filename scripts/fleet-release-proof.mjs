#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const proofGroups = Object.freeze([
  {
    id: 1,
    name: 'fleet identity and lease lifecycle',
    tests: [
      'fleet::tests::enrollment_is_single_use_and_store_contains_only_verifiers',
      'fleet::tests::heartbeat_requires_node_identity_and_rejects_stale_epoch',
      'fleet::tests::claim_lease_completion_and_replay_are_fenced',
      'fleet::tests::expired_lease_cannot_renew_or_complete',
      'fleet::tests::successful_renewal_extends_same_attempt_and_it_completes',
      'fleet::tests::revocation_fences_live_attempt_and_expiry_recovers_on_another_node',
      'fleet::tests::revoked_and_stale_nodes_fail_closed',
      'fleet_executor::tests::isolated_hub_and_executor_homes_offload_without_manual_receive',
    ],
  },
  {
    id: 2,
    name: 'shared execution envelope transports',
    tests: [
      'fleet_executor::tests::worker_claims_executes_and_completes_the_shared_envelope',
      'executor_node::tests::ssh_transport_builds_batch_mode_pinned_argv',
      'executor_node::tests::local_transport_runs_the_protocol_arguments',
      'executor_node::tests::local_ssh_and_direct_pull_share_the_normalized_result_contract',
      'executor_node::tests::poll_executor_parses_and_validates_the_probe_envelope',
    ],
  },
  {
    id: 3,
    name: 'lease loss and restart recovery',
    tests: [
      'fleet_executor::tests::renewal_loss_quiesces_worker_without_reporting_stale_outcome',
      'fleet::tests::expired_node_pinned_job_can_only_be_reclaimed_by_its_target',
      'hub::tests::hub_state_persists_to_disk_and_reloads_after_restart',
      'fleet::tests::hub_reopen_preserves_live_lease_then_expiry_allows_one_replacement',
      'fleet_executor::tests::executor_restart_waits_for_expiry_then_executes_one_replacement_attempt',
    ],
  },
  {
    id: 4,
    name: 'workspace mobility integrity',
    tests: [
      'workspace_mobility::tests::portable_policy_excludes_cross_platform_generated_caches',
      'workspace_mobility::tests::invokes_a_protocol_adapter_and_rejects_mismatched_responses',
      'fleet_executor::tests::workspace_request_is_leased_to_the_process_adapter',
    ],
  },
  {
    id: 5,
    name: 'managed harness lifecycle and credential boundary',
    tests: [
      'harness_host::tests::fake_actor_survives_reopen_accepts_input_and_stops',
      'harness_host::tests::actor_start_replay_requires_the_exact_immutable_binding',
      'harness_host::tests::provider_auth_remains_executor_local_and_serialized_credentials_fail_closed',
      'fleet_executor::tests::fake_harness_actor_start_send_status_and_stop_are_automatic',
      'fleet_executor::tests::persisted_executor_config_is_owner_only_and_redacted_status_can_omit_secret',
    ],
  },
  {
    id: 6,
    name: 'delegation isolation and integration authority',
    tests: [
      'result_integration::tests::previews_and_applies_only_against_the_exact_base',
      'result_integration::tests::divergence_is_explicit_and_does_not_mutate_parent',
      'result_integration::tests::apply_cas_rejects_parent_advance_after_clean_preview',
      'result_integration::tests::rejects_tampered_patch_or_failed_verification',
      'fleet_executor::tests::remote_delegation_retains_until_ack_then_cleans_up_on_owner_node',
      'fleet_ux::tests::snapshot_schema_is_redacted_bounded_and_fail_closed',
      'fleet_ux::tests::snapshot_is_deterministic_filtered_and_has_no_side_effects',
      'api::tests::fleet_ux_snapshot_is_local_only_and_accepts_session_filter',
      'api::tests::fleet_ux_delegation_decisions_are_local_redacted_and_replay_safe',
    ],
  },
  {
    id: 7,
    name: 'automatic generation-fenced roam',
    tests: [
      'fleet_executor::tests::automatic_roam_checkpoints_prepares_activates_and_drains_input',
      'roam::tests::automatic_roam_derives_private_authority_and_honors_explicit_target',
      'roam::tests::automatic_roam_uses_deterministic_scheduler_and_rejects_unknown_input',
      'roam::tests::automatic_roam_rejections_are_stable_and_do_not_mutate',
      'api::tests::roam_command_and_status_are_local_only_and_remote_attempts_do_not_mutate',
    ],
  },
  {
    id: 8,
    name: 'heterogeneous placement and matrix aggregation',
    tests: [
      'placement_scheduler::tests::platform_matrix',
      'placement_scheduler::tests::gpu_resources_versions_and_protocol_intersections',
      'placement_scheduler::tests::stale_and_unavailable_are_ineligible',
      'placement_scheduler::tests::preference_pressure_and_node_ties_are_deterministic',
      'fleet::tests::claim_binds_observation_snapshot_and_delegation_digest',
      'result_integration::tests::platform_evidence_is_canonical_and_bound_into_result_digest',
      'delegation_matrix::tests::start_normalizes_order_and_replays_without_duplicate_children',
      'delegation_matrix::tests::aggregate_is_order_independent_and_partial_is_terminal_only',
      'delegation_matrix::tests::aggregate_retains_and_digests_lane_platform_evidence',
      'delegation_matrix::tests::five_lane_heterogeneous_fan_out_is_completion_order_independent',
      'delegation_matrix::tests::five_lane_matrix_claims_matching_nodes_and_aggregates_bound_results',
      'delegation_matrix::tests::replay_rejects_changed_immutable_axis',
    ],
  },
]);

export function parseCargoTestList(output) {
  const names = new Set();
  for (const line of output.split(/\r?\n/u)) {
    const match = line.match(/^(.+): test$/u);
    if (match) names.add(match[1]);
  }
  return names;
}

export function validateManifest(groups = proofGroups) {
  const expectedIds = Array.from({ length: 8 }, (_, index) => index + 1);
  const ids = groups.map((group) => group.id);
  if (JSON.stringify(ids) !== JSON.stringify(expectedIds)) {
    throw new Error(`fleet proof groups must be exactly 1..8; found ${ids.join(', ')}`);
  }
  const seen = new Set();
  for (const group of groups) {
    if (!group.name || !Array.isArray(group.tests) || group.tests.length === 0) {
      throw new Error(`fleet proof group ${group.id} must have a name and at least one test`);
    }
    for (const test of group.tests) {
      if (!test || seen.has(test)) throw new Error(`duplicate or empty fleet proof test: ${test}`);
      seen.add(test);
    }
  }
  return seen;
}

export function missingProofs(listedTests, groups = proofGroups) {
  const required = validateManifest(groups);
  return [...required].filter((test) => !listedTests.has(test)).sort();
}

export function proofPassedExactlyOnce(output) {
  return /test result: ok\. 1 passed; 0 failed; 0 ignored;/u.test(output);
}

function runProof(command, args, proof) {
  const result = spawnSync(command, args, { encoding: 'utf8', shell: false });
  if (result.error) throw result.error;
  process.stdout.write(result.stdout ?? '');
  process.stderr.write(result.stderr ?? '');
  if (result.status !== 0) process.exit(result.status ?? 1);
  if (!proofPassedExactlyOnce(result.stdout ?? '')) {
    process.stderr.write(`Required fleet proof did not execute exactly once: ${proof}\n`);
    process.exit(1);
  }
}

function cargoCapture(args) {
  const command = process.platform === 'win32' ? 'cargo.exe' : 'cargo';
  const result = spawnSync(command, args, { encoding: 'utf8', shell: false });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    process.stderr.write(result.stderr ?? '');
    process.stdout.write(result.stdout ?? '');
    process.exit(result.status ?? 1);
  }
  return result.stdout;
}

export function parseCargoTestExecutable(output) {
  let executable;
  for (const line of output.split(/\r?\n/u)) {
    if (!line.startsWith('{')) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      continue;
    }
    if (
      message.reason === 'compiler-artifact'
      && message.profile?.test === true
      && message.target?.name === 'coven'
      && message.target?.kind?.includes('bin')
      && typeof message.executable === 'string'
    ) {
      executable = message.executable;
    }
  }
  if (!executable) throw new Error('cargo did not report the Coven test executable');
  return executable;
}

function captureExecutable(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8', shell: false });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    process.stdout.write(result.stdout ?? '');
    process.stderr.write(result.stderr ?? '');
    process.exit(result.status ?? 1);
  }
  return result.stdout ?? '';
}

export function main() {
  validateManifest();
  process.stdout.write('Building and discovering Coven fleet release proofs...\n');
  const cargo = process.platform === 'win32' ? 'cargo.exe' : 'cargo';
  const build = cargoCapture([
    'test', '-p', 'coven-cli', '--bin', 'coven', '--locked', '--no-run', '--message-format=json',
  ]);
  const testExecutable = parseCargoTestExecutable(build);
  const listing = captureExecutable(testExecutable, ['--list']);
  const missing = missingProofs(parseCargoTestList(listing));
  if (missing.length > 0) {
    process.stderr.write(`Missing required fleet release proofs:\n${missing.map((name) => `  - ${name}`).join('\n')}\n`);
    process.exit(1);
  }

  for (const group of proofGroups) {
    process.stdout.write(`Fleet proof group ${group.id}: ${group.name} (${group.tests.length} required tests)\n`);
    for (const proof of group.tests) {
      process.stdout.write(`  - ${proof}\n`);
      runProof(testExecutable, [proof, '--exact', '--nocapture'], proof);
    }
  }
  process.stdout.write('\nAll 8 Coven fleet release proof groups passed.\n');
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main();
