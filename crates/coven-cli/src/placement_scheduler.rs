//! Pure typed capability matching and deterministic placement ranking.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::fleet::NodeCapabilities;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolRequirements {
    #[serde(default)]
    pub executor: Vec<u16>,
    #[serde(default)]
    pub workspace_driver: Vec<u16>,
    #[serde(default)]
    pub harness_host: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactRuntimeRequirement {
    pub runtime: String,
    pub version: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GpuRequirement {
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub min_memory_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HardConstraints {
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub min_cpu_cores: u32,
    #[serde(default)]
    pub min_memory_bytes: u64,
    #[serde(default)]
    pub gpu: Option<GpuRequirement>,
    #[serde(default)]
    pub runtimes: Vec<ExactRuntimeRequirement>,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub harnesses: Vec<String>,
    #[serde(default)]
    pub workspace_drivers: Vec<String>,
    #[serde(default)]
    pub protocols: ProtocolRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LeafConstraint {
    Os { value: String },
    Architecture { value: String },
    MinCpuCores { value: u32 },
    MinMemoryBytes { value: u64 },
    GpuVendor { value: String },
    GpuModel { value: String },
    MinGpuMemoryBytes { value: u64 },
    RuntimeExact { runtime: String, version: String },
    Tool { name: String },
    Harness { name: String },
    WorkspaceDriver { name: String },
    ExecutorProtocol { any_of: Vec<u16> },
    WorkspaceDriverProtocol { any_of: Vec<u16> },
    HarnessHostProtocol { any_of: Vec<u16> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WeightedPreference {
    pub weight: u16,
    pub constraint: LeafConstraint,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlacementRequest {
    #[serde(default)]
    pub required: HardConstraints,
    #[serde(default)]
    pub preferred: Vec<WeightedPreference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementCandidate {
    pub node_id: String,
    pub observation_id: String,
    pub fresh: bool,
    pub available: bool,
    pub queue_pressure: u32,
    pub capabilities: NodeCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConstraintEvidence {
    pub constraint: String,
    pub expected: Value,
    pub actual: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreferenceEvidence {
    pub index: usize,
    pub weight: u16,
    pub constraint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchEvidence {
    pub eligible: bool,
    pub preference_score: u64,
    pub failed_constraints: Vec<ConstraintEvidence>,
    pub matched_preferences: Vec<PreferenceEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacementDecision {
    pub node_id: String,
    pub observation_id: String,
    pub queue_pressure: u32,
    pub evidence: MatchEvidence,
}

pub fn rank(
    request: &PlacementRequest,
    candidates: impl IntoIterator<Item = PlacementCandidate>,
) -> Result<Vec<PlacementDecision>> {
    let request = normalize_request(request)?;
    let mut ranked = candidates
        .into_iter()
        .filter_map(|candidate| {
            let evidence = evaluate_normalized(&request, &candidate);
            evidence.eligible.then_some(PlacementDecision {
                node_id: candidate.node_id,
                observation_id: candidate.observation_id,
                queue_pressure: candidate.queue_pressure,
                evidence,
            })
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|a, b| {
        b.evidence
            .preference_score
            .cmp(&a.evidence.preference_score)
            .then_with(|| a.queue_pressure.cmp(&b.queue_pressure))
            .then_with(|| a.node_id.cmp(&b.node_id))
    });
    Ok(ranked)
}

pub fn evaluate(
    request: &PlacementRequest,
    candidate: &PlacementCandidate,
) -> Result<MatchEvidence> {
    Ok(evaluate_normalized(&normalize_request(request)?, candidate))
}

pub fn normalize_request(request: &PlacementRequest) -> Result<PlacementRequest> {
    let mut r = request.clone();
    r.required.os = r.required.os.map(normalize_os).filter(|v| !v.is_empty());
    r.required.architecture = r
        .required
        .architecture
        .map(normalize_arch)
        .filter(|v| !v.is_empty());
    if let Some(gpu) = &mut r.required.gpu {
        gpu.vendor = gpu
            .vendor
            .take()
            .map(normalize_name)
            .filter(|v| !v.is_empty());
        gpu.model = gpu
            .model
            .take()
            .map(normalize_name)
            .filter(|v| !v.is_empty());
    }
    for item in &mut r.required.runtimes {
        item.runtime = normalize_name(std::mem::take(&mut item.runtime));
        item.version = item.version.trim().into();
        if item.runtime.is_empty() || item.version.is_empty() {
            bail!("runtime exact requirements need non-empty runtime and version")
        }
    }
    r.required.runtimes.sort_by(|a, b| {
        a.runtime
            .cmp(&b.runtime)
            .then_with(|| a.version.cmp(&b.version))
    });
    r.required.runtimes.dedup();
    for names in [
        &mut r.required.tools,
        &mut r.required.harnesses,
        &mut r.required.workspace_drivers,
    ] {
        normalize_names(names)?;
    }
    for versions in [
        &mut r.required.protocols.executor,
        &mut r.required.protocols.workspace_driver,
        &mut r.required.protocols.harness_host,
    ] {
        versions.sort_unstable();
        versions.dedup();
    }
    for preference in &mut r.preferred {
        if preference.weight == 0 {
            bail!("preference weights must be greater than zero")
        }
        normalize_leaf(&mut preference.constraint)?;
    }
    Ok(r)
}

fn evaluate_normalized(
    request: &PlacementRequest,
    candidate: &PlacementCandidate,
) -> MatchEvidence {
    let mut failed = Vec::new();
    if !candidate.fresh {
        failed.push(failure("fresh", json!(true), json!(false)));
    }
    if !candidate.available {
        failed.push(failure("available", json!(true), json!(false)));
    }
    let r = &request.required;
    optional_eq(
        &mut failed,
        "os",
        r.os.as_deref(),
        &normalize_os(candidate.capabilities.platform.os.clone()),
    );
    optional_eq(
        &mut failed,
        "architecture",
        r.architecture.as_deref(),
        &normalize_arch(candidate.capabilities.platform.architecture.clone()),
    );
    minimum(
        &mut failed,
        "cpu-cores",
        r.min_cpu_cores as u64,
        candidate.capabilities.resources.cpu_cores as u64,
    );
    minimum(
        &mut failed,
        "memory-bytes",
        r.min_memory_bytes,
        candidate.capabilities.resources.memory_bytes,
    );
    if let Some(want) = &r.gpu {
        match &candidate.capabilities.gpu {
            None => failed.push(failure("gpu", json!("required"), Value::Null)),
            Some(gpu) => {
                optional_eq(
                    &mut failed,
                    "gpu-vendor",
                    want.vendor.as_deref(),
                    &normalize_name(gpu.vendor.clone()),
                );
                optional_eq(
                    &mut failed,
                    "gpu-model",
                    want.model.as_deref(),
                    &normalize_name(gpu.model.clone()),
                );
                minimum(
                    &mut failed,
                    "gpu-memory-bytes",
                    want.min_memory_bytes,
                    gpu.memory_bytes,
                );
            }
        }
    }
    for runtime in &r.runtimes {
        if !runtime_exact(&candidate.capabilities, &runtime.runtime, &runtime.version) {
            failed.push(failure(
                &format!("runtime:{}", runtime.runtime),
                json!(runtime.version),
                json!(runtime_versions(&candidate.capabilities, &runtime.runtime)),
            ));
        }
    }
    names(&mut failed, "tool", &r.tools, &candidate.capabilities.tools);
    names(
        &mut failed,
        "harness",
        &r.harnesses,
        &candidate.capabilities.harnesses,
    );
    names(
        &mut failed,
        "workspace-driver",
        &r.workspace_drivers,
        &candidate.capabilities.workspace_drivers,
    );
    protocol(
        &mut failed,
        "protocol:executor",
        &r.protocols.executor,
        &candidate.capabilities.protocols.executor,
    );
    protocol(
        &mut failed,
        "protocol:workspace-driver",
        &r.protocols.workspace_driver,
        &candidate.capabilities.protocols.workspace_driver,
    );
    protocol(
        &mut failed,
        "protocol:harness-host",
        &r.protocols.harness_host,
        &candidate.capabilities.protocols.harness_host,
    );
    let mut score = 0u64;
    let matched_preferences = request
        .preferred
        .iter()
        .enumerate()
        .filter(|(_, p)| leaf_matches(&p.constraint, &candidate.capabilities))
        .map(|(index, p)| {
            score = score.saturating_add(u64::from(p.weight));
            PreferenceEvidence {
                index,
                weight: p.weight,
                constraint: leaf_name(&p.constraint),
            }
        })
        .collect();
    MatchEvidence {
        eligible: failed.is_empty(),
        preference_score: score,
        failed_constraints: failed,
        matched_preferences,
    }
}

fn normalize_name(value: String) -> String {
    value.trim().to_ascii_lowercase()
}
fn normalize_os(value: String) -> String {
    match normalize_name(value).as_str() {
        "darwin" | "mac" | "macosx" => "macos".into(),
        v => v.into(),
    }
}
fn normalize_arch(value: String) -> String {
    match normalize_name(value).as_str() {
        "amd64" | "x64" => "x86_64".into(),
        "arm64" => "aarch64".into(),
        v => v.into(),
    }
}
fn normalize_names(values: &mut Vec<String>) -> Result<()> {
    for v in values.iter_mut() {
        *v = normalize_name(std::mem::take(v));
        if v.is_empty() {
            bail!("named capability requirements cannot be empty")
        }
    }
    values.sort();
    values.dedup();
    Ok(())
}
fn normalize_leaf(leaf: &mut LeafConstraint) -> Result<()> {
    match leaf {
        LeafConstraint::Os { value } => *value = normalize_os(std::mem::take(value)),
        LeafConstraint::Architecture { value } => *value = normalize_arch(std::mem::take(value)),
        LeafConstraint::GpuVendor { value } | LeafConstraint::GpuModel { value } => {
            *value = normalize_name(std::mem::take(value))
        }
        LeafConstraint::RuntimeExact { runtime, version } => {
            *runtime = normalize_name(std::mem::take(runtime));
            *version = version.trim().into();
            if runtime.is_empty() || version.is_empty() {
                bail!("runtime preferences need non-empty runtime and version")
            }
        }
        LeafConstraint::Tool { name }
        | LeafConstraint::Harness { name }
        | LeafConstraint::WorkspaceDriver { name } => {
            *name = normalize_name(std::mem::take(name));
            if name.is_empty() {
                bail!("named preferences cannot be empty")
            }
        }
        LeafConstraint::ExecutorProtocol { any_of }
        | LeafConstraint::WorkspaceDriverProtocol { any_of }
        | LeafConstraint::HarnessHostProtocol { any_of } => {
            any_of.sort_unstable();
            any_of.dedup();
            if any_of.is_empty() {
                bail!("protocol preferences need a version")
            }
        }
        _ => {}
    }
    Ok(())
}
fn failure(name: &str, expected: Value, actual: Value) -> ConstraintEvidence {
    ConstraintEvidence {
        constraint: name.into(),
        expected,
        actual,
    }
}
fn optional_eq(f: &mut Vec<ConstraintEvidence>, name: &str, want: Option<&str>, got: &str) {
    if want.is_some_and(|v| v != got) {
        f.push(failure(name, json!(want), json!(got)))
    }
}
fn minimum(f: &mut Vec<ConstraintEvidence>, name: &str, want: u64, got: u64) {
    if got < want {
        f.push(failure(name, json!({"min":want}), json!(got)))
    }
}
fn has(values: &[String], want: &str) -> bool {
    values.iter().any(|v| normalize_name(v.clone()) == want)
}
fn names(f: &mut Vec<ConstraintEvidence>, kind: &str, want: &[String], got: &[String]) {
    for item in want {
        if !has(got, item) {
            f.push(failure(
                &format!("{kind}:{item}"),
                json!(true),
                json!(false),
            ))
        }
    }
}
fn protocol(f: &mut Vec<ConstraintEvidence>, name: &str, want: &[u16], got: &[u16]) {
    if !want.is_empty() && !want.iter().any(|v| got.contains(v)) {
        f.push(failure(name, json!({"anyOf":want}), json!(got)))
    }
}
fn runtime_versions(c: &NodeCapabilities, name: &str) -> Vec<String> {
    c.runtimes
        .iter()
        .find(|(k, _)| normalize_name((*k).clone()) == name)
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}
fn runtime_exact(c: &NodeCapabilities, name: &str, version: &str) -> bool {
    runtime_versions(c, name)
        .iter()
        .any(|v| v.trim() == version)
}
fn intersects(a: &[u16], b: &[u16]) -> bool {
    !a.is_empty() && a.iter().any(|v| b.contains(v))
}
fn leaf_matches(l: &LeafConstraint, c: &NodeCapabilities) -> bool {
    match l {
        LeafConstraint::Os { value } => normalize_os(c.platform.os.clone()) == *value,
        LeafConstraint::Architecture { value } => {
            normalize_arch(c.platform.architecture.clone()) == *value
        }
        LeafConstraint::MinCpuCores { value } => c.resources.cpu_cores >= *value,
        LeafConstraint::MinMemoryBytes { value } => c.resources.memory_bytes >= *value,
        LeafConstraint::GpuVendor { value } => c
            .gpu
            .as_ref()
            .is_some_and(|g| normalize_name(g.vendor.clone()) == *value),
        LeafConstraint::GpuModel { value } => c
            .gpu
            .as_ref()
            .is_some_and(|g| normalize_name(g.model.clone()) == *value),
        LeafConstraint::MinGpuMemoryBytes { value } => {
            c.gpu.as_ref().is_some_and(|g| g.memory_bytes >= *value)
        }
        LeafConstraint::RuntimeExact { runtime, version } => runtime_exact(c, runtime, version),
        LeafConstraint::Tool { name } => has(&c.tools, name),
        LeafConstraint::Harness { name } => has(&c.harnesses, name),
        LeafConstraint::WorkspaceDriver { name } => has(&c.workspace_drivers, name),
        LeafConstraint::ExecutorProtocol { any_of } => intersects(any_of, &c.protocols.executor),
        LeafConstraint::WorkspaceDriverProtocol { any_of } => {
            intersects(any_of, &c.protocols.workspace_driver)
        }
        LeafConstraint::HarnessHostProtocol { any_of } => {
            intersects(any_of, &c.protocols.harness_host)
        }
    }
}
fn leaf_name(l: &LeafConstraint) -> String {
    match l {
        LeafConstraint::Os { .. } => "os".into(),
        LeafConstraint::Architecture { .. } => "architecture".into(),
        LeafConstraint::MinCpuCores { .. } => "cpu-cores".into(),
        LeafConstraint::MinMemoryBytes { .. } => "memory-bytes".into(),
        LeafConstraint::GpuVendor { .. } => "gpu-vendor".into(),
        LeafConstraint::GpuModel { .. } => "gpu-model".into(),
        LeafConstraint::MinGpuMemoryBytes { .. } => "gpu-memory-bytes".into(),
        LeafConstraint::RuntimeExact { runtime, .. } => format!("runtime:{runtime}"),
        LeafConstraint::Tool { name } => format!("tool:{name}"),
        LeafConstraint::Harness { name } => format!("harness:{name}"),
        LeafConstraint::WorkspaceDriver { name } => format!("workspace-driver:{name}"),
        LeafConstraint::ExecutorProtocol { .. } => "protocol:executor".into(),
        LeafConstraint::WorkspaceDriverProtocol { .. } => "protocol:workspace-driver".into(),
        LeafConstraint::HarnessHostProtocol { .. } => "protocol:harness-host".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::{
        GpuCapability, PlatformCapabilities, ProtocolCapabilities, ResourceCapabilities,
    };
    use std::collections::BTreeMap;
    fn c(node: &str, os: &str, arch: &str) -> PlacementCandidate {
        PlacementCandidate {
            node_id: node.into(),
            observation_id: format!("obs-{node}"),
            fresh: true,
            available: true,
            queue_pressure: 0,
            capabilities: NodeCapabilities {
                protocols: ProtocolCapabilities {
                    executor: vec![1],
                    workspace_driver: vec![1],
                    harness_host: vec![1],
                },
                platform: PlatformCapabilities {
                    os: os.into(),
                    architecture: arch.into(),
                    version: "test".into(),
                },
                resources: ResourceCapabilities {
                    cpu_cores: 8,
                    memory_bytes: 16_000_000_000,
                },
                gpu: None,
                runtimes: BTreeMap::from([("node".into(), vec!["22.4.0".into()])]),
                harnesses: vec!["fake".into()],
                workspace_drivers: vec!["filesystem".into()],
                tools: vec!["shell".into(), "cargo".into()],
            },
        }
    }
    #[test]
    fn platform_matrix() -> Result<()> {
        let cs = vec![
            c("linux", "linux", "x86_64"),
            c("windows", "windows", "amd64"),
            c("mac-intel", "macos", "x86_64"),
            c("mac-arm", "darwin", "arm64"),
        ];
        for (os, arch, want) in [
            ("linux", "amd64", "linux"),
            ("windows", "x86_64", "windows"),
            ("macos", "x86_64", "mac-intel"),
            ("macos", "aarch64", "mac-arm"),
        ] {
            let r = PlacementRequest {
                required: HardConstraints {
                    os: Some(os.into()),
                    architecture: Some(arch.into()),
                    ..Default::default()
                },
                ..Default::default()
            };
            let got = rank(&r, cs.clone())?;
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].node_id, want)
        }
        Ok(())
    }
    #[test]
    fn gpu_resources_versions_and_protocol_intersections() -> Result<()> {
        let mut n = c("gpu", "linux", "x86_64");
        n.capabilities.gpu = Some(GpuCapability {
            vendor: "NVIDIA".into(),
            model: "RTX 4090".into(),
            memory_bytes: 24_000_000_000,
        });
        let r = PlacementRequest {
            required: HardConstraints {
                min_cpu_cores: 8,
                min_memory_bytes: 12_000_000_000,
                gpu: Some(GpuRequirement {
                    vendor: Some("nvidia".into()),
                    model: Some("rtx 4090".into()),
                    min_memory_bytes: 20_000_000_000,
                }),
                runtimes: vec![ExactRuntimeRequirement {
                    runtime: "node".into(),
                    version: "22.4.0".into(),
                }],
                tools: vec!["cargo".into()],
                harnesses: vec!["fake".into()],
                workspace_drivers: vec!["filesystem".into()],
                protocols: ProtocolRequirements {
                    executor: vec![1, 2],
                    workspace_driver: vec![1],
                    harness_host: vec![1],
                },
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(evaluate(&r, &n)?.eligible);
        n.capabilities.resources.memory_bytes = 4;
        n.capabilities.protocols.workspace_driver = vec![2];
        let e = evaluate(&r, &n)?;
        assert!(!e.eligible);
        assert!(e
            .failed_constraints
            .iter()
            .any(|x| x.constraint == "memory-bytes"));
        assert!(e
            .failed_constraints
            .iter()
            .any(|x| x.constraint == "protocol:workspace-driver"));
        Ok(())
    }
    #[test]
    fn stale_and_unavailable_are_ineligible() -> Result<()> {
        let mut a = c("stale", "linux", "x86_64");
        a.fresh = false;
        let mut b = c("down", "linux", "x86_64");
        b.available = false;
        assert!(rank(&PlacementRequest::default(), vec![a, b])?.is_empty());
        Ok(())
    }
    #[test]
    fn preference_pressure_and_node_ties_are_deterministic() -> Result<()> {
        let r = PlacementRequest {
            preferred: vec![
                WeightedPreference {
                    weight: 10,
                    constraint: LeafConstraint::GpuVendor {
                        value: "nvidia".into(),
                    },
                },
                WeightedPreference {
                    weight: 3,
                    constraint: LeafConstraint::Architecture {
                        value: "arm64".into(),
                    },
                },
            ],
            ..Default::default()
        };
        let mut gpu = c("z-gpu", "linux", "x86_64");
        gpu.queue_pressure = 99;
        gpu.capabilities.gpu = Some(GpuCapability {
            vendor: "NVIDIA".into(),
            model: "x".into(),
            memory_bytes: 1,
        });
        let arm = c("arm", "macos", "aarch64");
        let mut b = c("b", "linux", "x86_64");
        b.queue_pressure = 1;
        let mut a = c("a", "linux", "x86_64");
        a.queue_pressure = 1;
        let got = rank(&r, vec![b, arm, gpu, a])?;
        assert_eq!(
            got.iter().map(|x| x.node_id.as_str()).collect::<Vec<_>>(),
            vec!["z-gpu", "arm", "a", "b"]
        );
        Ok(())
    }
}
