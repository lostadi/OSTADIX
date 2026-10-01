//! Deterministic, non-authorizing grounding for one exact hosted project plan.
//!
//! The report is derived from a trusted [`ProjectHGraph`], its canonical
//! [`LogicalHGraphV1`], and the exact hosted-unbound [`DeploymentPlanV1`]. It
//! validates the identity and authority relationship between those records,
//! but never creates a World task, chooses a provider, grants authority, or
//! dispatches project code.

use anyhow::{bail, Context, Result};

use crate::world::ArtifactId;

use super::deployment::{DeploymentOperationBindingV1, DeploymentPlanV1};
use super::logical::LogicalHGraphV1;
use super::plan::ProjectHGraph;

/// A validated, typed grounding view for one exact hosted project HGraph.
///
/// The logical and deployment records are kept private so callers cannot
/// invalidate the cross-record checks after construction. Read-only accessors
/// expose the canonical records and their exact semantic identities.
#[derive(Debug)]
pub struct ProjectGroundingReport {
    project_text: String,
    logical: LogicalHGraphV1,
    logical_sha256: ArtifactId,
    deployment: DeploymentPlanV1,
    deployment_sha256: ArtifactId,
    residual_host_world: bool,
    authority_requirements_absent: bool,
    non_authorizing: bool,
}

impl ProjectGroundingReport {
    /// Derive and validate grounding from one trusted project plan/HGraph.
    ///
    /// This operation is deterministic and inspection-only. It does not
    /// materialize the project, inspect providers, allocate state, or execute
    /// any project route.
    pub fn from_trusted_project(project: &ProjectHGraph) -> Result<Self> {
        let logical = project
            .logical_v1()
            .context("failed to normalize LogicalHGraphV1")?;
        logical
            .validate_trusted_project(project)
            .context("LogicalHGraphV1 does not match the selected project HGraph")?;
        let logical_sha256 = logical
            .digest()
            .context("failed to digest LogicalHGraphV1")?;

        let deployment = DeploymentPlanV1::hosted(&logical)
            .context("failed to construct hosted DeploymentPlanV1")?;
        deployment
            .validate_trusted_hosted(&logical)
            .context("DeploymentPlanV1 does not match the selected LogicalHGraphV1")?;
        let deployment_sha256 = deployment
            .digest()
            .context("failed to digest hosted DeploymentPlanV1")?;

        if logical.operations.len() != deployment.operations.len() {
            bail!(
                "hosted DeploymentPlanV1 has {} operations for {} logical operations",
                deployment.operations.len(),
                logical.operations.len()
            );
        }
        for (logical_operation, deployment_operation) in
            logical.operations.iter().zip(&deployment.operations)
        {
            if logical_operation.id != deployment_operation.logical_operation {
                bail!(
                    "hosted deployment operation L{} does not match logical operation L{}",
                    deployment_operation.logical_operation.0,
                    logical_operation.id.0
                );
            }
            if logical_operation.authority_requirements
                != deployment_operation.requirements.authority
            {
                bail!(
                    "hosted deployment authority requirements for L{} do not match the logical graph",
                    logical_operation.id.0
                );
            }
        }

        let residual_host_world = deployment
            .operations
            .iter()
            .any(|operation| operation.requirements.residual_host_world);
        let authority_requirements_absent = deployment
            .operations
            .iter()
            .all(|operation| operation.requirements.authority.is_empty());
        let non_authorizing = deployment.world.is_none()
            && deployment.placement_snapshot.is_none()
            && deployment.selected_provider.is_none()
            && deployment.eligible_alternatives.is_empty()
            && deployment.rejected_providers.is_empty()
            && deployment.operations.iter().all(|operation| {
                operation.task.is_none()
                    && matches!(
                        &operation.binding,
                        DeploymentOperationBindingV1::HostedCoordinator
                            | DeploymentOperationBindingV1::AmbientHost
                            | DeploymentOperationBindingV1::Unresolved { .. }
                    )
            });

        Ok(Self {
            project_text: project.to_text(),
            logical,
            logical_sha256,
            deployment,
            deployment_sha256,
            residual_host_world,
            authority_requirements_absent,
            non_authorizing,
        })
    }

    pub const fn logical_hgraph(&self) -> &LogicalHGraphV1 {
        &self.logical
    }

    pub const fn deployment_plan(&self) -> &DeploymentPlanV1 {
        &self.deployment
    }

    pub const fn logical_sha256(&self) -> &ArtifactId {
        &self.logical_sha256
    }

    pub const fn deployment_sha256(&self) -> &ArtifactId {
        &self.deployment_sha256
    }

    pub const fn residual_host_world(&self) -> bool {
        self.residual_host_world
    }

    /// True when the descriptive hosted plan declares no authority
    /// requirements. This is distinct from whether the inspection itself
    /// carries or grants live authority.
    pub const fn authority_requirements_absent(&self) -> bool {
        self.authority_requirements_absent
    }

    /// True when the report and its hosted-unbound deployment contain no
    /// World, placement, provider, task, or other live authority binding.
    pub const fn non_authorizing(&self) -> bool {
        self.non_authorizing
    }

    /// Render the stable text shared by `olangc --target ir --grounding` and
    /// `o plan PROJECT --grounding`.
    pub fn to_text(&self) -> Result<String> {
        let mut output = format!(
            "; LogicalHGraphV1\nlogical schema={} sha256={}\n; DeploymentPlanV1\ndeployment schema={} sha256={}\n{}{}\n; Project grounding inspection (bounded)\ngrounding logical-schema={} logical-sha256={} deployment-schema={} deployment-sha256={}\n",
            self.logical.schema_version,
            self.logical_sha256.as_sha256(),
            self.deployment.schema_version,
            self.deployment_sha256.as_sha256(),
            self.project_text,
            self.deployment.to_text(),
            self.logical.schema_version,
            self.logical_sha256.as_sha256(),
            self.deployment.schema_version,
            self.deployment_sha256.as_sha256(),
        );

        for (logical_operation, deployment_operation) in self
            .logical
            .operations
            .iter()
            .zip(&self.deployment.operations)
        {
            let kind = serde_json::to_string(&logical_operation.kind)
                .context("failed to serialize logical operation kind")?;
            let effects = serde_json::to_string(&logical_operation.effects)
                .context("failed to serialize logical operation effects")?;
            let authority = serde_json::to_string(&logical_operation.authority_requirements)
                .context("failed to serialize logical authority requirements")?;
            let binding = serde_json::to_string(&deployment_operation.binding)
                .context("failed to serialize deployment operation binding")?;
            output.push_str(&format!(
                "grounding-operation logical-id=L{} logical-kind={} logical-effects={} authority-requirements={} deployment-binding={} deployment-residual-host-world={}\n",
                logical_operation.id.0,
                kind,
                effects,
                authority,
                binding,
                deployment_operation.requirements.residual_host_world,
            ));
        }

        output.push_str(&format!(
            "grounding-summary residual-host-world={} authority-requirements-absent={} non-authorizing={} placement=hosted-unbound world=none placement-snapshot=none selected-provider=none\n",
            self.residual_host_world,
            self.authority_requirements_absent,
            self.non_authorizing,
        ));
        output.push_str(
            "grounding-nonclaim authority=requirements are descriptive only; this inspection grants no capability or execution authority\n",
        );
        output.push_str(
            "grounding-nonclaim hostworld=residual HostWorld records ambient hosted effects; its absence would not prove complete mediation\n",
        );
        output.push_str(
            "grounding-nonclaim placement=the hosted-unbound plan proves no placement, provider admission, reservation, dispatch, runtime instantiation, or route execution\n",
        );
        output.push_str(
            "grounding-scope bounded-project-grounding=true full-pr9-authority-locality-failure-why=false\n",
        );
        Ok(output)
    }
}
