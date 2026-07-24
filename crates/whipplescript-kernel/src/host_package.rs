//! Placement-neutral authored agent packages for governed host runtimes.
//!
//! Package identity, compilation, capability validation, and model-facing tool
//! schemas must be identical on native and Durable Object placements. Hosts may
//! resolve the immutable document bytes differently, but they do not get a
//! second package interpretation.

#[cfg(feature = "native")]
use std::fs;
#[cfg(feature = "native")]
use std::path::{Component, Path};

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::harness_loop::ToolSpec;
use crate::host_protocol::HOST_PROTOCOL;
use whipplescript_parser::IrProgram;

pub const AGENT_PACKAGE_MANIFEST: &str = "package.json";
pub const AGENT_PACKAGE_SCHEMA: &str = "whipplescript.agent_package.v0";

#[derive(Clone, Debug)]
pub struct AuthoredAgentPackage {
    version_ref: String,
    manifest: String,
    source: String,
    workflow: String,
    agent: String,
    system_prompt: String,
    capabilities: Vec<String>,
    agent_abilities: Vec<String>,
    max_steps: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredAgentPackageManifest {
    schema: String,
    source: String,
    workflow: String,
    agent: String,
    system_prompt: String,
    capabilities: Vec<String>,
    agent_abilities: Vec<String>,
    max_steps: usize,
}

impl AuthoredAgentPackage {
    pub fn from_documents(
        manifest_text: impl Into<String>,
        source: impl Into<String>,
        system_prompt: impl Into<String>,
    ) -> Result<Self, String> {
        let manifest_text = manifest_text.into();
        let manifest: AuthoredAgentPackageManifest = serde_json::from_str(&manifest_text)
            .map_err(|error| format!("invalid agent package manifest: {error}"))?;
        if manifest.schema != AGENT_PACKAGE_SCHEMA {
            return Err(format!(
                "unsupported agent package schema `{}`",
                manifest.schema
            ));
        }
        Self::from_parts(manifest_text, manifest, source.into(), system_prompt.into())
    }

    #[cfg(feature = "native")]
    pub fn load(root: impl AsRef<Path>) -> Result<Self, String> {
        let root = root
            .as_ref()
            .canonicalize()
            .map_err(|error| format!("cannot open agent package: {error}"))?;
        if !root.is_dir() {
            return Err("agent package root is not a directory".to_owned());
        }
        let manifest_text = read_package_child(&root, AGENT_PACKAGE_MANIFEST)?;
        let manifest: AuthoredAgentPackageManifest = serde_json::from_str(&manifest_text)
            .map_err(|error| format!("invalid agent package manifest: {error}"))?;
        let source = read_package_child(&root, &manifest.source)?;
        let system_prompt = read_package_child(&root, &manifest.system_prompt)?;
        Self::from_documents(manifest_text, source, system_prompt)
    }

    fn from_parts(
        manifest_text: String,
        manifest: AuthoredAgentPackageManifest,
        source: String,
        system_prompt: String,
    ) -> Result<Self, String> {
        if manifest.workflow.trim().is_empty()
            || manifest.agent.trim().is_empty()
            || system_prompt.trim().is_empty()
            || manifest.max_steps == 0
        {
            return Err(
                "agent package requires workflow, agent, persona, and positive max_steps"
                    .to_owned(),
            );
        }
        let mut capabilities = manifest.capabilities;
        capabilities.sort();
        capabilities.dedup();
        for capability in &capabilities {
            if !matches!(
                capability.as_str(),
                "workspace.read" | "workspace.write" | "command.run"
            ) {
                return Err(format!(
                    "agent package declares unsupported capability `{capability}`"
                ));
            }
        }
        if capabilities.iter().any(|item| item == "workspace.write")
            && !capabilities.iter().any(|item| item == "workspace.read")
        {
            return Err("workspace.write requires workspace.read".to_owned());
        }
        let mut agent_abilities = manifest.agent_abilities;
        agent_abilities.sort();
        agent_abilities.dedup();
        for ability in &agent_abilities {
            if !capabilities.contains(ability) {
                return Err(format!(
                    "agent ability `{ability}` is absent from the package capability registry"
                ));
            }
        }
        if agent_abilities
            .iter()
            .any(|item| item == "workspace.write" || item == "command.run")
            && !agent_abilities.iter().any(|item| item == "workspace.read")
        {
            return Err(
                "workspace.write and command.run abilities require workspace.read".to_owned(),
            );
        }
        if agent_abilities.iter().any(|item| item == "command.run")
            && !agent_abilities.iter().any(|item| item == "workspace.write")
        {
            return Err(
                "command.run ability is write-capable and requires workspace.write".to_owned(),
            );
        }

        let compiled = whipplescript_parser::compile_program_with_root(
            &source,
            Some(manifest.workflow.as_str()),
        );
        let program = compiled.ir.ok_or_else(|| {
            compiled
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.message.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        })?;
        let declared_agent = program
            .agents
            .iter()
            .find(|agent| agent.name == manifest.agent)
            .ok_or_else(|| format!("agent package has no agent `{}`", manifest.agent))?;
        let mut source_capabilities = declared_agent.capabilities.clone();
        source_capabilities.sort();
        source_capabilities.dedup();
        if source_capabilities != capabilities {
            return Err(format!(
                "agent `{}` capabilities do not match the package capability registry",
                manifest.agent
            ));
        }

        let identity = json!({
            "manifest": &manifest_text,
            "source": &source,
            "system_prompt": &system_prompt,
        });
        let version_ref = format!(
            "whip:agent-package:{}",
            sha256_hex(identity.to_string().as_bytes())
        );
        Ok(Self {
            version_ref,
            manifest: manifest_text,
            source,
            workflow: manifest.workflow,
            agent: manifest.agent,
            system_prompt,
            capabilities,
            agent_abilities,
            max_steps: manifest.max_steps,
        })
    }

    pub fn version_ref(&self) -> &str {
        &self.version_ref
    }

    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    pub fn agent_abilities(&self) -> &[String] {
        &self.agent_abilities
    }

    /// Exact authored documents whose content hash produced [`Self::version_ref`].
    /// Hosted placements transmit these bytes to the governed host; they must
    /// never reconstruct a manifest or persona from the compiled projection.
    pub fn manifest_document(&self) -> &str {
        &self.manifest
    }

    pub fn source_document(&self) -> &str {
        &self.source
    }

    pub fn system_prompt_document(&self) -> &str {
        &self.system_prompt
    }

    pub fn resolve(&self, version_ref: &str) -> Result<ResolvedPackage, String> {
        if version_ref != self.version_ref {
            return Err("agent package bytes do not match the pinned version ref".to_owned());
        }
        let readable = self
            .agent_abilities
            .iter()
            .any(|item| item == "workspace.read");
        let writable = self
            .agent_abilities
            .iter()
            .any(|item| item == "workspace.write");
        let command = self
            .agent_abilities
            .iter()
            .any(|item| item == "command.run");
        ResolvedPackage::compile_with_capabilities(
            self.version_ref.clone(),
            &self.source,
            Some(&self.workflow),
            self.agent.clone(),
            self.system_prompt.clone(),
            workspace_tool_specs_from_registry(readable, writable, command, false),
            self.max_steps,
            self.agent_abilities.clone(),
        )
    }
}

impl PackageResolver for AuthoredAgentPackage {
    fn resolve_package(&self, version_ref: &str) -> Result<ResolvedPackage, String> {
        self.resolve(version_ref)
    }
}

#[cfg(feature = "native")]
fn read_package_child(root: &Path, relative: &str) -> Result<String, String> {
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative.components().count() != 1
        || !matches!(relative.components().next(), Some(Component::Normal(_)))
    {
        return Err("agent package file references must name direct children".to_owned());
    }
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot read agent package file: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("agent package files must be regular, non-symlink files".to_owned());
    }
    fs::read_to_string(path).map_err(|error| format!("cannot read agent package file: {error}"))
}

#[derive(Clone, Debug)]
pub struct ResolvedPackage {
    pub version_ref: String,
    pub source_hash: String,
    pub ir_hash: String,
    pub agent: String,
    pub system_prompt: String,
    pub tools: Vec<ToolSpec>,
    pub capabilities: Vec<String>,
    pub max_steps: usize,
    pub program: IrProgram,
}

impl ResolvedPackage {
    #[allow(clippy::too_many_arguments)]
    pub fn compile(
        version_ref: impl Into<String>,
        source: &str,
        root: Option<&str>,
        agent: impl Into<String>,
        system_prompt: impl Into<String>,
        tools: Vec<ToolSpec>,
        max_steps: usize,
    ) -> Result<Self, String> {
        Self::compile_with_capabilities(
            version_ref,
            source,
            root,
            agent,
            system_prompt,
            tools,
            max_steps,
            Vec::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn compile_with_capabilities(
        version_ref: impl Into<String>,
        source: &str,
        root: Option<&str>,
        agent: impl Into<String>,
        system_prompt: impl Into<String>,
        tools: Vec<ToolSpec>,
        max_steps: usize,
        mut capabilities: Vec<String>,
    ) -> Result<Self, String> {
        let compiled = whipplescript_parser::compile_program_with_root(source, root);
        let program = compiled.ir.ok_or_else(|| {
            compiled
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.message.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        })?;
        let agent = agent.into();
        let system_prompt = system_prompt.into();
        let tool_identity = tools
            .iter()
            .map(|tool| {
                json!({
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                })
            })
            .collect::<Vec<_>>();
        capabilities.sort();
        capabilities.dedup();
        let package_identity = json!({
            "source": source,
            "root": root,
            "agent": &agent,
            "system_prompt": &system_prompt,
            "tools": tool_identity,
            "max_steps": max_steps,
            "capabilities": &capabilities,
        });
        let source_hash = sha256_hex(package_identity.to_string().as_bytes());
        let ir_hash = sha256_hex(
            format!("{}:{}:{}", source_hash, program.workflow, HOST_PROTOCOL).as_bytes(),
        );
        Ok(Self {
            version_ref: version_ref.into(),
            source_hash,
            ir_hash,
            agent,
            system_prompt,
            tools,
            capabilities,
            max_steps,
            program,
        })
    }
}

pub trait PackageResolver {
    fn resolve_package(&self, version_ref: &str) -> Result<ResolvedPackage, String>;
}

pub fn workspace_tool_specs(writable: bool) -> Vec<ToolSpec> {
    workspace_tool_specs_with_capabilities(writable, false, false)
}

pub fn workspace_tool_specs_with_command(writable: bool, command_execution: bool) -> Vec<ToolSpec> {
    workspace_tool_specs_with_capabilities(writable, command_execution, false)
}

pub fn workspace_tool_specs_with_capabilities(
    writable: bool,
    command_execution: bool,
    human_interaction: bool,
) -> Vec<ToolSpec> {
    workspace_tool_specs_from_registry(true, writable, command_execution, human_interaction)
}

pub fn workspace_tool_specs_from_registry(
    readable: bool,
    writable: bool,
    command_execution: bool,
    human_interaction: bool,
) -> Vec<ToolSpec> {
    let mut tools = Vec::new();
    if readable {
        tools.extend([
            tool_spec("read", "Read a workspace text file.", json!({"type":"object","properties":{"path":{"type":"string"},"offset":{"type":"integer"},"limit":{"type":"integer"}},"required":["path"],"additionalProperties":false})),
            tool_spec("grep", "Search text in workspace files.", json!({"type":"object","properties":{"pattern":{"type":"string"},"path":{"type":"string"}},"required":["pattern"],"additionalProperties":false})),
            tool_spec("find", "Find workspace paths by wildcard pattern.", json!({"type":"object","properties":{"pattern":{"type":"string"},"path":{"type":"string"}},"required":["pattern"],"additionalProperties":false})),
            tool_spec("ls", "List a workspace directory.", json!({"type":"object","properties":{"path":{"type":"string"}},"additionalProperties":false})),
        ]);
    }
    if writable {
        tools.extend([
            tool_spec("write", "Create or replace a workspace text file.", json!({"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"],"additionalProperties":false})),
            tool_spec("edit", "Apply exact, unique string replacements.", json!({"type":"object","properties":{"path":{"type":"string"},"edits":{"type":"array","items":{"type":"object","properties":{"oldText":{"type":"string"},"newText":{"type":"string"}},"required":["oldText","newText"],"additionalProperties":false}}},"required":["path","edits"],"additionalProperties":false})),
        ]);
    }
    if command_execution {
        tools.push(tool_spec(
            "bash",
            "Run governed virtual bash over the placement workspace.",
            json!({"type":"object","properties":{"command":{"type":"string"},"timeout":{"type":"integer","minimum":1}},"required":["command"],"additionalProperties":false}),
        ));
    }
    if human_interaction {
        tools.push(tool_spec(
            "ask_human",
            "Pause this turn for one attributable human answer under the current policy epoch.",
            json!({"type":"object","properties":{"question":{"type":"string","minLength":1,"maxLength":10000},"choices":{"type":"array","maxItems":20,"items":{"type":"string","minLength":1,"maxLength":256}},"freeform_allowed":{"type":"boolean"}},"required":["question"],"additionalProperties":false}),
        ));
    }
    tools
}

fn tool_spec(name: &str, description: &str, input_schema: Value) -> ToolSpec {
    ToolSpec {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_lower(&digest)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authored_package_is_placement_neutral_and_bash_is_virtual() {
        let source = r#"
workflow Chat {
  agent assistant {
    provider owned
    profile "repo-writer"
    capacity 1
    capabilities ["workspace.read", "workspace.write", "command.run"]
  }
}
"#;
        let manifest = json!({
            "schema": AGENT_PACKAGE_SCHEMA,
            "source": "agent.whip",
            "workflow": "Chat",
            "agent": "assistant",
            "system_prompt": "persona.md",
            "capabilities": ["workspace.read", "workspace.write", "command.run"],
            "agent_abilities": ["workspace.read", "workspace.write", "command.run"],
            "max_steps": 12
        });
        let package =
            AuthoredAgentPackage::from_documents(manifest.to_string(), source, "Be useful.")
                .expect("package");
        let resolved = package.resolve(package.version_ref()).expect("resolved");
        let bash = resolved
            .tools
            .iter()
            .find(|tool| tool.name == "bash")
            .expect("bash");
        assert!(bash.description.contains("virtual bash"));
    }
}
