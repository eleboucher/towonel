use std::net::{IpAddr, SocketAddr};

use anyhow::Context;
use k8s_openapi::api::core::v1::{Node, Service};
use kube::{Api, Client};
use tracing::{info, warn};

const NAMESPACE_FILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
const DEFAULT_SERVICE: &str = "towonel-agent";

/// Discover NodePort-based direct addresses by combining this pod's host
/// `Node` IPs with the UDP nodePorts of the agent `Service`. Opportunistic:
/// any failure is logged and produces an empty result so startup proceeds.
pub async fn discover() -> Vec<SocketAddr> {
    if !env_truthy("TOWONEL_AGENT_K8S_AUTODISCOVER") {
        return Vec::new();
    }

    let node_name = match std::env::var("NODE_NAME") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            warn!("k8s autodiscovery enabled but NODE_NAME not set (downward API); skipping");
            return Vec::new();
        }
    };
    let namespace = match read_namespace() {
        Ok(ns) => ns,
        Err(e) => {
            warn!(error = %e, "k8s autodiscovery: could not resolve namespace; skipping");
            return Vec::new();
        }
    };
    let service_name =
        std::env::var("TOWONEL_AGENT_K8S_SERVICE").unwrap_or_else(|_| DEFAULT_SERVICE.to_string());

    match discover_inner(&node_name, &namespace, &service_name).await {
        Ok(addrs) => {
            info!(
                count = addrs.len(),
                node = node_name,
                namespace,
                service = service_name,
                "k8s autodiscovery succeeded"
            );
            addrs
        }
        Err(e) => {
            warn!(error = %e, "k8s autodiscovery failed; returning no addresses");
            Vec::new()
        }
    }
}

async fn discover_inner(
    node_name: &str,
    namespace: &str,
    service_name: &str,
) -> anyhow::Result<Vec<SocketAddr>> {
    let client = Client::try_default()
        .await
        .context("failed to build k8s client (try_default)")?;

    let nodes: Api<Node> = Api::all(client.clone());
    let node = nodes
        .get(node_name)
        .await
        .with_context(|| format!("failed to GET Node {node_name}"))?;

    let ips = node_addresses(&node);
    if ips.is_empty() {
        warn!(node = node_name, "node has no usable ExternalIP/InternalIP");
        return Ok(Vec::new());
    }

    let services: Api<Service> = Api::namespaced(client, namespace);
    let svc = services
        .get(service_name)
        .await
        .with_context(|| format!("failed to GET Service {namespace}/{service_name}"))?;

    let node_ports = service_udp_node_ports(&svc);
    if node_ports.is_empty() {
        warn!(
            namespace,
            service = service_name,
            "service has no UDP nodePorts"
        );
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(ips.len() * node_ports.len());
    for ip in &ips {
        for port in &node_ports {
            out.push(SocketAddr::new(*ip, *port));
        }
    }
    Ok(out)
}

fn node_addresses(node: &Node) -> Vec<IpAddr> {
    let Some(status) = node.status.as_ref() else {
        return Vec::new();
    };
    let Some(addrs) = status.addresses.as_ref() else {
        return Vec::new();
    };
    // ExternalIP first, then InternalIP. v4 and v6 both kept.
    let mut external = Vec::new();
    let mut internal = Vec::new();
    for addr in addrs {
        let Ok(ip) = addr.address.parse::<IpAddr>() else {
            continue;
        };
        match addr.type_.as_str() {
            "ExternalIP" => external.push(ip),
            "InternalIP" => internal.push(ip),
            _ => {}
        }
    }
    external.extend(internal);
    external
}

fn service_udp_node_ports(svc: &Service) -> Vec<u16> {
    let Some(spec) = svc.spec.as_ref() else {
        return Vec::new();
    };
    let Some(ports) = spec.ports.as_ref() else {
        return Vec::new();
    };
    ports
        .iter()
        .filter(|p| p.protocol.as_deref() == Some("UDP"))
        .filter_map(|p| p.node_port)
        .filter(|np| *np > 0)
        .filter_map(|np| u16::try_from(np).ok())
        .collect()
}

fn read_namespace() -> anyhow::Result<String> {
    if let Ok(v) = std::env::var("TOWONEL_AGENT_K8S_NAMESPACE")
        && !v.is_empty()
    {
        return Ok(v);
    }
    if let Ok(v) = std::env::var("POD_NAMESPACE")
        && !v.is_empty()
    {
        return Ok(v);
    }
    let contents = std::fs::read_to_string(NAMESPACE_FILE).with_context(|| {
        format!("k8s autodiscovery: namespace not provided and {NAMESPACE_FILE} could not be read")
    })?;
    let ns = contents.trim().to_string();
    if ns.is_empty() {
        anyhow::bail!("k8s autodiscovery: {NAMESPACE_FILE} is empty");
    }
    Ok(ns)
}

fn env_truthy(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref().map(str::trim),
        Ok("true" | "TRUE" | "True" | "1")
    )
}
