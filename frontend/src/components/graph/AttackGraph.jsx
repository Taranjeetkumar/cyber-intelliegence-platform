import { useEffect, useRef } from "react";
import { Network } from "vis-network";
import { DataSet } from "vis-data";
import { useDispatch } from "react-redux";
import { setSelectedNode } from "../../features/investigation/investigationSlice";

const DAY_GROUP_STYLES = {
  IP: { shape: "box", size: 30, background: "#DBEAFE", border: "#2563EB", font: "#0F3B8F" },
  Domain: { shape: "box", size: 24, background: "#DCFCE7", border: "#16A34A", font: "#14532D" },
  Malware: { shape: "box", size: 24, background: "#FFE4E6", border: "#E11D48", font: "#881337" },
  CVE: { shape: "box", size: 24, background: "#FEF3C7", border: "#D97706", font: "#78350F" },
  Exploit: { shape: "box", size: 24, background: "#FEE2E2", border: "#DC2626", font: "#7F1D1D" },
  Campaign: { shape: "database", size: 24, background: "#EDE9FE", border: "#7C3AED", font: "#4C1D95" },
  ThreatActor: { shape: "box", size: 24, background: "#FCE7F3", border: "#DB2777", font: "#831843" },
  Device: { shape: "box", size: 24, background: "#CCFBF1", border: "#0D9488", font: "#134E4A" },
  Port: { shape: "box", size: 20, background: "#E2E8F0", border: "#475569", font: "#334155" },
  Service: { shape: "box", size: 24, background: "#FFEDD5", border: "#EA580C", font: "#7C2D12" },
  Credential: { shape: "box", size: 24, background: "#FDE68A", border: "#B45309", font: "#713F12" },
  Pulse: { shape: "box", size: 24, background: "#F3E8FF", border: "#9333EA", font: "#581C87" },
  Reputation: { shape: "box", size: 24, background: "#E0F2FE", border: "#0284C7", font: "#0C4A6E" },
  Geo: { shape: "box", size: 22, background: "#ECFCCB", border: "#65A30D", font: "#365314" },
  ASN: { shape: "database", size: 24, background: "#E0E7FF", border: "#4F46E5", font: "#312E81" },
  IntelSource: { shape: "box", size: 24, background: "#FAE8FF", border: "#C026D3", font: "#701A75" },
  Observation: { shape: "box", size: 21, background: "#F8FAFC", border: "#64748B", font: "#334155" },
};

const NIGHT_GROUP_STYLES = {
  IP: { shape: "box", size: 30, background: "#082F49", border: "#38BDF8", font: "#BAE6FD" },
  Domain: { shape: "box", size: 24, background: "#14351F", border: "#4ADE80", font: "#BBF7D0" },
  Malware: { shape: "box", size: 24, background: "#4A1620", border: "#FB7185", font: "#FFE4E6" },
  CVE: { shape: "box", size: 24, background: "#452E10", border: "#FBBF24", font: "#FEF3C7" },
  Exploit: { shape: "box", size: 24, background: "#4A1111", border: "#F87171", font: "#FEE2E2" },
  Campaign: { shape: "database", size: 24, background: "#2E1D5C", border: "#A78BFA", font: "#EDE9FE" },
  ThreatActor: { shape: "box", size: 24, background: "#4A1734", border: "#F472B6", font: "#FCE7F3" },
  Device: { shape: "square", size: 24, background: "#123C3A", border: "#2DD4BF", font: "#CCFBF1" },
  Port: { shape: "box", size: 20, background: "#1E293B", border: "#94A3B8", font: "#E2E8F0" },
  Service: { shape: "box", size: 24, background: "#431F0A", border: "#FB923C", font: "#FFEDD5" },
  Credential: { shape: "ellipse", size: 24, background: "#3F2E0A", border: "#FACC15", font: "#FEF9C3" },
  Pulse: { shape: "hexagon", size: 24, background: "#3B1D5F", border: "#C084FC", font: "#F3E8FF" },
  Reputation: { shape: "star", size: 24, background: "#082F49", border: "#38BDF8", font: "#E0F2FE" },
  Geo: { shape: "ellipse", size: 24, background: "#263A0B", border: "#A3E635", font: "#ECFCCB" },
  ASN: { shape: "database", size: 23, background: "#1E1B4B", border: "#818CF8", font: "#E0E7FF" },
  IntelSource: { shape: "box", size: 24, background: "#4A174F", border: "#E879F9", font: "#FAE8FF" },
  Observation: { shape: "box", size: 21, background: "#0F172A", border: "#94A3B8", font: "#CBD5E1" },
};

const EVIDENCE_LEVELS = {
  IP: 0,
  Reputation: 1,
  IntelSource: 1,
  ASN: 1,
  Geo: 2,
  Pulse: 2,
  Service: 2,
  Credential: 2,
  Observation: 2,
};

const AttackGraph = ({ graphData, themeMode }) => {
  const containerRef = useRef(null);
  const networkRef = useRef(null);
  const dispatch = useDispatch();

  useEffect(() => {
    if (!containerRef.current || !graphData) return;

    const computed = getComputedStyle(containerRef.current);
    const edgeColor = computed.getPropertyValue("--graph-edge").trim() || "#93a8b7";
    const edgeHighlight = computed.getPropertyValue("--graph-edge-highlight").trim() || "#087f8c";
    const graphLabel = computed.getPropertyValue("--graph-label").trim() || "#667987";
    const groupStyles = themeMode === "night" ? NIGHT_GROUP_STYLES : DAY_GROUP_STYLES;

    const isEvidenceGraph = graphData.nodes.some((node) => node.properties?.source === "evidence_graph");
    const nodes = new DataSet(
      graphData.nodes.map((n) => {
        const style = groupStyles[n.group] || groupStyles.Domain;
        return {
          id: n.id,
          label: n.label.length > 20 ? `${n.label.slice(0, 18)}...` : n.label,
          title: `${n.group}: ${n.label}`,
          group: n.group,
          shape: style.shape,
          size: n.isRoot ? style.size + 3 : style.size,
          level: isEvidenceGraph ? EVIDENCE_LEVELS[n.group] ?? 3 : undefined,
          margin: { top: 8, right: 12, bottom: 8, left: 12 },
          widthConstraint: isEvidenceGraph ? { minimum: 96, maximum: 180 } : { maximum: 170 },
          color: {
            background: style.background,
            border: style.border,
            highlight: { background: style.background, border: style.font },
          },
          font: {
            color: style.font,
            size: 13,
            face: "ui-monospace, SFMono-Regular, Consolas, monospace",
            vadjust: -2,
          },
          borderWidth: n.isRoot ? 4 : 2,
          shadow: themeMode === "night"
            ? { enabled: true, color: style.border, size: n.isRoot ? 18 : 12, x: 0, y: 0 }
            : { enabled: n.isRoot, color: style.border, size: 10, x: 0, y: 0 },
          rawData: n,
        };
      })
    );

    const edges = new DataSet(
      graphData.edges.map((e) => ({
        id: e.id,
        from: e.from,
        to: e.to,
        label: e.label,
        font: { size: isEvidenceGraph ? 9 : 10, color: graphLabel, align: "middle", strokeWidth: themeMode === "night" ? 3 : 0 },
        arrows: { to: { enabled: true, scaleFactor: isEvidenceGraph ? 0.45 : 0.6 } },
        color: { color: edgeColor, highlight: edgeHighlight },
        smooth: isEvidenceGraph ? { type: "cubicBezier", forceDirection: "horizontal", roundness: 0.35 } : { type: "curvedCW", roundness: 0.15 },
      }))
    );

    const options = {
      physics: {
        enabled: !isEvidenceGraph,
        solver: "forceAtlas2Based",
        forceAtlas2Based: {
          gravitationalConstant: -60,
          centralGravity: 0.005,
          springLength: 120,
          springConstant: 0.08,
        },
        stabilization: { iterations: 150 },
      },
      interaction: {
        hover: true,
        tooltipDelay: 200,
        zoomView: true,
        dragView: true,
      },
      layout: isEvidenceGraph
        ? {
            hierarchical: {
              enabled: true,
              direction: "LR",
              sortMethod: "directed",
              levelSeparation: 230,
              nodeSpacing: 145,
              treeSpacing: 180,
              blockShifting: true,
              edgeMinimization: true,
              parentCentralization: true,
            },
          }
        : { improvedLayout: true },
      nodes: {
        shapeProperties: {
          borderRadius: 6,
        },
      },
    };

    const network = new Network(containerRef.current, { nodes, edges }, options);
    networkRef.current = network;

    network.on("click", (params) => {
      if (params.nodes.length > 0) {
        const nodeId = params.nodes[0];
        const node = nodes.get(nodeId);
        dispatch(setSelectedNode(node?.rawData || null));
      } else {
        dispatch(setSelectedNode(null));
      }
    });

    return () => {
      network.destroy();
      networkRef.current = null;
    };
  }, [graphData, dispatch, themeMode]);

  return <div ref={containerRef} className="graph-frame" />;
};

export default AttackGraph;
