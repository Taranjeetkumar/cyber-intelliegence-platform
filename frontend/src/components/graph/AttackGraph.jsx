import { useEffect, useRef } from "react";
import { Network } from "vis-network";
import { DataSet } from "vis-data";
import { useDispatch } from "react-redux";
import { setSelectedNode } from "../../features/investigation/investigationSlice";

const DAY_GROUP_COLORS = {
  IP: { background: "#E6F1FB", border: "#185FA5", font: "#0C447C" },
  Domain: { background: "#EAF3DE", border: "#3B6D11", font: "#27500A" },
  Malware: { background: "#FAECE7", border: "#993C1D", font: "#712B13" },
  CVE: { background: "#FAEEDA", border: "#854F0B", font: "#633806" },
  Exploit: { background: "#FCEBEB", border: "#A32D2D", font: "#791F1F" },
  Campaign: { background: "#EEEDFE", border: "#534AB7", font: "#3C3489" },
  ThreatActor: { background: "#FBEAF0", border: "#993556", font: "#72243E" },
  Device: { background: "#E1F5EE", border: "#0F6E56", font: "#085041" },
  Port: { background: "#F1EFE8", border: "#5F5E5A", font: "#444441" },
  Service: { background: "#F1EFE8", border: "#888780", font: "#5F5E5A" },
};

const NIGHT_GROUP_COLORS = {
  IP: { background: "#102c40", border: "#3aa9ff", font: "#bde6ff" },
  Domain: { background: "#183221", border: "#77d77b", font: "#c7f3c5" },
  Malware: { background: "#3a2019", border: "#ff946c", font: "#ffd1bf" },
  CVE: { background: "#342817", border: "#f5b85b", font: "#ffe1a8" },
  Exploit: { background: "#3a1c20", border: "#ff6b5f", font: "#ffc4be" },
  Campaign: { background: "#242348", border: "#a8a2ff", font: "#dedbff" },
  ThreatActor: { background: "#371d2b", border: "#ff8fbd", font: "#ffd0e2" },
  Device: { background: "#12332d", border: "#53d2ba", font: "#c2f4ea" },
  Port: { background: "#202c33", border: "#8fa0ad", font: "#d4e2e8" },
  Service: { background: "#202c33", border: "#6f8994", font: "#d4e2e8" },
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
    const groupColors = themeMode === "night" ? NIGHT_GROUP_COLORS : DAY_GROUP_COLORS;

    const nodes = new DataSet(
      graphData.nodes.map((n) => {
        const colors = groupColors[n.group] || groupColors.Domain;
        return {
          id: n.id,
          label: n.label.length > 20 ? `${n.label.slice(0, 18)}...` : n.label,
          title: `${n.group}: ${n.label}`,
          group: n.group,
          shape: n.isRoot ? "star" : "dot",
          size: n.isRoot ? 29 : 18,
          color: {
            background: colors.background,
            border: colors.border,
            highlight: { background: colors.background, border: colors.font },
          },
          font: {
            color: colors.font,
            size: 13,
            face: "ui-monospace, SFMono-Regular, Consolas, monospace",
            vadjust: -2,
          },
          borderWidth: n.isRoot ? 3 : 1.5,
          shadow: themeMode === "night" ? { enabled: true, color: colors.border, size: 12, x: 0, y: 0 } : false,
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
        font: { size: 10, color: graphLabel, align: "middle", strokeWidth: themeMode === "night" ? 3 : 0 },
        arrows: { to: { enabled: true, scaleFactor: 0.6 } },
        color: { color: edgeColor, highlight: edgeHighlight },
        smooth: { type: "curvedCW", roundness: 0.15 },
      }))
    );

    const options = {
      physics: {
        enabled: true,
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
      layout: { improvedLayout: true },
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
