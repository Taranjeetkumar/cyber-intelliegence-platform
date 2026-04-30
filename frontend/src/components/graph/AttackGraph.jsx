import { useEffect, useRef } from "react";
import { Network } from "vis-network";
import { DataSet } from "vis-data";
import { useDispatch } from "react-redux";
import { setSelectedNode } from "../../features/investigation/investigationSlice";

// Color mapping per node type — matches architecture diagram colors
const GROUP_COLORS = {
  IP:          { background: "#E6F1FB", border: "#185FA5", font: "#0C447C" },
  Domain:      { background: "#EAF3DE", border: "#3B6D11", font: "#27500A" },
  Malware:     { background: "#FAECE7", border: "#993C1D", font: "#712B13" },
  CVE:         { background: "#FAEEDA", border: "#854F0B", font: "#633806" },
  Exploit:     { background: "#FCEBEB", border: "#A32D2D", font: "#791F1F" },
  Campaign:    { background: "#EEEDFE", border: "#534AB7", font: "#3C3489" },
  ThreatActor: { background: "#FBEAF0", border: "#993556", font: "#72243E" },
  Device:      { background: "#E1F5EE", border: "#0F6E56", font: "#085041" },
  Port:        { background: "#F1EFE8", border: "#5F5E5A", font: "#444441" },
  Service:     { background: "#F1EFE8", border: "#888780", font: "#5F5E5A" },
};

const AttackGraph = ({ graphData }) => {
  const containerRef = useRef(null);
  const networkRef = useRef(null);
  const dispatch = useDispatch();

  useEffect(() => {
    if (!containerRef.current || !graphData) return;

    // Build vis DataSets
    const nodes = new DataSet(
      graphData.nodes.map((n) => {
        const colors = GROUP_COLORS[n.group] || GROUP_COLORS.Domain;
        return {
          id: n.id,
          label: n.label.length > 20 ? n.label.slice(0, 18) + "…" : n.label,
          title: `${n.group}: ${n.label}`,  // tooltip
          group: n.group,
          shape: n.isRoot ? "star" : "dot",
          size: n.isRoot ? 28 : 18,
          color: {
            background: colors.background,
            border: colors.border,
            highlight: { background: colors.background, border: colors.font },
          },
          font: { color: colors.font, size: 13, face: "monospace" },
          borderWidth: n.isRoot ? 3 : 1.5,
          // Store full data for detail panel
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
        font: { size: 10, color: "#888780", align: "middle" },
        arrows: { to: { enabled: true, scaleFactor: 0.6 } },
        color: { color: "#B4B2A9", highlight: "#534AB7" },
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

    // Click → update Redux selected node
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
  }, [graphData, dispatch]);

  return (
    <div
      ref={containerRef}
      style={{
        width: "100%",
        height: "520px",
        border: "1px solid #D3D1C7",
        borderRadius: "8px",
        background: "#FAFAF8",
      }}
    />
  );
};

export default AttackGraph;
