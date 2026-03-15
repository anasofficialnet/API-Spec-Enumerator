"use client";

import Icon from "@/components/ui/AppIcon";
import HelpTooltip from "./HelpTooltip";

interface AttackGraphNode {
  id: string;
  method: string;
  path: string;
  host: string;
  authRequired: boolean;
}

interface AttackGraphEdge {
  source: string;
  target: string;
  relation: string;
  evidence: string;
  weight: number;
}

export interface AttackGraphData {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  paths: string[][];
}

interface AttackGraphPanelProps {
  graph: AttackGraphData | null;
  loading?: boolean;
}

const ATTACK_GRAPH_HELP = {
  summary: "Attack Graph links endpoints that appear to belong to the same flow, then shows the paths the scanner can replay as chained tests.",
  when: "Use this when you want to understand how login, profile, orders, and other related endpoints connect.",
};

export default function AttackGraphPanel({ graph, loading = false }: AttackGraphPanelProps) {
  const nodeMap = new Map((graph?.nodes || []).map((node) => [node.id, node]));

  return (
    <div className="terminal-window">
      <div className="terminal-header justify-between">
        <div className="flex items-center gap-2">
          <div className="terminal-dot" style={{ background: "#FF5F56" }} />
          <div className="terminal-dot" style={{ background: "#FFBD2E" }} />
          <div className="terminal-dot" style={{ background: "#27C93F" }} />
          <span className="font-mono text-[10px] text-[#475569] uppercase tracking-widest ml-2">
            attack_graph
          </span>
          <HelpTooltip summary={ATTACK_GRAPH_HELP.summary} when={ATTACK_GRAPH_HELP.when} />
        </div>
        {graph && (
          <span className="font-mono text-[10px] text-[#475569] uppercase tracking-widest">
            {graph.nodes.length} nodes / {graph.edges.length} edges
          </span>
        )}
      </div>

      <div className="p-5 space-y-5">
        {loading && (
          <div className="font-mono text-xs text-[#94A3B8]">Building attack graph...</div>
        )}

        {!loading && !graph && (
          <div className="font-mono text-xs text-[#475569]">No attack graph available yet.</div>
        )}

        {graph && (
          <>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="terminal-window p-4">
                <div className="font-mono text-[10px] text-[#475569] uppercase tracking-widest mb-1">Nodes</div>
                <div className="font-mono text-2xl text-[#4FC3F7] font-bold">{graph.nodes.length}</div>
              </div>
              <div className="terminal-window p-4">
                <div className="font-mono text-[10px] text-[#475569] uppercase tracking-widest mb-1">Edges</div>
                <div className="font-mono text-2xl text-[#6366F1] font-bold">{graph.edges.length}</div>
              </div>
              <div className="terminal-window p-4">
                <div className="font-mono text-[10px] text-[#475569] uppercase tracking-widest mb-1">Paths</div>
                <div className="font-mono text-2xl text-[#FF8C42] font-bold">{graph.paths.length}</div>
              </div>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              <div className="terminal-window p-4 space-y-3">
                <div className="font-mono text-[10px] text-[#A78BFA] uppercase tracking-widest">Edges</div>
                <div className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
                  {graph.edges.map((edge, index) => {
                    const source = nodeMap.get(edge.source);
                    const target = nodeMap.get(edge.target);
                    return (
                      <div key={`${edge.source}-${edge.target}-${index}`} className="border border-[rgba(99,102,241,0.08)] rounded p-3">
                        <div className="flex items-center gap-2 font-mono text-xs text-[#F8FAFC]">
                          <span className="text-[#4FC3F7]">{source?.method || "?"}</span>
                          <span className="truncate">{source?.path || edge.source}</span>
                          <Icon name="ArrowRightIcon" size={12} className="text-[#475569] flex-shrink-0" />
                          <span className="text-[#FF8C42]">{target?.method || "?"}</span>
                          <span className="truncate">{target?.path || edge.target}</span>
                        </div>
                        <div className="font-mono text-[10px] text-[#6366F1] uppercase tracking-widest mt-2">
                          {edge.relation} x{edge.weight}
                        </div>
                        <div className="font-mono text-[10px] text-[#475569] mt-1">
                          {edge.evidence}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="terminal-window p-4 space-y-3">
                <div className="font-mono text-[10px] text-[#A78BFA] uppercase tracking-widest">Paths</div>
                <div className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
                  {graph.paths.length === 0 && (
                    <div className="font-mono text-xs text-[#475569]">No multi-hop paths were inferred from the current traffic.</div>
                  )}
                  {graph.paths.map((path, index) => (
                    <div key={`${path.join("-")}-${index}`} className="border border-[rgba(99,102,241,0.08)] rounded p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        {path.map((nodeId, nodeIndex) => {
                          const node = nodeMap.get(nodeId);
                          return (
                            <div key={`${nodeId}-${nodeIndex}`} className="flex items-center gap-2">
                              <span className="font-mono text-[10px] px-2 py-1 rounded bg-[rgba(99,102,241,0.08)] text-[#F8FAFC]">
                                {node?.method || "?"} {node?.path || nodeId}
                              </span>
                              {nodeIndex < path.length - 1 && (
                                <Icon name="ChevronRightIcon" size={12} className="text-[#475569]" />
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
