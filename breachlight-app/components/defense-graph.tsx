'use client';
import { useMemo } from 'react';
import { ReactFlow, Background, Controls, Handle, Position, type Node, type Edge, type NodeProps } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './defense-graph.css';
import { Globe, Server, CircleHelp, CheckCircle2, Clock, Ticket } from 'lucide-react';

// Exposure map for the defense plan: inventory assets -> plan CVEs -> review status.
// Every edge comes from real data (the app's product matching and the plan state);
// there is no network topology, so assets are never linked to each other.

export type GraphAsset = { id: string; name: string; product: string; exposure: 'Public' | 'Internal'; criticality: 'High' | 'Medium' | 'Low' };
export type GraphItem = { id: string; rank: number; title: string; matches: GraphAsset[]; reviewed: boolean; ticket?: { externalKey: string; url: string } };

type AssetData = { asset: GraphAsset; count: number };
type NoMatchData = { count: number };
type CveData = { item: GraphItem; isPublic: boolean };
type StatusData = { reviewed: boolean; count: number };
type AssetNode = Node<AssetData, 'asset'>;
type NoMatchNode = Node<NoMatchData, 'nomatch'>;
type CveNode = Node<CveData, 'cve'>;
type StatusNode = Node<StatusData, 'status'>;
type GraphNode = AssetNode | NoMatchNode | CveNode | StatusNode;

const COL = { asset: 0, cve: 300, status: 620 };
const ROW = 84;
const tier = (rank: number) => rank <= 100 ? 'fix' : rank <= 500 ? 'week' : 'monitor';
const tierLabel = { fix: 'Fix now', week: 'This week', monitor: 'Monitor' } as const;
const mean = (ys: number[]) => ys.reduce((a, b) => a + b, 0) / ys.length;

// Place nodes near the average height of their neighbours, then push apart so none overlap.
function spread<T>(entries: { key: T; ys: number[] }[]) {
  const sorted = entries.map(e => ({ key: e.key, y: mean(e.ys) })).sort((a, b) => a.y - b.y);
  let prev = -Infinity;
  for (const e of sorted) { e.y = Math.max(e.y, prev + ROW); prev = e.y; }
  return sorted;
}

const hidden = { opacity: 0, pointerEvents: 'none' as const };

function AssetNodeView({ data }: NodeProps<AssetNode>) {
  const { asset, count } = data;
  const Icon = asset.exposure === 'Public' ? Globe : Server;
  return <div className={`dg-node dg-asset ${asset.exposure === 'Public' ? 'public' : ''}`}>
    <span className="dg-icon"><Icon size={15} /></span>
    <div><b>{asset.name}</b><small>{asset.exposure} · {asset.criticality} criticality · {count} CVE{count > 1 ? 's' : ''}</small></div>
    <Handle type="source" position={Position.Right} isConnectable={false} style={hidden} />
  </div>;
}

function NoMatchNodeView({ data }: NodeProps<NoMatchNode>) {
  return <div className="dg-node dg-asset dg-nomatch">
    <span className="dg-icon"><CircleHelp size={15} /></span>
    <div><b>No matching asset</b><small>{data.count} CVE{data.count > 1 ? 's' : ''} · check your inventory</small></div>
    <Handle type="source" position={Position.Right} isConnectable={false} style={hidden} />
  </div>;
}

function CveNodeView({ data }: NodeProps<CveNode>) {
  const { item, isPublic } = data;
  const t = tier(item.rank);
  return <div className={`dg-node dg-cve ${t}`} title="Open the vulnerability briefing">
    <Handle type="target" position={Position.Left} isConnectable={false} style={hidden} />
    <div className="dg-cve-top"><b>{item.title}</b><span className={`dg-tier ${t}`}>{tierLabel[t]}</span></div>
    <small>{item.id} · Rank #{item.rank}</small>
    <div className="dg-badges">
      {isPublic && <span className="dg-badge public"><Globe size={11} />Public exposure</span>}
      {item.ticket && <a className="dg-badge ticket nodrag nopan" href={item.ticket.url} target="_blank" rel="noreferrer" onClick={e => e.stopPropagation()}><Ticket size={11} />{item.ticket.externalKey}</a>}
    </div>
    <Handle type="source" position={Position.Right} isConnectable={false} style={hidden} />
  </div>;
}

function StatusNodeView({ data }: NodeProps<StatusNode>) {
  const Icon = data.reviewed ? CheckCircle2 : Clock;
  return <div className={`dg-node dg-status ${data.reviewed ? 'reviewed' : 'pending'}`}>
    <Handle type="target" position={Position.Left} isConnectable={false} style={hidden} />
    <span className="dg-icon"><Icon size={15} /></span>
    <div><b>{data.reviewed ? 'Evidence reviewed' : 'Pending review'}</b><small>{data.count} item{data.count > 1 ? 's' : ''}</small></div>
  </div>;
}

const nodeTypes = { asset: AssetNodeView, nomatch: NoMatchNodeView, cve: CveNodeView, status: StatusNodeView };

function layout(items: GraphItem[]) {
  const sorted = [...items].sort((a, b) => a.rank - b.rank);
  const nodes: GraphNode[] = [];
  const edges: Edge[] = [];
  const assetYs = new Map<string, { asset: GraphAsset; ys: number[] }>();
  const noMatchYs: number[] = [];
  const statusYs = { pending: [] as number[], reviewed: [] as number[] };

  sorted.forEach((item, i) => {
    const y = i * ROW;
    const isPublic = item.matches.some(a => a.exposure === 'Public');
    nodes.push({ id: `cve:${item.id}`, type: 'cve', position: { x: COL.cve, y }, data: { item, isPublic } });
    if (!item.matches.length) {
      noMatchYs.push(y);
      edges.push({ id: `nomatch->${item.id}`, source: 'nomatch', target: `cve:${item.id}`, className: 'dg-edge nomatch' });
    }
    for (const a of item.matches) {
      if (!assetYs.has(a.id)) assetYs.set(a.id, { asset: a, ys: [] });
      assetYs.get(a.id)!.ys.push(y);
      edges.push({ id: `${a.id}->${item.id}`, source: `asset:${a.id}`, target: `cve:${item.id}`, className: `dg-edge ${a.exposure === 'Public' ? 'public' : 'internal'}`, animated: a.exposure === 'Public' });
    }
    const status = item.reviewed ? 'reviewed' : 'pending';
    statusYs[status].push(y);
    edges.push({ id: `${item.id}->${status}`, source: `cve:${item.id}`, target: `status:${status}`, className: `dg-edge status ${status}` });
  });

  const left = [...assetYs.entries()].map(([id, v]) => ({ key: id, ys: v.ys }));
  if (noMatchYs.length) left.push({ key: '__nomatch', ys: noMatchYs });
  for (const { key, y } of spread(left)) {
    if (key === '__nomatch') nodes.push({ id: 'nomatch', type: 'nomatch', position: { x: COL.asset, y }, data: { count: noMatchYs.length } });
    else { const v = assetYs.get(key)!; nodes.push({ id: `asset:${key}`, type: 'asset', position: { x: COL.asset, y }, data: { asset: v.asset, count: v.ys.length } }); }
  }
  const right = (['pending', 'reviewed'] as const).filter(s => statusYs[s].length).map(s => ({ key: s, ys: statusYs[s] }));
  for (const { key, y } of spread(right)) nodes.push({ id: `status:${key}`, type: 'status', position: { x: COL.status, y }, data: { reviewed: key === 'reviewed', count: statusYs[key].length } });

  return { nodes, edges, rows: Math.max(sorted.length, left.length) };
}

export default function DefenseGraph({ items, onSelect }: { items: GraphItem[]; onSelect: (cveId: string) => void }) {
  const { nodes, edges, rows } = useMemo(() => layout(items), [items]);
  if (!items.length) return null;
  const publicCount = items.filter(i => i.matches.some(a => a.exposure === 'Public')).length;
  const unmatched = items.filter(i => !i.matches.length).length;
  const height = Math.min(560, Math.max(260, rows * ROW + 60));
  return <section className="panel dg-panel" aria-label="Defense plan exposure map">
    <div className="panel-heading">
      <div>
        <h2>Exposure map</h2>
        <p>
          <b>{publicCount} of {items.length}</b> plan item{items.length > 1 ? 's' : ''} touch an internet-facing asset
          {unmatched > 0 && <> · <b>{unmatched}</b> match no asset in your inventory</>}. Select a CVE to open its briefing.
        </p>
      </div>
    </div>
    <div className="dg-canvas" style={{ height }}>
      <ReactFlow
        nodes={nodes} edges={edges} nodeTypes={nodeTypes}
        onNodeClick={(_, n) => { if (n.type === 'cve') onSelect((n as CveNode).data.item.id); }}
        fitView fitViewOptions={{ padding: 0.12, maxZoom: 1 }} minZoom={0.3} maxZoom={1.5}
        nodesDraggable={false} nodesConnectable={false} elementsSelectable={false}
        zoomOnScroll={false} panOnScroll={false} preventScrolling={false} zoomOnDoubleClick={false}
      >
        <Background gap={20} size={1} color="var(--line)" />
        <Controls showInteractive={false} position="bottom-right" />
      </ReactFlow>
    </div>
    <div className="dg-legend" aria-hidden="true">
      <span><i className="dg-swatch public" />Public asset</span>
      <span><i className="dg-swatch internal" />Internal asset</span>
      <span><i className="dg-swatch nomatch" />No inventory match</span>
      <span><i className="dg-dot fix" />Fix now (top 100)</span>
      <span><i className="dg-dot week" />This week (101–500)</span>
    </div>
    <p className="dg-mobile-note">The exposure map needs a wider screen; the plan items below carry the same information.</p>
    <p className="dg-footnote">Links come from product names in your inventory matched against each CVE. Assets are not linked to each other because the app has no network topology.</p>
  </section>;
}
