import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { ArrowDownToLine, ArrowRight, Fingerprint, LoaderCircle, Plus } from 'lucide-react';
import { api, label, name, safeDownload, status } from './api';
import type { Row } from './api';

type Graph = { nodes: { id: string; kind: string; label: string; role?: string }[]; edges: { from: string; to: string; relation: string }[]; limit: number };

export function EvidenceGraph({ projectId, findings, evidence, inspect }: { projectId: string; findings: Row[]; evidence: Row[]; inspect: (row: Row) => void }) {
  const [focus, setFocus] = useState('');
  const [graph, setGraph] = useState<Graph | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const selected = findings.some(row => row.id === focus) ? focus : findings[0]?.id ?? '';
  useEffect(() => {
    const controller = new AbortController();
    setGraph(null); setError('');
    if (!selected) return () => controller.abort();
    setLoading(true);
    api<Graph>(`/projects/${encodeURIComponent(projectId)}/graph?finding_id=${encodeURIComponent(selected)}`, { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setGraph(value); })
      .catch(err => { if (!controller.signal.aborted) setError(err.message); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [projectId, selected]);
  const visible = graph?.nodes.slice(0, Math.min(graph.limit, 60)) ?? [];
  const findingNodes = visible.filter(node => node.kind === 'finding');
  const evidenceNodes = visible.filter(node => node.kind === 'evidence');
  const height = Math.max(200, evidenceNodes.length * 66 + 32);
  const positions = new Map(visible.map(node => [node.id, node.kind === 'finding' ? { x: 28, y: height / 2 - 25 + findingNodes.indexOf(node) * 66 } : { x: 430, y: evidenceNodes.indexOf(node) * 66 + 20 }]));
  function inspectNode(id: string) { const row = [...findings, ...evidence].find(item => item.id === id); if (row) inspect(row); }
  const edges = (graph?.edges ?? []).filter(edge => positions.has(edge.from) && positions.has(edge.to));
  return <div className="evidence-graph"><div className="graph-toolbar"><label>Focus on a located finding<select value={selected} onChange={e => setFocus(e.target.value)} disabled={!findings.length}><option value="">No finding selected</option>{findings.map(row => <option key={row.id} value={row.id}>{name(row)} · {label(row.path ?? row.role)}</option>)}</select></label><p>One claim and its supporting records.<br />Contradictions remain in the register above.</p></div>
    {loading && <p role="status"><LoaderCircle size={15} className="spin" /> Loading evidence relationships…</p>}
    {error && <p className="error-box" role="alert">{error}</p>}
    {!selected && <p className="scope-note">Run discovery to inspect the relationships between findings and their evidence.</p>}
    {graph && <><div className="graph-canvas"><svg viewBox={`0 0 780 ${height}`} style={{ minHeight: Math.min(height, 430) }} role="img" aria-label="A located finding linked to its supporting evidence. The relationship table below provides the same information."><defs><marker id="evidence-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#9aafa1" /></marker></defs>{edges.map((edge, i) => { const from = positions.get(edge.from)!; const to = positions.get(edge.to)!; return <path key={i} d={`M ${from.x + 278} ${from.y + 24} C 360 ${from.y + 24}, 376 ${to.y + 24}, ${to.x - 8} ${to.y + 24}`} fill="none" stroke="#9aafa1" strokeWidth="1.4" markerEnd="url(#evidence-arrow)" />; })}{visible.map(node => { const point = positions.get(node.id)!; return <g key={node.id} transform={`translate(${point.x} ${point.y})`}><rect width="278" height="49" rx="5" fill={node.kind === 'finding' ? '#1c3738' : '#fffefa'} stroke={node.kind === 'finding' ? '#1c3738' : '#ced9cf'} /><text x="13" y="18" fontSize="8" letterSpacing="1.2" fill={node.kind === 'finding' ? '#d8b592' : '#97745a'}>{node.kind.toUpperCase()}{node.role ? ` / ${node.role.replaceAll('_', ' ').toUpperCase()}` : ''}</text><text x="13" y="36" fontSize="12" fill={node.kind === 'finding' ? '#fff9ed' : '#243c3e'}>{label(node.label).length > 36 ? label(node.label).slice(0, 33) + '…' : label(node.label)}</text></g>; })}</svg></div><details className="relationship-details" open><summary>Evidence relationship table · {edges.length} links</summary><div className="relationship-table"><table><thead><tr><th>Finding</th><th>Relationship</th><th>Evidence</th></tr></thead><tbody>{edges.map((edge, i) => <tr key={i}><td><button className="text-button" onClick={() => inspectNode(edge.from)}>{label(visible.find(n => n.id === edge.from)?.label)}</button></td><td>{edge.relation.replaceAll('_', ' ')}</td><td><button className="text-button" onClick={() => inspectNode(edge.to)}>{label(visible.find(n => n.id === edge.to)?.label)}<ArrowRight size={12} /></button></td></tr>)}</tbody></table>{!edges.length && <p className="scope-note">No evidence links were returned for this finding.</p>}</div></details><p className="scope-note">This view is capped at {Math.min(graph.limit, 60)} nodes. A link preserves provenance; it does not establish that a claim is true.</p></>}
  </div>;
}

export function ProjectForm({ busy, submit, cancel }: { busy: boolean; submit: (value: { name: string; description: string }) => Promise<boolean>; cancel: () => void }) {
  const [projectName, setProjectName] = useState(''); const [description, setDescription] = useState('');
  async function save(event: FormEvent) { event.preventDefault(); if (!projectName.trim()) return; if (await submit({ name: projectName.trim(), description: description.trim() })) { setProjectName(''); setDescription(''); } }
  return <form className="stack" onSubmit={save}><label>Project name<input autoFocus value={projectName} onChange={e => setProjectName(e.target.value)} maxLength={120} placeholder="A service, product or scoped migration case" required /></label><label>Scope and purpose<textarea value={description} onChange={e => setDescription(e.target.value)} rows={3} maxLength={1500} placeholder="Describe the assets and decision this evidence will support." /></label><p className="scope-note">New projects are restricted. Their evidence stays local and cannot be sent to a remote AI provider. You are the initial project member.</p><div className="form-row"><button className="primary" disabled={busy || !projectName.trim()}><Plus size={15} />Create restricted project</button><button className="secondary" type="button" disabled={busy} onClick={cancel}>Cancel</button></div></form>;
}

export function PassportRecords({ records, inspect }: { records: Row[]; inspect: (row: Row) => void }) {
  return <div className="passport-list">{[...records].reverse().map((record, index) => {
    const anchor = record.anchor && typeof record.anchor === 'object' ? record.anchor as Row : {};
    const download = safeDownload(record.download_url);
    const included = status(record) === 'included-local';
    return <article className="passport-card" key={record.id ?? index}><header><Fingerprint size={25} /><div><span className="eyebrow">MIGRATION PASSPORT</span><h3>{included ? 'Recorded on the local development chain' : label(record.error ?? record.reason, 'Passport attempt recorded')}</h3></div><span className={`badge ${included ? 'neutral' : 'warn'}`}>{status(record).replaceAll('-', ' ')}</span></header>{Object.keys(anchor).length > 0 && <dl className="passport-bindings"><div><dt>Network / chain</dt><dd>{label(anchor.network)} / {label(anchor.chain_id)}</dd></div><div><dt>Transaction</dt><dd><code>{label(anchor.transaction_hash)}</code></dd></div><div><dt>Block</dt><dd>{label(anchor.block_number)}</dd></div><div><dt>Verification outcome</dt><dd>{label(anchor.verification_status)}</dd></div><div><dt>Finality</dt><dd>{label(anchor.finality).replaceAll('_', ' ')}</dd></div><div><dt>Signature authority</dt><dd>{label(anchor.role_model)}</dd></div></dl>}<div className="form-row"><button className="secondary" onClick={() => inspect(record)}>Inspect commitment & signatures<ArrowRight size={13} /></button>{download && included && <a className="button primary" href={download} download><ArrowDownToLine size={15} />Download passport</a>}</div>{included && <p className="scope-note">A real local EVM transaction, with local demonstration signing keys. Independent public-network finality is not claimed.</p>}</article>;
  })}</div>;
}
