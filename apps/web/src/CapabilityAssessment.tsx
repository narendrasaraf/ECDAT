import { useState } from 'react';
import type { FormEvent } from 'react';
import { label, status } from './api';
import type { Row } from './api';

export function CapabilityAssessment({ verifications, busy, assess }: { verifications: Row[]; busy: boolean; assess: (payload: unknown) => Promise<unknown> }) {
  const [mode, setMode] = useState('unknown');
  const [verification, setVerification] = useState('');
  const [source, setSource] = useState(''); const [scope, setScope] = useState('');
  const [runtime, setRuntime] = useState(''); const [peer, setPeer] = useState(''); const [protocol, setProtocol] = useState('');
  const [hsm, setHsm] = useState('unknown'); const [hsmCapabilities, setHsmCapabilities] = useState('');
  const [memory, setMemory] = useState(''); const [latency, setLatency] = useState(''); const [error, setError] = useState('');
  const passed = verifications.filter(row => status(row) === 'passed');
  const selected = passed.some(row => row.id === verification) ? verification : passed[0]?.id ?? '';
  const tokens = (value: string) => value.trim() ? value.split(',').map(item => item.trim()).filter(Boolean) : null;
  async function submit(event: FormEvent) {
    event.preventDefault(); setError('');
    if (mode === 'unknown') { await assess({}); return; }
    if (!source.trim() || !scope.trim()) { setError('Attribute this capability claim to a source and a specific scope.'); return; }
    if (mode === 'measured' && !selected) { setError('A passed project verification is required for measured capabilities.'); return; }
    if ([runtime, peer, hsmCapabilities].some(value => (tokens(value)?.length ?? 0) > 20 || tokens(value)?.some(item => item.length > 100))) { setError('Use no more than 20 capability names per field, each under 101 characters.'); return; }
    if ([memory, latency].some(value => value !== '' && (!Number.isFinite(Number(value)) || Number(value) <= 0))) { setError('Performance limits must be positive finite numbers.'); return; }
    const requirements = { ...(hsm === 'unknown' ? {} : { requires_hsm: hsm === 'yes' }), hsm_capabilities: tokens(hsmCapabilities), max_memory_mb: memory === '' ? null : Number(memory), max_latency_ms: latency === '' ? null : Number(latency) };
    const capability = { source: source.trim(), scope: scope.trim(), ...requirements, ...(mode === 'measured' ? { verification_id: selected } : { runtime_capabilities: tokens(runtime), peer_capabilities: tokens(peer), protocol: protocol.trim() || null }) };
    await assess({ capabilities: { key_exchange: capability } });
  }
  return <form className="stack" onSubmit={submit}>
    <label>Basis for key exchange capabilities<select value={mode} onChange={e => setMode(e.target.value)}><option value="unknown">Not yet established — retain unknowns</option><option value="measured">Use a passed local TLS verification</option><option value="attributed">Record an attributed capability claim</option></select></label>
    {mode !== 'unknown' && <>
      <div className="two-column"><label>Capability source<input value={source} onChange={e => setSource(e.target.value)} maxLength={300} placeholder="Test report or accountable source" required /></label><label>Requested assessment scope<input value={scope} onChange={e => setScope(e.target.value)} maxLength={300} placeholder="Named service, endpoint or laboratory" required /></label></div>
      {mode === 'measured' ? <><label>Passed verification<select value={selected} onChange={e => setVerification(e.target.value)} required><option value="">Select a passed verification</option>{passed.map(row => <option value={row.id} key={row.id}>{row.id} · {label(row.created_at)}</option>)}</select></label><p className="scope-note">The server derives observed groups and protocol from this verification and binds the result to its candidate artifact. Its scope remains the authored loopback laboratory; it does not establish support in another deployment.</p></> : <><div className="two-column"><label>Runtime capability names<input value={runtime} onChange={e => setRuntime(e.target.value)} maxLength={1000} placeholder="Comma-separated names; blank means unknown" /></label><label>Peer capability names<input value={peer} onChange={e => setPeer(e.target.value)} maxLength={1000} placeholder="Comma-separated names; blank means unknown" /></label></div><label>Protocol<input value={protocol} onChange={e => setProtocol(e.target.value)} maxLength={100} placeholder="For example TLSv1.3; blank means unknown" /></label><p className="scope-note">These are attributed claims supplied by you. A feasible option means the declared constraints match; independent testing and review are still required.</p></>}
      <details className="edit-plan"><summary>Hardware and performance requirements</summary><div className="stack"><label>Is an HSM required?<select value={hsm} onChange={e => setHsm(e.target.value)}><option value="unknown">No HSM requirement specified</option><option value="no">No</option><option value="yes">Yes</option></select></label>{hsm === 'yes' && <label>Attributed HSM capability names<input value={hsmCapabilities} onChange={e => setHsmCapabilities(e.target.value)} maxLength={1000} placeholder="Comma-separated names; blank means unknown" /></label>}<div className="two-column"><label>Maximum memory (MB)<input type="number" min="0.000001" step="any" value={memory} onChange={e => setMemory(e.target.value)} placeholder="No limit specified" /></label><label>Maximum latency (ms)<input type="number" min="0.000001" step="any" value={latency} onChange={e => setLatency(e.target.value)} placeholder="No limit specified" /></label></div></div></details>
    </>}
    {error && <p className="error-box" role="alert">{error}</p>}
    <button className="primary" disabled={busy || (mode === 'measured' && !selected)}>Assess with this capability basis</button>
    <p className="scope-note">Key exchange evidence does not establish certificate authentication or signature support. Missing requirements stay unknown.</p>
  </form>;
}
