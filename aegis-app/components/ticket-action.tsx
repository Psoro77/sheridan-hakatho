'use client';
import { useState } from 'react';
import { Ticket as TicketIcon, ExternalLink, X, Copy, Download, Check, Eye } from 'lucide-react';
import { GitHubMark } from './brand';

export type TicketProvider = 'github' | 'jira' | null;
export type Ticket = { key: string; provider: 'github' | 'jira'; externalKey: string; url: string; title: string; createdAt: string };
export type TicketPreviewData = { key: string; provider: TicketProvider; configured: boolean; title: string; labels: string[]; markdown: string };
export type Ticketing = { provider: TicketProvider; configured: boolean; target: string; ok?: boolean; message?: string };

export const providerName = (p: TicketProvider) => p === 'github' ? 'GitHub' : p === 'jira' ? 'Jira' : 'Ticket';
const ProviderIcon = ({ provider, size = 15 }: { provider: TicketProvider; size?: number }) => provider === 'github' ? <GitHubMark size={size} /> : <TicketIcon size={size} />;

/** A filed ticket shows as a link; otherwise a create button (or a preview when no tracker is connected). */
export default function TicketAction({ ticket, ticketing, busy, disabled, onCreate, onPreview }: { ticket?: Ticket; ticketing: Ticketing | null; busy: boolean; disabled?: boolean; onCreate: () => void; onPreview: () => void }) {
  if (ticket) return <a className="ticket-link" href={ticket.url} target="_blank" rel="noopener noreferrer" title={ticket.title}><ProviderIcon provider={ticket.provider} size={14} />{providerName(ticket.provider)} {ticket.externalKey}<ExternalLink size={12} /></a>;
  const live = !!ticketing?.configured;
  return <span className="ticket-action">
    {live && <button className="icon-button" aria-label="Preview ticket text" title="Preview ticket text" disabled={busy || disabled} onClick={onPreview}><Eye size={16} /></button>}
    <button className="button" disabled={busy || disabled} onClick={live ? onCreate : onPreview}><ProviderIcon provider={ticketing?.provider ?? null} />{busy ? 'Filing…' : ticketing?.provider === 'github' && live ? 'Create GitHub issue' : ticketing?.provider === 'jira' && live ? 'Create Jira ticket' : 'Preview ticket'}</button>
  </span>;
}

export function TicketPreview({ preview, ticketing, onClose, onCreate }: { preview: TicketPreviewData; ticketing: Ticketing | null; onClose: () => void; onCreate: () => void }) {
  const [copied, setCopied] = useState(false);
  const text = `# ${preview.title}\n\n${preview.markdown}\n`;
  const copy = () => navigator.clipboard?.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1800); }).catch(() => {});
  const save = () => { const url = URL.createObjectURL(new Blob([text], { type: 'text/markdown' })); const a = document.createElement('a'); a.href = url; a.download = `${preview.key.replace(/[^\w.+-]+/g, '-')}.md`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); };
  return <div className="modal-backdrop center" onClick={onClose}><section className="integration-modal ticket-preview" role="dialog" aria-modal="true" aria-label="Ticket preview" onClick={e => e.stopPropagation()}>
    <div className="drawer-top"><div><div className="eyebrow">{preview.configured ? `${providerName(preview.provider)} · ${ticketing?.target}` : 'Ticket preview · not sent'}</div><h2>{preview.title}</h2></div><button className="icon-button" aria-label="Close preview" onClick={onClose}><X size={20} /></button></div>
    {!preview.configured && <p className="ticket-note">No tracker is connected, so nothing was filed. Connect GitHub Issues or Jira in <code>aegis-app/.env.local</code> (see README), or copy this into your own tracker.</p>}
    <div className="ticket-labels">{preview.labels.map(l => <span key={l} className="tiny-pill">{l}</span>)}</div>
    <pre>{preview.markdown}</pre>
    <div className="ticket-preview-actions"><button className="button" onClick={copy}>{copied ? <Check size={15} /> : <Copy size={15} />}{copied ? 'Copied' : 'Copy Markdown'}</button><button className="button" onClick={save}><Download size={15} />Download .md</button>{preview.configured && <button className="button primary" onClick={onCreate}><ProviderIcon provider={preview.provider} />{preview.provider === 'github' ? 'Create GitHub issue' : 'Create Jira ticket'}</button>}</div>
  </section></div>;
}
