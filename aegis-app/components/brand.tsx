/** Inline brand marks. No external requests; all render crisply at 14-24px. */
type MarkProps = { size?: number; className?: string };
const box = (size: number) => ({ width: size, height: size, flexShrink: 0, display: 'block' as const });

export function GitHubMark({ size = 16, className }: MarkProps) {
 return <svg viewBox="0 0 16 16" style={box(size)} className={className} fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>;
}

export function NpmMark({ size = 16, className }: MarkProps) {
 return <svg viewBox="0 0 24 24" style={box(size)} className={className} fill="currentColor" aria-hidden="true"><path d="M1.763 0C.786 0 0 .786 0 1.763v20.474C0 23.214.786 24 1.763 24h20.474c.977 0 1.763-.786 1.763-1.763V1.763C24 .786 23.214 0 22.237 0ZM5.13 5.323l13.837.019-.009 13.836h-3.464l.01-10.382h-3.456L12.04 19.17H5.113Z"/></svg>;
}

/** Cursor's hexagonal prism mark, drawn as three shaded faces. */
export function CursorMark({ size = 16, className }: MarkProps) {
 return <svg viewBox="0 0 24 24" style={box(size)} className={className} aria-hidden="true">
  <path d="M12 1.5 22.4 7.5v9L12 22.5 1.6 16.5v-9Z" fill="currentColor" opacity=".16"/>
  <path d="M12 1.5 22.4 7.5 12 13.5Z" fill="currentColor" opacity=".9"/>
  <path d="M12 13.5 22.4 7.5v9Z" fill="currentColor" opacity=".55"/>
  <path d="M1.6 7.5 12 13.5v9L1.6 16.5Z" fill="currentColor" opacity=".75"/>
 </svg>;
}

/** Claude's radial burst. */
export function ClaudeMark({ size = 16, className }: MarkProps) {
 const rays = [0, 30, 60, 90, 120, 150].map((deg, i) => (
  <rect key={i} x="11.1" y="1.6" width="1.8" height="20.8" rx=".9" transform={`rotate(${deg} 12 12)`} />
 ));
 return <svg viewBox="0 0 24 24" style={box(size)} className={className} fill="currentColor" aria-hidden="true">{rays}</svg>;
}

/** IBM's striped wordmark: I, B and M built from eight horizontal rules. */
export function IbmMark({ size = 16, className }: MarkProps) {
 // Per stripe: the x-spans that are inked. Narrower spans in the middle rows
 // carve out the counters of the B and the M, which is what makes it read as IBM.
 const stripes: [number, number][][] = [
  [[0, 5], [7, 17], [19, 32]],
  [[0, 5], [7, 17], [19, 32]],
  [[0, 5], [7, 11], [13, 17], [19, 23], [25.5, 32]],
  [[0, 5], [7, 17], [19, 23], [26.5, 32]],
  [[0, 5], [7, 17], [19, 23], [26.5, 32]],
  [[0, 5], [7, 11], [13, 17], [19, 23], [25.5, 32]],
  [[0, 5], [7, 17], [19, 32]],
  [[0, 5], [7, 17], [19, 32]],
 ];
 return <svg viewBox="0 0 32 15" style={{ width: size * 32 / 15, height: size, flexShrink: 0, display: 'block' }} className={className} fill="currentColor" aria-hidden="true">
  {stripes.flatMap((spans, row) => spans.map(([x1, x2], i) =>
   <rect key={`${row}-${i}`} x={x1} y={row * 1.875} width={x2 - x1} height="1.15"/>
  ))}
 </svg>;
}

/** OSV.dev — advisory database. */
export function OsvMark({ size = 16, className }: MarkProps) {
 return <svg viewBox="0 0 24 24" style={box(size)} className={className} fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
  <path d="M12 2.5 20 6v6c0 4.3-3.2 7.8-8 9.5-4.8-1.7-8-5.2-8-9.5V6Z"/>
  <path d="M8.6 11.8 11 14.3l4.6-4.8"/>
 </svg>;
}

/** TigerData / Timescale — stacked time-series records. */
export function TigerDataMark({ size = 16, className }: MarkProps) {
 return <svg viewBox="0 0 24 24" style={box(size)} className={className} fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
  <ellipse cx="12" cy="5.8" rx="7.5" ry="3.1"/>
  <path d="M4.5 5.8v12.4c0 1.7 3.4 3.1 7.5 3.1s7.5-1.4 7.5-3.1V5.8"/>
  <path d="M4.5 12c0 1.7 3.4 3.1 7.5 3.1s7.5-1.4 7.5-3.1"/>
 </svg>;
}

/** Solana's three slanted bars. */
export function SolanaMark({ size = 16, className }: MarkProps) {
 return <svg viewBox="0 0 24 24" style={box(size)} className={className} fill="currentColor" aria-hidden="true">
  <path d="M6.3 16.6a.8.8 0 0 1 .55-.22h14.3c.36 0 .54.43.29.68l-2.74 2.74a.8.8 0 0 1-.55.22H3.85a.4.4 0 0 1-.29-.68Z"/>
  <path d="M6.3 4.18A.8.8 0 0 1 6.85 4h14.3c.36 0 .54.43.29.68l-2.74 2.73a.8.8 0 0 1-.55.23H3.85a.4.4 0 0 1-.29-.68Z"/>
  <path d="M18.7 10.35a.8.8 0 0 0-.55-.22H3.85a.4.4 0 0 0-.29.68l2.74 2.74c.14.14.34.22.55.22h14.3a.4.4 0 0 0 .29-.68Z"/>
 </svg>;
}

/** Ollama — local inference runtime. */
export function OllamaMark({ size = 16, className }: MarkProps) {
 return <svg viewBox="0 0 24 24" style={box(size)} className={className} fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
  <path d="M7 8.5C7 5.5 5.6 3 5.6 3S4 4.6 4 7.4"/>
  <path d="M17 8.5C17 5.5 18.4 3 18.4 3S20 4.6 20 7.4"/>
  <path d="M12 21c-4.4 0-7.2-2.4-7.2-6.4C4.8 10.4 7.9 7.5 12 7.5s7.2 2.9 7.2 7.1c0 4-2.8 6.4-7.2 6.4Z"/>
  <path d="M10 13.6h.01M14 13.6h.01"/>
 </svg>;
}

export const agentMarks = { cursor: CursorMark, claude: ClaudeMark } as const;
