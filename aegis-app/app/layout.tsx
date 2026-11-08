import type { Metadata } from 'next';
import './globals.css';
export const metadata: Metadata = { title: 'Aegis — Pre-breach intelligence', description: 'Know what matters. Defend what comes next.', icons: { icon: '/favicon.svg' } };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body>{children}</body></html>; }
