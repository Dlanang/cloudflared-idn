import React from "react";
import { motion } from "framer-motion";
import {
  Activity,
  LineChart,
  ShieldAlert,
  Cloud,
  Download,
  Filter,
  Box,
  Lock,
  TerminalSquare,
  ArrowRight,
  Github,
  ExternalLink,
  CheckCircle2,
  Copy,
} from "lucide-react";

/**
 * KISS + Patternized
 * - Config-first: UI driven by plain objects
 * - Tiny atoms: Button, Card, SectionTitle, etc.
 * - Reusable Motion wrapper to avoid duplicate props
 * - No unnecessary abstractions; single-file for now
 */

// ------------------------------
// Config (single source of truth)
// ------------------------------
const NAV = [
  { label: "Fitur", href: "#fitur" },
  { label: "Teknologi", href: "#teknologi" },
  { label: "Demo", href: "#demo" },
  { label: "FAQ", href: "#faq" },
];

const STATS = [
  { icon: Activity, label: "Events/min", value: "~1.2k" },
  { icon: ShieldAlert, label: "Alerts", value: "~230" },
  { icon: LineChart, label: "Throughput", value: "~180 Mbps" },
];

const FEATURES = [
  { icon: Filter, title: "Live tail + filter", desc: "Streaming eve.json dengan query sederhana (event_type, src_ip, signature)." },
  { icon: LineChart, title: "Grafik event & alert", desc: "Sparkline & mini chart untuk tren menit‑an atau jam‑an." },
  { icon: Download, title: "Unduh CSV & JSONL", desc: "Ambil subset data untuk analisis lanjutan di Python/R/SIEM." },
  { icon: Lock, title: "Basic Auth", desc: "Caddy reverse proxy dengan kredensial demo untuk akses cepat." },
  { icon: Box, title: "Ringan", desc: "Vite + React (landing), Streamlit 1.37 (Python 3.11) untuk UI log." },
  { icon: Cloud, title: "Tunnel", desc: "Expose lokal aman via Cloudflared Tunnel tanpa fixed IP." },
];

const TECHS = [
  { name: "Streamlit 1.37", icon: TerminalSquare },
  { name: "Caddy Reverse Proxy", icon: Lock },
  { name: "Vite + React", icon: Box },
  { name: "Cloudflared Tunnel", icon: Cloud },
];

const CREDS = [
  { user: "fox", pass: "foxziemalam999" },
  { user: "adit", pass: "aditidn123" },
  { user: "bebek", pass: "bebekcantik123" },
];

const FAQS = [
  {
    q: "Apakah butuh VPS?",
    a: "Tidak wajib. Kamu bisa expose lokal via Cloudflared Tunnel. VPS disarankan untuk uptime & IP publik statis.",
  },
  { q: "Apakah data bisa di‑export?", a: "Ya, subset query dapat diunduh sebagai CSV atau JSONL untuk analisis lanjutan." },
  { q: "Autentikasi seperti apa?", a: "Basic Auth di layer proxy (Caddy). Untuk produksi, tambah IP allow‑list & OAuth/SSO." },
  { q: "Seberapa ringan?", a: "Landing Vite + React, backend Streamlit. Tuning Suricata & ruleset menentukan footprint." },
];

// ------------------------------
// Utils
// ------------------------------
const cn = (...xs) => xs.filter(Boolean).join(" ");
const copy = (text) => navigator.clipboard?.writeText(text).catch(() => {});

// Motion container to cut repetition
const M = ({ as: Tag = "div", children, delay = 0, ...rest }) => (
  <motion.div
    initial={{ opacity: 0, y: 10 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.6, delay }}
    {...rest}
  >
    {children}
  </motion.div>
);

// ------------------------------
// Atoms
// ------------------------------
const Container = ({ className, children }) => (
  <div className={cn("mx-auto max-w-7xl px-4 sm:px-6 lg:px-8", className)}>{children}</div>
);

const Button = ({ as: Tag = "a", variant = "solid", className, children, ...props }) => {
  const base = "inline-flex items-center gap-2 rounded-xl px-5 py-3 font-medium transition-colors";
  const variants = {
    solid: "bg-emerald-500 hover:bg-emerald-400 text-zinc-950",
    outline: "border border-white/10 hover:border-white/20",
  };
  return (
    <Tag className={cn(base, variants[variant], className)} {...props}>
      {children}
    </Tag>
  );
};

const Card = ({ className, children }) => (
  <div className={cn("rounded-2xl border border-white/10 p-5", className)}>{children}</div>
);

const SectionTitle = ({ title, subtitle }) => (
  <div className="max-w-2xl">
    <h2 className="text-2xl font-semibold">{title}</h2>
    <p className="mt-1 text-zinc-400">{subtitle}</p>
  </div>
);

const Stat = ({ icon: Icon, label, value }) => (
  <Card>
    <div className="flex items-center gap-2 text-zinc-400 text-xs">
      <Icon className="size-4 text-emerald-400" />
      {label}
    </div>
    <div className="mt-1 text-2xl font-semibold">{value}</div>
  </Card>
);

const Feature = ({ icon: Icon, title, desc }) => (
  <Card>
    <div className="flex items-center gap-3">
      <div className="size-9 grid place-items-center rounded-xl bg-emerald-500/15 ring-1 ring-emerald-400/30">
        <Icon className="size-5 text-emerald-400" />
      </div>
      <div>
        <div className="font-medium">{title}</div>
        <div className="text-sm text-zinc-400">{desc}</div>
      </div>
    </div>
  </Card>
);

const Tech = ({ name, icon: Icon }) => (
  <Card className="flex items-center gap-3">
    <Icon className="size-6 text-emerald-400" />
    <div>
      <div className="font-medium">{name}</div>
      <div className="text-xs text-zinc-400">Production‑ready</div>
    </div>
  </Card>
);

const Faq = ({ q, a }) => (
  <details className="rounded-2xl border border-white/10 p-5 group open:bg-white/[0.02]">
    <summary className="cursor-pointer list-none flex items-center justify-between">
      <span className="font-medium">{q}</span>
      <span className="text-zinc-400 group-open:rotate-90 transition-transform">›</span>
    </summary>
    <p className="mt-3 text-sm text-zinc-300">{a}</p>
  </details>
);

// ------------------------------
// App
// ------------------------------
export default function App() {
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 selection:bg-emerald-500/30 selection:text-emerald-200">
      {/* Background */}
      <div className="fixed inset-0 -z-10">
        <div className="absolute inset-0 bg-[radial-gradient(60%_40%_at_50%_-10%,rgba(16,185,129,0.15),rgba(0,0,0,0))]" />
        <div className="absolute inset-0 bg-[radial-gradient(60%_40%_at_50%_110%,rgba(99,102,241,0.12),rgba(0,0,0,0))]" />
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
      </div>

      {/* Navbar */}
      <header className="sticky top-0 z-40 backdrop-blur supports-[backdrop-filter]:bg-zinc-950/40 border-b border-white/5">
        <Container className="h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="size-8 grid place-items-center rounded-xl bg-emerald-500/15 ring-1 ring-emerald-400/30">
              <ShieldAlert className="size-5 text-emerald-400" />
            </div>
            <span className="font-semibold tracking-tight">Suricata Monitor</span>
          </div>
          <nav className="hidden md:flex items-center gap-6 text-sm text-zinc-300">
            {NAV.map((n) => (
              <a key={n.href} href={n.href} className="hover:text-white">
                {n.label}
              </a>
            ))}
          </nav>
          <div className="flex items-center gap-3">
            <Button href="/monitor" className="px-4 py-2 text-sm">
              Masuk Dashboard <ArrowRight className="size-4" />
            </Button>
          </div>
        </Container>
      </header>

      {/* Hero */}
      <section className="relative">
        <Container>
          <div className="grid lg:grid-cols-2 gap-10 pt-16 pb-10">
            <M>
              <h1 className="text-4xl sm:text-5xl font-bold tracking-tight leading-tight">
                Monitoring <span className="text-emerald-400">Suricata</span>
              </h1>
              <p className="mt-4 text-lg text-zinc-300">
                Untuk menyelesaikan tugas akhir dari <b className="text-white">ID‑NETWORKERS</b>. Dashboard menampilkan log
                <code className="mx-1 text-emerald-300">eve.json</code>, grafik singkat, dan unduhan CSV/JSON.
              </p>
              <div className="mt-8 flex flex-wrap items-center gap-3">
                <Button href="/monitor">
                  <TerminalSquare className="size-5" /> Masuk ke Dashboard
                </Button>
                <Button href="/docs" variant="outline">
                  <ExternalLink className="size-5" /> Dokumentasi
                </Button>
                <Button href="https://github.com/" variant="outline">
                  <Github className="size-5" /> Source
                </Button>
              </div>

              {/* Stats */}
              <div className="mt-10 grid grid-cols-3 gap-4 max-w-lg">
                {STATS.map((s) => (
                  <Stat key={s.label} {...s} />
                ))}
              </div>
            </M>

            {/* Code/Preview Card */}
            <M delay={0.1}>
              <div className="relative rounded-3xl border border-white/10 bg-zinc-900/60 backdrop-blur p-4 lg:p-6 shadow-2xl">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs text-zinc-400">
                    <div className="size-2 rounded-full bg-rose-400" />
                    <div className="size-2 rounded-full bg-amber-400" />
                    <div className="size-2 rounded-full bg-emerald-400" />
                    <span className="ml-2">tail -f /var/log/suricata/eve.json</span>
                  </div>
                  <span className="text-xs text-zinc-400">Live</span>
                </div>
                <pre className="mt-4 h-72 overflow-auto rounded-2xl bg-black/60 p-4 text-xs leading-relaxed text-emerald-200/90">{`
{"timestamp":"2025-08-11T14:22:10Z","event_type":"alert","src_ip":"192.168.10.5","dest_ip":"10.10.10.12","alert":{"signature":"ET WEB_SERVER Possible SQLi UNION SELECT","severity":2}}
{"timestamp":"2025-08-11T14:22:11Z","event_type":"dns","query":"suspicious.example","rrtype":"A","rcode":"NOERROR"}
{"timestamp":"2025-08-11T14:22:12Z","event_type":"flow","app_proto":"http","bytes_toserver":9831,"bytes_toclient":12044}
`}</pre>
                <div className="mt-3 flex items-center justify-between text-xs text-zinc-400">
                  <div className="flex items-center gap-3">
                    <div className="inline-flex items-center gap-1"><Filter className="size-4 text-emerald-400" /> filter: <code>event_type:alert</code></div>
                    <div className="inline-flex items-center gap-1"><Download className="size-4 text-emerald-400" /> export: CSV · JSONL</div>
                  </div>
                  <div className="inline-flex items-center gap-1"><Cloud className="size-4 text-emerald-400" /> Cloudflared Tunnel</div>
                </div>
              </div>
            </M>
          </div>
        </Container>
      </section>

      {/* Features */}
      <section id="fitur" className="py-12 sm:py-16">
        <Container>
          <SectionTitle title="Fitur" subtitle="Semua yang kamu butuhkan untuk observasi cepat" />
          <div className="mt-8 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map((f) => (
              <Feature key={f.title} {...f} />
            ))}
          </div>
        </Container>
      </section>

      {/* Tech */}
      <section id="teknologi" className="py-12 sm:py-16 border-t border-white/5">
        <Container>
          <SectionTitle title="Teknologi" subtitle="Komponen utama deployment" />
          <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {TECHS.map((t) => (
              <Tech key={t.name} {...t} />
            ))}
          </div>
        </Container>
      </section>

      {/* Demo creds */}
      <section id="demo" className="py-12 sm:py-16">
        <Container>
          <SectionTitle title="Demo Credentials" subtitle="Gunakan saat diminta Basic Auth (Caddy)." />
          <div className="mt-6 grid gap-4 lg:grid-cols-2">
            <Card>
              <div className="text-sm text-zinc-400">Akun Demo</div>
              <div className="mt-3 divide-y divide-white/5">
                {CREDS.map((c) => (
                  <div key={c.user} className="py-3 flex items-center justify-between">
                    <div>
                      <div className="font-mono text-sm">{c.user}</div>
                      <div className="text-xs text-zinc-400">{c.pass}</div>
                    </div>
                    <button
                      onClick={() => copy(`${c.user}:${c.pass}`)}
                      className="inline-flex items-center gap-2 rounded-lg border border-white/10 px-3 py-1.5 text-xs hover:border-white/20"
                    >
                      <Copy className="size-3.5" /> salin
                    </button>
                  </div>
                ))}
              </div>
            </Card>

            <Card className="bg-gradient-to-b from-white/5 to-transparent">
              <div className="text-sm text-zinc-400">Contoh Konfigurasi Caddy (Basic Auth)</div>
              <pre className="mt-3 text-xs bg-black/50 rounded-xl p-4 overflow-auto">{`# Caddyfile
:443 {
  encode gzip
  tls you@example.com
  @protected {
    path /monitor*
  }
  basicauth @protected {
    fox    JDJhJDEwJG... # htpasswd hash
    adit   JDJhJDEwJG...
    bebek  JDJhJDEwJG...
  }
  reverse_proxy 127.0.0.1:8501
}
`}</pre>
            </Card>
          </div>
        </Container>
      </section>

      {/* FAQ */}
      <section id="faq" className="py-12 sm:py-16 border-t border-white/5">
        <Container>
          <SectionTitle title="FAQ" subtitle="Pertanyaan umum terkait setup" />
          <div className="mt-6 grid gap-4 lg:grid-cols-2">
            {FAQS.map((f) => (
              <Faq key={f.q} {...f} />
            ))}
          </div>
        </Container>
      </section>

      {/* Footer */}
      <footer className="mt-10 border-t border-white/5">
        <Container>
          <div className="py-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-zinc-400">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="size-4 text-emerald-400" />
              <span>© {new Date().getFullYear()} Suricata Monitor • ID‑NETWORKERS TA</span>
            </div>
            <div className="flex items-center gap-5">
              <a href="/monitor" className="hover:text-white inline-flex items-center gap-1">
                <TerminalSquare className="size-4" /> Dashboard
              </a>
              <a href="/docs" className="hover:text-white inline-flex items-center gap-1">
                <ExternalLink className="size-4" /> Docs
              </a>
              <a href="https://github.com/" className="hover:text-white inline-flex items-center gap-1">
                <Github className="size-4" /> GitHub
              </a>
            </div>
          </div>
        </Container>
      </footer>
    </div>
  );
}
