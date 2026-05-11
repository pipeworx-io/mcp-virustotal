interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}

interface McpToolExport {
  tools: McpToolDefinition[];
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  meter?: { credits: number };
  cost?: Record<string, unknown>;
  provider?: string;
}

/**
 * VirusTotal MCP — file / URL / domain / IP reputation (BYO key)
 *
 * Free tier is 4 lookups/min and 500/day per key, so this pack is BYO-only.
 * For platform-key use the operator should expose a separate paid VT key
 * (this pack reads _apiKey directly).
 *
 * API: https://docs.virustotal.com/reference
 * Tools:
 * - lookup_file:   sha256 / sha1 / md5 report
 * - lookup_url:    URL report (deterministic id; no submit step needed)
 * - lookup_domain: domain report (resolutions, related files, communicating samples)
 * - lookup_ip:     IP report (geo, AS, related URLs, communicating files)
 */


const BASE_URL = 'https://www.virustotal.com/api/v3';

const tools: McpToolExport['tools'] = [
  {
    name: 'lookup_file',
    description:
      'Look up a file by hash (sha256, sha1, or md5). Returns last-analysis stats (malicious / suspicious / harmless / undetected detector counts), type description, size, names seen, and tags. Useful for triaging hashes seen in alerts or logs.',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'SHA-256 / SHA-1 / MD5 of the file' },
      },
      required: ['hash'],
    },
  },
  {
    name: 'lookup_url',
    description:
      'Look up a URL\'s reputation. Returns last-analysis stats across all engines, categories (per vendor), and whether the URL has been redirected. The URL is canonicalized before lookup; no submission step is required to read existing reports.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'Full URL including scheme' },
      },
      required: ['url'],
    },
  },
  {
    name: 'lookup_domain',
    description:
      'Look up a domain. Returns last-analysis stats, categories per vendor, last DNS records, popularity ranks, and reputation score.',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string', description: 'FQDN (no scheme)' },
      },
      required: ['domain'],
    },
  },
  {
    name: 'lookup_ip',
    description:
      'Look up an IPv4 address. Returns last-analysis stats, ASN/owner, country, network range, and reputation score.',
    inputSchema: {
      type: 'object',
      properties: {
        ip: { type: 'string', description: 'IPv4 address' },
      },
      required: ['ip'],
    },
  },
];

async function callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  const apiKey = (args._apiKey as string | undefined)?.trim();
  if (!apiKey) {
    throw new Error(
      'VirusTotal requires a BYO API key (free tier 4 req/min, 500/day). Pass ?_apiKey=<key>. Register at https://www.virustotal.com/gui/join-us',
    );
  }
  switch (name) {
    case 'lookup_file':
      return lookup(apiKey, 'files', String(args.hash).toLowerCase().trim());
    case 'lookup_url':
      return lookup(apiKey, 'urls', urlId(String(args.url)));
    case 'lookup_domain':
      return lookup(apiKey, 'domains', String(args.domain).trim().toLowerCase());
    case 'lookup_ip':
      return lookup(apiKey, 'ip_addresses', String(args.ip).trim());
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

function urlId(url: string): string {
  // VT URL identifier: unpadded base64url of the URL string
  const bytes = new TextEncoder().encode(url);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

interface VtData {
  data?: {
    id?: string;
    type?: string;
    attributes?: Record<string, unknown> & {
      last_analysis_stats?: { malicious?: number; suspicious?: number; harmless?: number; undetected?: number; timeout?: number };
      reputation?: number;
      total_votes?: { harmless?: number; malicious?: number };
      tags?: string[];
      last_analysis_date?: number;
    };
  };
  error?: { code?: string; message?: string };
}

async function lookup(apiKey: string, kind: string, id: string) {
  if (!id) throw new Error(`Missing identifier for ${kind}`);
  const res = await fetch(`${BASE_URL}/${kind}/${encodeURIComponent(id)}`, {
    headers: { 'x-apikey': apiKey, Accept: 'application/json' },
  });
  if (res.status === 401 || res.status === 403) throw new Error('VirusTotal: unauthorized — check the API key');
  if (res.status === 404) throw new Error(`VirusTotal: no report for ${kind} "${id}"`);
  if (res.status === 429) throw new Error('VirusTotal: rate-limit hit (free tier is 4 req/min, 500/day)');
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`VirusTotal error: ${res.status} ${body.slice(0, 200)}`);
  }
  const data = (await res.json()) as VtData;
  return normalize(kind, data);
}

function normalize(kind: string, data: VtData) {
  const d = data.data;
  if (!d) throw new Error('VirusTotal: empty response');
  const a = d.attributes ?? {};
  const stats = a.last_analysis_stats ?? {};
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const harmless = stats.harmless ?? 0;
  const undetected = stats.undetected ?? 0;
  const total = malicious + suspicious + harmless + undetected;

  return {
    type: d.type ?? kind,
    id: d.id ?? null,
    stats: {
      malicious,
      suspicious,
      harmless,
      undetected,
      total_engines: total,
      malicious_pct: total > 0 ? Number(((malicious / total) * 100).toFixed(1)) : 0,
    },
    reputation: a.reputation ?? null,
    community_votes: a.total_votes ?? null,
    tags: a.tags ?? [],
    last_analyzed_at: a.last_analysis_date ? new Date(a.last_analysis_date * 1000).toISOString() : null,
    raw_attributes: a,
    vt_url: buildVtUrl(kind, d.id),
  };
}

function buildVtUrl(kind: string, id?: string): string | null {
  if (!id) return null;
  if (kind === 'files') return `https://www.virustotal.com/gui/file/${id}`;
  if (kind === 'urls') return `https://www.virustotal.com/gui/url/${id}`;
  if (kind === 'domains') return `https://www.virustotal.com/gui/domain/${id}`;
  if (kind === 'ip_addresses') return `https://www.virustotal.com/gui/ip-address/${id}`;
  return null;
}

export default { tools, callTool, meter: { credits: 3 } } satisfies McpToolExport;
