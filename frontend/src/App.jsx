import { useMemo, useState, useEffect } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";
const OPERATIONS = ["analysis", "export", "storage", "logging"];

function riskTone(label) {
  if (label === "CRITICAL" || label === "HIGH") return "text-warn";
  if (label === "MEDIUM") return "text-pseudo";
  return "text-accent";
}

function tagClass(kind) {
  if (kind === "redact" || kind === "block") return "bg-red-100 text-red-800 border-red-300";
  if (kind === "pseudo") return "bg-amber-100 text-amber-800 border-amber-300";
  return "bg-slate-100 text-slate-700 border-slate-300";
}

function tokenizeSanitized(text) {
  const regex = /(\[REDACTED\]|\[BLOCKED\]|\b[A-Z]+_\d{2,}\b)/g;
  const tokens = [];
  let last = 0;
  let match;

  while ((match = regex.exec(text)) !== null) {
    if (match.index > last) tokens.push({ value: text.slice(last, match.index), kind: "plain" });
    const token = match[0];
    let kind = "pseudo";
    if (token === "[REDACTED]") kind = "redact";
    if (token === "[BLOCKED]") kind = "block";
    tokens.push({ value: token, kind });
    last = regex.lastIndex;
  }
  if (last < text.length) tokens.push({ value: text.slice(last), kind: "plain" });

  return tokens;
}

function inferRuleNumber(rules, operation, entity) {
  if (!rules?.length || !entity) return null;

  const op = String(operation || "").toLowerCase();
  const et = String(entity.entity_type || "").toUpperCase();

  for (let i = 0; i < rules.length; i += 1) {
    const r = rules[i];
    const opMatch = r.operation === "*" || String(r.operation).toLowerCase() === op;
    const etMatch = r.entity_type === "*" || String(r.entity_type).toUpperCase() === et;
    if (opMatch && etMatch) {
      return i + 1;
    }
  }
  return null;
}

export default function App() {
  const [inputText, setInputText] = useState(`Login failed for john@company.com from 192.168.1.105\nCustomer CUST-7823 called support.`);
  const [operation, setOperation] = useState("analysis");
  const [result, setResult] = useState(null);
  const [uploadName, setUploadName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const [rules, setRules] = useState([]);
  const [analysis, setAnalysis] = useState(null);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [sessionId, setSessionId] = useState(null);
  const [sessionMapping, setSessionMapping] = useState({});
  const [showOriginals, setShowOriginals] = useState(false);

  useEffect(() => {
    async function fetchRules() {
      try {
        const res = await fetch(`${API_BASE}/policy/rules`);
        if (!res.ok) return;
        const data = await res.json();
        setRules(Array.isArray(data.rules) ? data.rules : []);
      } catch (_e) {
        setRules([]);
      }
    }
    fetchRules();
  }, []);

  const sanitizedOutputText = useMemo(() => {
    if (!result) return "";
    const sanitized = result?.sanitized || "";
    return typeof sanitized === "string" ? sanitized : JSON.stringify(sanitized, null, 2);
  }, [result]);

  const displayText = useMemo(() => tokenizeSanitized(sanitizedOutputText), [sanitizedOutputText]);

  const entityRows = useMemo(() => {
    if (!result?.entities_found) return [];
    return result.entities_found.map((entity) => {
      const ruleNo = inferRuleNumber(rules, operation, entity);
      return {
        ...entity,
        explanation: `This field was ${entity.action} because operation=${operation} + entity=${entity.entity_type}` +
          (ruleNo ? ` matched rule #${ruleNo}.` : " matched a policy rule."),
      };
    });
  }, [result, operation, rules]);

  const actionData = useMemo(() => {
    const counts = { pseudonymize: 0, redact: 0, allow: 0, block: 0 };
    entityRows.forEach((e) => {
      const key = e.action || "allow";
      counts[key] = (counts[key] || 0) + (e.count || 1);
    });
    return [
      { name: "Pseudonymized", value: counts.pseudonymize, color: "#a16207" },
      { name: "Redacted", value: counts.redact, color: "#b91c1c" },
      { name: "Allowed", value: counts.allow, color: "#0f766e" },
      { name: "Blocked", value: counts.block, color: "#7f1d1d" },
    ].filter((d) => d.value > 0);
  }, [entityRows]);

  const riskData = useMemo(() => {
    const score = Number(result?.risk_score || 0);
    return [{ name: "Risk", score }];
  }, [result]);

  const mappingRows = useMemo(() => {
    return Object.entries(sessionMapping)
      .map(([original, token]) => ({ original, token }))
      .sort((a, b) => String(a.token).localeCompare(String(b.token)));
  }, [sessionMapping]);

  function maskOriginal(value) {
    if (showOriginals) return value;
    if (!value) return "";
    return `${"*".repeat(Math.min(8, value.length))}`;
  }

  async function ensureSession() {
    if (sessionId) return sessionId;
    const response = await fetch(`${API_BASE}/session/create`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ label: "frontend-dashboard" }),
    });
    if (!response.ok) {
      throw new Error(`Session creation failed (${response.status})`);
    }
    const data = await response.json();
    const createdSessionId = data.session_id;
    setSessionId(createdSessionId);
    return createdSessionId;
  }

  async function refreshSessionMapping(targetSessionId) {
    if (!targetSessionId) return;
    const response = await fetch(`${API_BASE}/session/${targetSessionId}?include_mapping=true`);
    if (!response.ok) return;
    const data = await response.json();
    setSessionMapping(data.mapping || {});
  }

  async function requestAnalysisFromMcp(sanitizedResult) {
    setAnalysisLoading(true);
    try {
      const sanitizedText = typeof sanitizedResult.sanitized === "string"
        ? sanitizedResult.sanitized
        : JSON.stringify(sanitizedResult.sanitized, null, 2);

      const response = await fetch(`${API_BASE}/analyze/sanitized`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sanitized_text: sanitizedText,
          operation,
          risk_label: sanitizedResult.risk_label || "NONE",
          entities_found: sanitizedResult.entities_found || [],
        }),
      });

      if (!response.ok) {
        throw new Error(`Analysis request failed (${response.status})`);
      }

      const data = await response.json();
      setAnalysis(data);
    } catch (e) {
      setAnalysis({
        summary: e.message || "Unable to fetch AI log summary.",
        key_findings: [],
        recommended_actions: [],
      });
    } finally {
      setAnalysisLoading(false);
    }
  }

  async function sanitizeNow() {
    setLoading(true);
    setError("");
    setCopied(false);
    setAnalysis(null);
    try {
      const trimmed = inputText.trim();
      if (!trimmed) {
        setError("Paste text or upload a file first.");
        setResult(null);
        return;
      }

      let endpoint = `${API_BASE}/sanitize`;
      const activeSessionId = await ensureSession();
      let payload = { text: trimmed, operation, include_mapping: true, session_id: activeSessionId };
      let mode = "text";

      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        try {
          const parsed = JSON.parse(trimmed);
          endpoint = `${API_BASE}/sanitize/schema`;
          payload = { data: parsed, operation, session_id: activeSessionId };
          mode = "json";
        } catch (_e) {
          mode = "text";
        }
      }

      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(`Request failed (${response.status})`);
      }

      const data = await response.json();
      setResult(data);
      if (data.pseudonym_mapping) {
        setSessionMapping(data.pseudonym_mapping);
      } else {
        await refreshSessionMapping(activeSessionId);
      }
      await requestAnalysisFromMcp(data);
    } catch (e) {
      setResult(null);
      setAnalysis(null);
      setError(e.message || "Unable to sanitize the input");
    } finally {
      setLoading(false);
    }
  }

  function handleUpload(file) {
    if (!file) return;
    setUploadName(file.name);
    const reader = new FileReader();
    reader.onload = (evt) => {
      setInputText(String(evt.target?.result || ""));
    };
    reader.readAsText(file);
  }

  async function copyOutput() {
    if (!result?.sanitized) return;
    const text = typeof result.sanitized === "string"
      ? result.sanitized
      : JSON.stringify(result.sanitized, null, 2);
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="min-h-screen p-4 md:p-8 text-ink">
      <div className="mx-auto max-w-7xl rounded-2xl border border-stone-300 bg-card/90 p-4 shadow-panel md:p-8">
        <header className="mb-6 flex flex-col gap-3 border-b border-stone-300 pb-4 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">PII-Safe Dashboard</h1>
            <p className="text-sm text-stone-600">Privacy middleware visualizer for logs and operational text.</p>
          </div>
          <div className="rounded-lg border border-stone-300 bg-stone-50 px-4 py-2 text-sm">
            Risk: <span className={`font-bold ${riskTone(result?.risk_label)}`}>{result?.risk_label || "NONE"}</span>
          </div>
        </header>

        <main className="grid gap-5 md:grid-cols-2">
          <section className="rounded-xl2 border border-stone-300 bg-white p-4">
            <h2 className="mb-3 text-lg font-semibold">Input Panel</h2>
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <label className="cursor-pointer rounded-md border border-stone-300 bg-stone-50 px-3 py-1.5 text-sm hover:bg-stone-100">
                Upload Log
                <input
                  type="file"
                  className="hidden"
                  accept=".txt,.log,.json"
                  onChange={(e) => handleUpload(e.target.files?.[0])}
                />
              </label>
              <span className="text-xs text-stone-500">{uploadName || "No file selected"}</span>
            </div>

            <div className="mb-3 flex items-center gap-2">
              <label className="text-sm font-medium">Operation:</label>
              <select
                className="rounded-md border border-stone-300 bg-white px-2 py-1 text-sm"
                value={operation}
                onChange={(e) => setOperation(e.target.value)}
              >
                {OPERATIONS.map((op) => (
                  <option key={op} value={op}>{op}</option>
                ))}
              </select>
            </div>

            <textarea
              className="code-view mb-3 h-56 w-full rounded-lg border border-stone-300 bg-stone-50 p-3 text-sm outline-none focus:border-accent"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder="Paste logs here"
            />

            <button
              className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
              onClick={sanitizeNow}
              disabled={loading}
            >
              {loading ? "Sanitizing..." : "Sanitize ->"}
            </button>
            {error && <p className="mt-2 text-sm text-warn">{error}</p>}
          </section>

          <section className="space-y-4">
            <div className="rounded-xl2 border border-stone-300 bg-white p-4">
              <h2 className="mb-3 text-lg font-semibold">Output Panel</h2>
              <div className="code-view h-48 overflow-y-auto whitespace-pre-wrap break-words rounded-lg border border-stone-300 bg-stone-50 p-3 text-sm leading-7">
                {result ? (
                  displayText.map((tok, idx) => (
                    <span
                      key={`${tok.value}-${idx}`}
                      className={tok.kind === "plain" ? "" : `rounded border px-1 ${tagClass(tok.kind)}`}
                    >
                      {tok.value}
                    </span>
                  ))
                ) : (
                  <span className="text-stone-500">Sanitized output will appear here.</span>
                )}
              </div>

              <div className="mt-3 flex items-center gap-2">
                <button
                  className="rounded-md border border-stone-300 bg-stone-50 px-3 py-1.5 text-sm hover:bg-stone-100"
                  onClick={copyOutput}
                  disabled={!result}
                >
                  Copy Clean Text
                </button>
                {copied && <span className="text-xs text-accent">Copied.</span>}
              </div>
            </div>
            <details className="rounded-xl2 border border-stone-300 bg-white p-4">
              <summary className="cursor-pointer text-sm font-semibold">
                Session Consistency
              </summary>
              <div className="mt-3 space-y-3">
                <div className="flex items-center justify-between gap-3 text-xs text-stone-700">
                  <span>Session ID: {sessionId || "Not created yet"}</span>
                  <button
                    className="rounded-md border border-stone-300 bg-stone-50 px-2 py-1 text-xs hover:bg-stone-100"
                    onClick={() => setShowOriginals((v) => !v)}
                    type="button"
                  >
                    {showOriginals ? "Hide originals" : "Show originals"}
                  </button>
                </div>
                <div className="max-h-44 overflow-y-auto rounded-lg border border-stone-300 bg-stone-50 p-3">
                  {mappingRows.length === 0 && (
                    <p className="text-xs text-stone-500">No pseudonym mappings yet for this session.</p>
                  )}
                  {mappingRows.length > 0 && (
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="text-stone-600">
                          <th className="pb-1 pr-2">Token</th>
                          <th className="pb-1">Original</th>
                        </tr>
                      </thead>
                      <tbody>
                        {mappingRows.map((row) => (
                          <tr key={`${row.token}-${row.original}`} className="border-t border-stone-200">
                            <td className="py-1 pr-2 font-semibold">{row.token}</td>
                            <td className="py-1">{maskOriginal(row.original)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            </details>
            <div className="rounded-xl2 border border-stone-300 bg-white p-4">
              <h3 className="mb-2 text-sm font-semibold">Entity Breakdown</h3>
              {entityRows.length === 0 && <p className="text-sm text-stone-500">No entities detected yet.</p>}
              <div className="max-h-52 space-y-3 overflow-y-auto pr-1">
                {entityRows.map((entity) => (
                  <div key={`${entity.entity_type}-${entity.action}`} className="rounded-md border border-stone-200 p-2">
                    <p className="text-sm font-semibold">
                      {entity.entity_type} <span className="capitalize">{entity.action}</span>
                    </p>
                    <p className="text-xs text-stone-700">"{entity.reason}"</p>
                    <p className="mt-1 text-xs text-stone-600">{entity.explanation}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-xl2 border border-stone-300 bg-white p-4">
              <h3 className="mb-2 text-sm font-semibold">Analysis Incident Log</h3>
              <div className="max-h-52 overflow-y-auto rounded-lg border border-stone-300 bg-stone-50 p-3 text-sm">
                {analysisLoading && <p className="text-stone-600">Generating analysis...</p>}
                {!analysisLoading && !analysis && (
                  <p className="text-stone-500">Run sanitize to generate AI summary of sanitized logs.</p>
                )}
                {!analysisLoading && analysis && (
                  <div className="space-y-2">
                    <p>{analysis.summary}</p>
                    {!!analysis.likely_incident_type && (
                      <p className="text-xs text-stone-700">
                        Incident type: {analysis.likely_incident_type}
                      </p>
                    )}
                    {!!analysis.priority && (
                      <p className="text-xs text-stone-700">
                        Priority: {analysis.priority}
                      </p>
                    )}
                    {!!analysis.source && (
                      <p className="text-xs text-stone-700">
                        Source: {analysis.source === "local" ? "Local summary" : analysis.source}
                      </p>
                    )}
                    {!!analysis.key_findings?.length && (
                      <ul className="list-disc pl-4 text-xs text-stone-700">
                        {analysis.key_findings.map((item) => <li key={item}>{item}</li>)}
                      </ul>
                    )}
                    {!!analysis.recommended_actions?.length && (
                      <ul className="list-disc pl-4 text-xs text-stone-700">
                        {analysis.recommended_actions.map((item) => <li key={item}>{item}</li>)}
                      </ul>
                    )}
                  </div>
                )}
              </div>
            </div>
          </section>
        </main>

        <section className="mt-5 grid gap-5 lg:grid-cols-2">
          <div className="rounded-xl2 border border-stone-300 bg-white p-4">
            <h3 className="mb-3 text-sm font-semibold">Risk Score</h3>
            <div className="h-40">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={riskData} layout="vertical" margin={{ left: 20, right: 20 }}>
                  <XAxis type="number" domain={[0, 1]} />
                  <YAxis dataKey="name" type="category" />
                  <Tooltip formatter={(v) => Number(v).toFixed(3)} />
                  <Bar dataKey="score" fill="#b91c1c" radius={[5, 5, 5, 5]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <p className="mt-2 text-sm">{(result?.risk_score ?? 0).toFixed(3)} {result?.risk_label || "NONE"}</p>
          </div>

          <div className="rounded-xl2 border border-stone-300 bg-white p-4">
            <h3 className="mb-3 text-sm font-semibold">Action Distribution</h3>
            <div className="h-40">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={actionData} dataKey="value" nameKey="name" outerRadius={58} label>
                    {actionData.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>
        {/* Can be added in future for more detailed pipeline step visibility, if MCP server provides audit log data in the response. */}
        {/* <section className="mt-5 rounded-xl2 border border-stone-300 bg-white p-4">
          <h3 className="text-sm font-semibold">Audit Log</h3>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
            {(result?.audit_log || []).map((log, idx) => (
              <span key={`${log.step}-${idx}`} className="rounded-full border border-stone-300 bg-stone-50 px-2 py-1">
                [{log.step}]
              </span>
            ))}
            {(result?.audit_log || []).length === 0 && <span className="text-stone-500">Run sanitize to see pipeline steps.</span>}
          </div>
        </section> */}
      </div>
    </div>
  );
}
