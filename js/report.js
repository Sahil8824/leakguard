// Report generation. Findings never carry raw secret values, so reports cannot leak them.
export const csvCell = (value) => {
  let s = String(value ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; // spreadsheet formula-injection guard
  return `"${s.replace(/"/g, '""')}"`;
};

export function buildReport(result, now = new Date()) {
  return {
    tool: 'LeakGuard', generatedAt: now.toISOString(),
    disclaimer: 'Findings are potential exposures found by heuristics; verify each one manually.',
    summary: result.summary,
    findings: result.findings.map(({ ruleId, severity, type, file, line, column, maskedValue, reason, remediation, heuristic }) =>
      ({ ruleId, severity, type, file, line, column, maskedValue, heuristic, reason, remediation })),
  };
}
export const toJSON = (result) => JSON.stringify(buildReport(result), null, 2);

export function toCSV(result) {
  const cols = ['ruleId', 'severity', 'type', 'file', 'line', 'column', 'maskedValue', 'reason', 'remediation'];
  const rows = result.findings.map((f) => cols.map((c) => csvCell(f[c])).join(','));
  return [cols.join(','), ...rows].join('\r\n') + '\r\n';
}
