type Props = {
  blocked: number;
  connected: boolean;
  total: number;
};

export default function SystemStatus({ blocked, connected, total }: Props) {
  const blockedRate = total === 0 ? 0 : Math.round((blocked / total) * 100);

  return (
    <section
      className={`system-status ${connected ? "stream-online" : "stream-offline"}`}
      aria-label="Aegis system status"
    >
      <div className="system-status-heading">
        <div>
          <span className="system-status-kicker">MONITORING</span>
          <h2>Authorization activity</h2>
        </div>
        <span className="stream-state">
          <i />
          {connected ? "EVENT STREAM LIVE" : "STREAM OFFLINE"}
        </span>
      </div>
      <div className="status-stat-grid">
        <div className="status-stat">
          <span>DECISIONS LOGGED</span>
          <strong>{total}</strong>
          <small>for the selected app</small>
        </div>
        <div className="status-stat blocked-stat">
          <span>ACTIONS BLOCKED</span>
          <strong>{blocked}</strong>
          <small>{blockedRate}% of recorded decisions</small>
        </div>
      </div>
      <div
        className="blocked-meter"
        role="meter"
        aria-label="Share of recorded decisions blocked"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={blockedRate}
      >
        <span style={{ width: `${blockedRate}%` }} />
      </div>
      <p className="system-status-note">
        This panel reflects recorded authorization decisions, not payment or email delivery.
      </p>
    </section>
  );
}
