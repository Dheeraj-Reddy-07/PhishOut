import { useEffect, useRef } from 'react';
import { Terminal } from 'lucide-react';

const TYPE_CLASSES = {
  sys:  'log-sys',
  err:  'log-err',
  warn: 'log-warn',
  ok:   'log-ok',
  info: 'log-info',
};

export default function DiagnosticsTerminal({ logs }) {
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="panel terminal-panel">
      <div className="panel-header">
        <Terminal size={17} className="panel-icon" />
        <h2>Diagnostics Monitor</h2>
      </div>

      <div className="terminal-window">
        {logs.map((log, i) => (
          <p key={i} className={TYPE_CLASSES[log.type] || 'log-info'}>
            <span style={{ opacity: 0.45 }}>[{log.time}] &gt; </span>
            {log.msg}
          </p>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
