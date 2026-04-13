# Systemd units — ChainGate collector

Install with:

```bash
sudo cp chaingate-collector-npm.service  /etc/systemd/system/
sudo cp chaingate-collector-npm.timer    /etc/systemd/system/
sudo cp chaingate-collector-pypi.service /etc/systemd/system/
sudo cp chaingate-collector-pypi.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now chaingate-collector-npm.timer
sudo systemctl enable --now chaingate-collector-pypi.timer
```

## Verify

```bash
# Is the timer armed?
systemctl list-timers chaingate-collector-npm.timer

# Trigger a run right now without waiting for the schedule
sudo systemctl start chaingate-collector-npm.service

# Watch the last run's structured logs
journalctl -u chaingate-collector-npm.service -n 100 --no-pager

# Tail live during a run
journalctl -u chaingate-collector-npm.service -f
```

## Query collector_runs for operational truth

```bash
psql "$DATABASE_URL" -c "
SELECT id, source, status, packages_attempted, versions_inserted, errors,
       round(EXTRACT(EPOCH FROM (finished_at - started_at))::numeric, 2) AS elapsed_s
  FROM collector_runs ORDER BY id DESC LIMIT 10;
"
```

## Schedule

| Source | Schedule | Installed |
|---|---|---|
| npm | `OnCalendar=hourly` (fires at :00) | ✅ |
| pypi | `OnCalendar=*:15` | ✅ |
| advisories | `OnCalendar=*:30` | ❌ not yet built |

Staggering prevents DB contention and makes failure attribution obvious.

## Uninstall

```bash
sudo systemctl disable --now chaingate-collector-npm.timer chaingate-collector-pypi.timer
sudo rm /etc/systemd/system/chaingate-collector-{npm,pypi}.{service,timer}
sudo systemctl daemon-reload
```
