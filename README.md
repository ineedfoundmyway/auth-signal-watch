# Auth Signal Watch

A defensive JSONL authentication-log analyzer that detects failure bursts and a subsequent successful login inside a sliding time window.

Python 3.11+ · Standard library only · MIT · Maintained by [ineedfoundmyway](https://github.com/ineedfoundmyway)

## Run the proof

```sh
python -m unittest -v
python main.py fixtures/auth.jsonl
python scripts/prove.py
```

The checked-in [execution evidence](proof/report.json), [test transcript](proof/tests.txt), and [source hashes](proof/sha256.json) record a real local execution. Run the same commands to verify the result independently. CI regenerates evidence as an artifact on every push. Local results are not a claim that GitHub Actions has run.

## What you learn

The input schema contains timezone-aware ISO timestamps, a source IP, a user and a success/failure outcome. Events are sorted chronologically, partitioned by source and user, and compared inside a configurable inclusive window. The detector emits one burst alert when the threshold is first crossed, then a separate alert if the next success follows enough recent failures.

Try `python main.py fixtures/auth.jsonl --threshold 4` and compare the alerts. This is an offline batch analyzer: it loads the file into memory. Distributed password spraying, event IDs, allowlists and streaming ingestion are outside its current scope. Alerts require analyst review; they are not proof of compromise.

## Design and limits

This is original educational code inspired by the reading below. Article text, screenshots and third-party tool code are not bundled. Examples use synthetic data and temporary directories. No Internet targets are contacted. Results describe the supplied fixtures and do not certify a production system.

## Reading

- https://www.hackingarticles.in/detect-nmap-scan-using-snort/

## License

MIT. Third-party tools and articles retain their own licenses.
