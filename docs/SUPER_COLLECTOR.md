# Super Collector

The Super Collector is the source-discovery stage that runs before the existing SmartSub ingestion and quality pipeline.

## Current discovery engines

- GitHub repository search for V2Ray, Clash, sing-box, and public proxy subscription projects
- Bounded Git tree inspection for likely subscription/config artifacts
- DuckDuckGo HTML search for public subscription pages and repositories
- Scrapling HTTP fetching, with Scrapling's headless browser fetcher as a fallback for JavaScript-rendered pages
- Bounded same-host page crawling from discovered pages

The default run is bounded to 40 repositories and 80 pages. Workflow overrides are available through:

- `SMARTSUB_DISCOVERY_MAX_REPOS`
- `SMARTSUB_DISCOVERY_MAX_PAGES`

The command can also be run locally:

```bash
python -m pip install -r requirements.txt
scrapling install
python scripts/super_collector.py
```

## Output and integration

- `runtime/super_collector_sources.txt`: candidate subscription/config URLs
- `runtime/super_collector_pages.txt`: discovered public pages for the existing page extractor
- `super_collector_report.json`: bounded discovery counters and output locations

`main.py` loads these runtime lists and passes them through the existing subscription validation and deduplication. The strict Cloud Robot stage remains the final admission gate. A discovered URL or parsed node is never published merely because it was found.

## Safety and limits

- Only HTTPS destinations resolving to public IP addresses are accepted during discovery.
- URL credentials, localhost, private, loopback, link-local, and reserved addresses are rejected.
- Repository and page counts are capped; page link extraction is capped per page.
- GitHub API rate limits, search-engine indexing, robots policies, site availability, and anti-bot challenges limit discovery coverage.
- The browser fallback is a fetch mechanism, not a guarantee that every protected site can be accessed.
- This is a broad, continuously extensible discovery layer, not a claim that every public source on the internet can be enumerated in one run.
