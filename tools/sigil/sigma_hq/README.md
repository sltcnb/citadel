# Sigma HQ Rules - Imported

This directory contains **1,487 Sigma HQ rules** (critical and high severity) automatically imported from the official Sigma repository.

## Import Details

- **Source**: https://github.com/SigmaHQ/sigma
- **Import Date**: Automatically updated
- **Severity Levels**: critical, high
- **Total Rules**: 1,487
- **Categories**: 7 (organized by MITRE ATT&CK tactic)

## Organization

Rules are organized by MITRE ATT&CK tactic:

| File | Tactic | Rules |
|------|--------|-------|
| `02_execution.yaml` | Execution | 321 |
| `03_persistence.yaml` | Persistence | 321 |
| `07_discovery.yaml` | Discovery | 56 |
| `09_collection.yaml` | Collection | 32 |
| `11_exfiltration.yaml` | Exfiltration | 20 |
| `12_impact.yaml` | Impact | 38 |
| `99_other.yaml` | Other/Uncategorized | 699 |

## Rule Format

Each rule in these files follows this structure:

```yaml
category: Sigma HQ

rules:
  - name: Rule Title
    description: >-
      Rule description explaining what it detects
    artifact_type: evtx  # Automatically mapped from logsource
    # detection: (will be converted at runtime)
    sigma_detection: |
      # Original Sigma detection YAML
      condition: selection
    # level: high
    # tags: attack.execution, attack.t1059.001
    # authors: John Doe
    # sigma_id: abc12345-6789-...
```

## How It Works

1. **At Runtime**: When you run these rules against a case, Citadel uses the `pysigma` library to convert the `sigma_detection` YAML into an Elasticsearch query.

2. **Automatic Mapping**: The `artifact_type` is automatically determined based on the Sigma `logsource`:
   - Windows logs → `evtx`
   - Linux logs → `syslog`
   - Network logs → `suricata`
   - Web server logs → `access_log`

3. **Conversion**: The actual Sigma → Elasticsearch conversion happens in `api/services/sigma_sync.py` using the `LuceneBackend` from `pysigma-backend-elasticsearch`.

## Updating Rules

To update to the latest Sigma HQ rules:

```bash
cd /Users/nbuisson/Tools/dfir/citadel
source .venv/bin/activate
python3 scripts/import_sigma_hq_simple.py --levels critical,high
```

To import all severity levels (includes low, medium, high, critical - ~4,000+ rules):

```bash
python3 scripts/import_sigma_hq_simple.py --levels ""
```

## Using These Rules

### Via UI

1. Navigate to **Alert Rules** in the Citadel UI
2. Click **Load Default Rules** or **Import Sigma**
3. Select rules from the `sigma_hq` directory

### Via API

```bash
# Sync to Redis (makes rules available in UI)
curl -X POST http://localhost/api/v1/sigma/sync \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"levels": ["critical", "high"]}'

# List imported rules
curl http://localhost/api/v1/sigma/rules \
  -H "Authorization: Bearer $TOKEN"
```

### Run Against a Case

1. Go to a case's **Alert Rules** page
2. Click **Run Library Rules** or select specific rules
3. Review matches in the results panel

## Customizing Rules

You can modify these rules directly in the YAML files:

1. Edit the `sigma_detection` field with your custom detection logic
2. Update the `artifact_type` if needed
3. Save the file
4. Re-import or reload rules in the UI

**Note**: Changes to these files require reloading the rules in the UI or re-running the sync API endpoint.

## Troubleshooting

### Rules Not Appearing in UI

1. Ensure the `sigma_hq` directory is in `tools/sigil/`
2. Run the sync endpoint to load rules into Redis:
   ```bash
   curl -X POST http://localhost/api/v1/sigma/sync ...
   ```
3. Refresh the Alert Rules page

### Conversion Errors

If a rule fails to convert at runtime:
1. Check the API logs for conversion errors
2. The rule may use unsupported Sigma features
3. Try simplifying the detection logic

## Credits

- **Original Rules**: Sigma HQ contributors (https://github.com/SigmaHQ/sigma)
- **License**: [LGPL-2.1](https://github.com/SigmaHQ/sigma/blob/master/LICENSE)
- **Import Script**: `scripts/import_sigma_hq_simple.py`

## See Also

- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [Sigma HQ GitHub](https://github.com/SigmaHQ/sigma)
- [Citadel Sigma Integration](../../routers/sigma_sync.py)
