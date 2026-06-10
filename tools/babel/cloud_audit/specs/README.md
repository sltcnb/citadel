# Cloud / identity mapping specs

Each `*.yaml` here teaches the `cloud_audit` parser one log source. The parser
itself has no provider logic — it loads these specs and runs the shared
`citadel_contracts.mapping` engine. **Add a source = add a YAML file. No code.**

## Schema

```yaml
name: my_source            # unique id (also the artifact_type unless overridden)
artifact_type: my_source   # optional; timeline/index type
os: cloud                  # os family for filtering (windows|linux|macos|mobile|cloud|cross)
priority: 100              # higher wins when several specs could match

detect:                    # how to recognise a record (all present rules must hold)
  all: [pathA, pathB]      # every path must resolve to a non-null value
  any: [pathC, pathD]      # at least one must be non-null
  equals: {path: value}    # exact match
  any_equals: {path: [v1, v2]}

timestamp: [eventTime, time]   # first non-empty wins; canonicalised to ...Z

message: "{eventName} by {user.name} from {sourceIPAddress}"   # {path|tf} tokens

fields:                    # canonical event path  <-  source path|transforms
  user.email: userPrincipalName
  user.name:  userPrincipalName|user_of
  network.src_ip: ipAddress|ip

attributes:                # extra columns, namespaced under artifact_type
  app: appDisplayName
  result: status.errorCode

envelope: Records          # optional: path to the records array in the file
```

## Paths

Dotted, with numeric list indices: `protoPayload.authenticationInfo.principalEmail`,
`target.0.displayName`. A missing hop yields nothing (no error).

## Transforms (pipe-chained: `path|tf1|tf2`)

`lower` `upper` `strip` `str` `int` `float` `bool` `ip` (strip :port/brackets/zone)
`basename` `first` `last` `join` `domain_of` (`a@b`→`b`) `user_of` (`a@b`→`a`)

Register more at runtime with `citadel_contracts.register_transform(name, fn)`.

## Canonical target fields

Map into the ForensicEvent shape so the timeline lights up:
`host.hostname` `host.ip` · `user.name` `user.email` `user.id` `user.domain` ·
`network.src_ip` `network.dest_ip` `network.protocol` · `process.name` `process.pid`.
Everything else goes under `attributes` (becomes `<artifact_type>.<key>`).

## Test it

Add a one-record sample to `tools/babel/tests/test_cloud_audit.py` (`ALL_DOCS`)
— the parametrised tests then assert it detects to exactly one spec and maps to a
valid event.
```
cd tools && pytest babel/tests/test_cloud_audit.py -q
```
