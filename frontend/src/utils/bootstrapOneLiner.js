// Paste-and-run forms of a generated bootstrap script, no file transfer needed.
//
// Linux: decode and pipe to bash. Windows: decode to a temp .ps1 and run it in
// a child powershell, then delete it — the equivalent of `| bash`. Not `iex`:
// the script has a param() block and calls `exit`, which under iex would close
// the analyst's own console. Not -EncodedCommand: it caps the command line at
// ~32 KB. The file is written UTF-8 with BOM so Windows PowerShell 5.1 does not
// read it as ANSI.
export function bootstrapOneLiner(platform, script) {
  const b64 = btoa(unescape(encodeURIComponent(script)))
  if (platform === 'ps1') {
    return (
      "$f=Join-Path $env:TEMP ('fo-bootstrap-'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.ps1');" +
      `[IO.File]::WriteAllText($f,[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64}')),(New-Object Text.UTF8Encoding $true));` +
      'try{powershell -NoProfile -ExecutionPolicy Bypass -File $f}finally{Remove-Item $f -Force -ErrorAction SilentlyContinue}'
    )
  }
  return `echo "${b64}" | base64 -d | bash`
}
