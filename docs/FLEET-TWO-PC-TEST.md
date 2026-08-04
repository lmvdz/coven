# Fleet two-PC test kit

This kit tests one Intel Mac hub and one Windows x64 executor using matching
Coven binaries from the same commit. It does not publish npm packages and does
not expose the daemon to the public internet.

## Install the Intel Mac binary

Verify and install the extracted artifact:

```sh
shasum -a 256 -c SHA256SUMS
mkdir -p "$HOME/.local/bin"
install -m 0755 coven "$HOME/.local/bin/coven"
"$HOME/.local/bin/coven" --version
```

Use the full path below or add `$HOME/.local/bin` to `PATH`.

## Install the Windows binary

In PowerShell, verify and copy the extracted artifact:

```powershell
$expected = (Get-Content .\SHA256SUMS).Split()[0]
$actual = (Get-FileHash .\coven.exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "coven.exe checksum mismatch" }
$install = Join-Path $env:LOCALAPPDATA "CovenFleet"
New-Item -ItemType Directory -Force $install | Out-Null
Copy-Item .\coven.exe (Join-Path $install "coven.exe") -Force
$Coven = Join-Path $install "coven.exe"
& $Coven --version
```

Keep `$Coven` defined in each PowerShell used below, or add the install directory
to the user `PATH` through Windows Settings.

## Connect the machines

Install Tailscale on both machines, sign them into the same tailnet, and confirm
they can reach each other. The Mac is the hub for this proof.

On the Mac, obtain its tailnet DNS name without the trailing dot:

```sh
HUB_FQDN="$(tailscale status --json | jq -r '.Self.DNSName | rtrimstr(".")')"
printf '%s\n' "$HUB_FQDN"
```

In a dedicated Mac terminal, start the Coven daemon on loopback. Leave it
attached for the duration of the proof:

```sh
"$HOME/.local/bin/coven" daemon serve \
  --tcp 127.0.0.1:8787 \
  --allow-host "$HUB_FQDN"
```

In a second Mac terminal, expose only that loopback listener to the tailnet:

```sh
COVEN_TAILSCALE_HTTPS_PORT=8443
tailscale serve --bg --https="$COVEN_TAILSCALE_HTTPS_PORT" http://127.0.0.1:8787
tailscale serve status
curl "https://$HUB_FQDN:$COVEN_TAILSCALE_HTTPS_PORT/api/v1/health"
```

The dedicated port preserves any existing Tailscale Serve route on port 443.
Do not use Tailscale Funnel; this test needs tailnet-private Serve only.

## Enroll the Windows executor

On the Mac, create a short-lived, single-use enrollment code:

```sh
"$HOME/.local/bin/coven" executor enrollment-code --label "Windows PC"
```

Copy only the returned `enrollmentCode` to the Windows PC over a trusted path.
In PowerShell 7, keep it out of command arguments and shell history:

```powershell
$Coven = Join-Path $env:LOCALAPPDATA "CovenFleet\coven.exe"
$env:COVEN_HOME = Join-Path $env:LOCALAPPDATA "CovenFleetTest"
$TestWorkspace = Join-Path $env:USERPROFILE "CovenFleetTestWorkspace"
New-Item -ItemType Directory -Force $env:COVEN_HOME | Out-Null
New-Item -ItemType Directory -Force $TestWorkspace | Out-Null
$Hub = "https://YOUR-MAC-NAME.YOUR-TAILNET.ts.net:8443"
$code = Read-Host "One-time enrollment code" -MaskInput
$code | & $Coven executor enroll --hub $Hub --node-id windows-pc `
  --workspace-root $TestWorkspace --code-stdin
$code = $null
& $Coven daemon restart
& $Coven executor fleet-status
& $Coven executor autostart install --activate
& $Coven executor autostart status
```

The Windows daemon now heartbeats and long-polls automatically. There is no
receive command. Shell jobs without an explicit `--cwd` run in the enrolled
workspace root; an explicit job working directory remains authoritative. Older
fleet configurations without `workspaceRoot` safely default to
`COVEN_HOME/executor-workspace` after upgrading. Autostart runs the daemon as a
least-privilege per-user scheduled task at login and supervises it in the
foreground. Its registration stores paths only; the fleet node credential stays
in the executor's private configuration.

## Prove remote execution

Back on the Mac:

```sh
"$HOME/.local/bin/coven" hub nodes
"$HOME/.local/bin/coven" executor offload -- cmd.exe /C hostname
"$HOME/.local/bin/coven" executor offload -- powershell.exe -NoProfile -Command \
  '$PSVersionTable.OS; [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture'
```

The normalized result must identify the Windows PC. Commands and `--cwd` paths
are evaluated on the executor, so do not pass Mac-only paths.

## Prove executor-local actor ownership

The deterministic fake harness proves actor selection and pinning without moving
provider credentials:

```sh
printf '%s\n' '{"protocolVersion":"coven.harness-host.v1","requestId":"start-1","operation":"start","actorId":"actor-test","harness":"fake","generation":1}' \
  | "$HOME/.local/bin/coven" executor actor --request-stdin
printf '%s\n' '{"protocolVersion":"coven.harness-host.v1","requestId":"send-1","operation":"send","actorId":"actor-test","generation":1,"idempotencyKey":"input-1","input":"hello from the Mac"}' \
  | "$HOME/.local/bin/coven" executor actor --request-stdin
```

The second response should include `fake:hello from the Mac`. Provider-backed
Claude and Codex delegation are not enabled by this proof; their future adapters
must resolve authentication from executor-local state.

## Stop the proof

On Windows:

```powershell
& $Coven executor autostart uninstall
```

On the Mac, stop the foreground Coven daemon with `Ctrl-C`, then remove the
dedicated tailnet proxy without resetting unrelated Serve routes:

```sh
tailscale serve --https=8443 off
```
