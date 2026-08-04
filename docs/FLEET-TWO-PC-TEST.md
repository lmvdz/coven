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
tailscale serve --bg http://127.0.0.1:8787
tailscale serve status
curl "https://$HUB_FQDN/api/v1/health"
```

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
$Hub = "https://YOUR-MAC-NAME.YOUR-TAILNET.ts.net"
$code = Read-Host "One-time enrollment code" -MaskInput
$code | & $Coven executor enroll --hub $Hub --node-id windows-pc --code-stdin
$code = $null
& $Coven daemon restart
& $Coven executor fleet-status
```

The Windows daemon now heartbeats and long-polls automatically. There is no
receive command.

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
& $Coven daemon stop
```

On the Mac, stop the foreground Coven daemon with `Ctrl-C`, then remove the
tailnet proxy configuration:

```sh
tailscale serve reset
```
