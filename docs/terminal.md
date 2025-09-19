# Web terminal image (ttyd) for iOS/Debian users

This directory provides a small Debian-based container that runs `ttyd`,
exposing a browser-accessible terminal. It's intended as a convenient way for
users (including iOS Safari users) to open a live shell and run scan tools like
`nmap`, `netcat`, and Python-based scripts.

Security notice

- Exposing a shell over HTTP is dangerous. Always run this behind strong
  authentication (Reverse proxy with OAuth/OIDC, SSH tunnels, or internal-only
  networks). Do not expose to the public internet without proper access control.
- Consider running scans in a sandboxed namespace and limiting available tools.

How to build

From the repository root:

  make build-terminal

How to run locally

  make run-terminal

This maps container port 7681 to host port 7681. Open http://localhost:7681 in a
browser on your iOS or Debian device.

Customizing the shell or arguments

- To change the shell command run inside the web terminal, set the `SHELL_CMD`
  env var when running the container, e.g.:

  nerdctl run -e SHELL_CMD="/bin/bash -l" -p 7681:7681 osrovnet-terminal:local

- To pass additional ttyd arguments (for example to enable TLS), set `TT_ARGS`.

Integration

- For production use integrate with a reverse proxy (Traefik/Nginx) and
  disable direct public access. Use short-lived tokens or OAuth/OIDC for user
  authentication.

*** End Patch