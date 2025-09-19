# Using nerdctl and containerd to build & run Osrovnet

This project includes a Makefile that provides convenient targets for building images and running services using `nerdctl` and `containerd`.

Prerequisites

- containerd installed and configured on your machine
- nerdctl installed and available on PATH
- (Optional) root or proper user permissions for containerd

Quick commands

- Build backend image:

  make build-backend

- Build frontend image:

  make build-frontend

- Build both images:

  make build-all

- Start services using the development compose file:

  make up

- Stop services and remove local images created by compose:

  make down

- Tail logs for a specific service (e.g., backend):

  make logs SERVICE=backend

Notes and tips

- The Makefile defaults to `docker-compose.dev.yml`. Set `COMPOSE_FILE` to override if you want production compose.
- If your environment uses a custom containerd namespace, prefix nerdctl commands with `nerdctl --namespace yourns` or export `CONTAINERD_NAMESPACE`.
- If you plan to push images to a registry, update the image tags in the Makefile to include the registry host: `registry.example.com/osrovnet-backend:tag`.
- For multi-architecture builds you can use `nerdctl buildx` or `buildctl` depending on your setup; this Makefile uses a simple local build.

Troubleshooting

- If `nerdctl` commands fail with permission errors, run them with `sudo` or configure your user to access containerd.
- If `nerdctl compose` is not installed, you may need to enable it in your nerdctl distribution or install `nerdctl-compose`.
- To inspect containers created by compose use `nerdctl ps -a`.

Contact

If you want, I can add a `Makefile` target to build multi-arch images, or a small script that tags and pushes images to a registry. Tell me which registry and architectures you need and I’ll add it.

Root image (single-container) instructions

This repository also includes a multi-stage `Dockerfile.root` which builds a single
image containing both the backend and the compiled frontend static assets. This is
handy for one-container deployments or quick manual testing.

Build the root image using make:

  make build-root

Run it with nerdctl:

  nerdctl run --rm -p 8000:8000 --name osrovnet-root osrovnet-root:local

Notes:
- The root image runs `gunicorn` by default and exposes port 8000.
- The image includes the full Python requirements (including ML libs) so it can
  be large. For production you may prefer separate, smaller service images.
- The entrypoint will attempt migrations at startup; ensure the database is
  reachable (or run migrations manually via `nerdctl exec` if you prefer).
