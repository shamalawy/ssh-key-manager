# SKM web interface

Angular 21, standalone components, zoneless, signals. It is built into the Go
binary at `backend/internal/web/dist` by `make frontend`; there is no separate
deployment.

```bash
make dev-frontend    # dev server on :4200, proxying /api to the Go server
make frontend        # production build, copied into the embed directory
```

`make dev` starts the Go server the proxy points at. See the root
[README](../README.md) for everything else.
