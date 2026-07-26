# Self-hosted GeoLibre Share

This fork includes a Share service in the same container as the GeoLibre web
application. Projects, users, sessions, and API-token hashes stay on the host;
it does not call `share.geolibre.app`.

## Runtime configuration

Build the web application with:

```text
VITE_GEOLIBRE_SHARE_URL=/share
```

The Docker image uses that value by default. At runtime set:

```text
GEOLIBRE_SHARE_PUBLIC_URL=https://your-geolibre-host.example/share
GEOLIBRE_SHARE_DATA_DIR=/data/share
```

Mount `/data/share` on persistent storage. For example:

```yaml
volumes:
  - geolibre-share-data:/data/share
```

The SQLite database is created with mode `0600` inside a `0700` directory.
Passwords use salted scrypt hashes; API tokens and browser sessions are stored
only as SHA-256 hashes.

## Create the first administrator

Run this once inside the application container:

```bash
python -m geolibre_server.app.share_admin create-user --username admin --admin
```

The command prompts for the password without putting it in the process list.
Afterward, open `/share/settings`, sign in, and create a personal API token.
Paste that token into **Settings → Environment → GeoLibre Share API token**.

Administrators can create additional local accounts in the same portal. Each
account owns its tokens and projects. Projects support public, unlisted, and
private visibility; private project JSON requires its owner's token.
