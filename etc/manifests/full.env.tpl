# /etc/vaulted-agent/manifests/full.env.tpl
#
# A manifest names environment variables and the vault references that fill
# them. It holds no secrets, only pointers, which is why it is safe to commit
# and safe to leave world-readable.
#
#   KEY=op://<vault>/<item>/<field>
#
# `op inject` substitutes each reference at launch. A reference that cannot be
# resolved fails the whole injection and aborts the launch, rather than
# starting the agent with that one variable silently empty.
#
# This file IS the blast radius of any harness pointing at it. Give each
# harness the narrowest manifest that still lets it do its job; see
# limited.env.tpl and readonly.env.tpl for the same fleet, cut down.

# --- Database ---------------------------------------------------------------
APP_DB_HOST=op://AgentVault/app-database/hostname
APP_DB_USER=op://AgentVault/app-database/mysql/username
APP_DB_PASS=op://AgentVault/app-database/mysql/password

# A second credential on the same server, granted SELECT on a few tables.
# Prefer handing an agent this one over the read-write pair above.
REPORTING_DB_USER=op://AgentVault/app-database/readonly/username
REPORTING_DB_PASS=op://AgentVault/app-database/readonly/password

# --- Hosts the agent administers -------------------------------------------
# One item per host, carrying both the SSH login and any service credentials
# that live on it, keeps the vault navigable as the fleet grows.
WEB_HOST=op://AgentVault/web-server/hostname
WEB_SSH_USER=op://AgentVault/web-server/username
WEB_SSH_PASS=op://AgentVault/web-server/password

STAGING_HOST=op://AgentVault/staging-server/hostname
STAGING_SSH_USER=op://AgentVault/staging-server/username
STAGING_SSH_PASS=op://AgentVault/staging-server/password

# --- Third-party APIs -------------------------------------------------------
# Most CLIs read a credential from a fixed variable. Using it beats letting the
# tool write the token into its own config file, which puts it back on disk.
GH_TOKEN=op://AgentVault/github/fine-grained-token

SMTP_HOST=op://AgentVault/smtp/hostname
SMTP_PORT=op://AgentVault/smtp/port
SMTP_USER=op://AgentVault/smtp/username
SMTP_PASS=op://AgentVault/smtp/api-key

# Resolve straight to the name the tool expects rather than re-exporting under
# a second name later, so the value only ever exists in one variable.
DIGITALOCEAN_ACCESS_TOKEN=op://AgentVault/digitalocean/personal-access-token
