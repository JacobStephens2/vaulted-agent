# /etc/vaulted-agent/manifests/readonly.env.tpl
#
# Read-only credentials only. Nothing here can write to a database, push to a
# repository, send mail, or change infrastructure.
#
# This is the manifest to reach for when trying out a new agent, or when the
# task is analysis rather than change.

APP_DB_HOST=op://AgentVault/app-database/hostname
REPORTING_DB_USER=op://AgentVault/app-database/readonly/username
REPORTING_DB_PASS=op://AgentVault/app-database/readonly/password
