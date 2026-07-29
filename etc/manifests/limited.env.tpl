# /etc/vaulted-agent/manifests/limited.env.tpl
#
# The same fleet as full.env.tpl, minus production database write access and
# minus the mail credentials. Point a harness at this when you want it working
# on code and infrastructure but not able to modify customer data.
#
# The point of a second manifest is not that one agent is untrustworthy. It is
# that "which agent had which credential" should be a question with a written
# answer, and that a prompt-injection or a bad tool call in one harness should
# not reach everything the other harness can.

APP_DB_HOST=op://AgentVault/app-database/hostname
REPORTING_DB_USER=op://AgentVault/app-database/readonly/username
REPORTING_DB_PASS=op://AgentVault/app-database/readonly/password

STAGING_HOST=op://AgentVault/staging-server/hostname
STAGING_SSH_USER=op://AgentVault/staging-server/username
STAGING_SSH_PASS=op://AgentVault/staging-server/password

GH_TOKEN=op://AgentVault/github/fine-grained-token
