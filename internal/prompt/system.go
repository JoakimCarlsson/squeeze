package prompt

import _ "embed"

//go:embed system.md
var SystemPrompt string

//go:embed recon_agent.md
var ReconAgentPrompt string

//go:embed web_analyst_agent.md
var WebAnalystAgentPrompt string

//go:embed exploit_runner_agent.md
var ExploitRunnerAgentPrompt string
