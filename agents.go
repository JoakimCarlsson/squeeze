package squeeze

import (
	"github.com/joakimcarlsson/ai/agent"
	llm "github.com/joakimcarlsson/ai/providers"
	"github.com/joakimcarlsson/ai/tool"
	"github.com/joakimcarlsson/squeeze/internal/prompt"
	"github.com/joakimcarlsson/squeeze/internal/sandbox"
	"github.com/joakimcarlsson/squeeze/internal/tools"
)

func defaultSubAgents(llmClient llm.LLM, sbx *sandbox.Manager) []agent.SubAgentConfig {
	return []agent.SubAgentConfig{
		ReconAgent(llmClient, sbx),
		WebAnalystAgent(llmClient, sbx),
		ExploitRunnerAgent(llmClient, sbx),
	}
}

func ReconAgent(llmClient llm.LLM, sbx *sandbox.Manager) agent.SubAgentConfig {
	agentTools := []tool.BaseTool{
		tools.NewDNSLookup(),
		tools.NewPortScan(),
		tools.NewTechFingerprint(),
		tools.NewWhois(),
		tools.NewSSLInfo(),
		tools.NewWebSearch(),
		tools.NewFetch(),
	}
	agentTools = append(agentTools, sbx.Tools()...)

	return agent.SubAgentConfig{
		Name:        "recon",
		Description: "Reconnaissance specialist. Delegates DNS enumeration, port scanning, technology fingerprinting, WHOIS, and SSL/TLS analysis. Returns structured findings.",
		Agent: agent.New(llmClient,
			agent.WithSystemPrompt(prompt.ReconAgentPrompt),
			agent.WithTools(agentTools...),
		),
	}
}

func WebAnalystAgent(llmClient llm.LLM, sbx *sandbox.Manager) agent.SubAgentConfig {
	agentTools := []tool.BaseTool{
		tools.NewHTTPProbe(),
		tools.NewFetch(),
		tools.NewWebSearch(),
		tools.NewCVELookup(),
		tools.NewTechFingerprint(),
		tools.NewJWTInspect(),
	}
	agentTools = append(agentTools, sbx.Tools()...)

	return agent.SubAgentConfig{
		Name:        "web_analyst",
		Description: "Web application analysis specialist. Probes HTTP endpoints, checks for misconfigurations, looks up CVEs, inspects JWTs, and analyzes web content. Returns structured findings.",
		Agent: agent.New(llmClient,
			agent.WithSystemPrompt(prompt.WebAnalystAgentPrompt),
			agent.WithTools(agentTools...),
		),
	}
}

func ExploitRunnerAgent(llmClient llm.LLM, sbx *sandbox.Manager) agent.SubAgentConfig {
	agentTools := []tool.BaseTool{
		tools.NewBash(),
		tools.NewHTTPProbe(),
		tools.NewFetch(),
		tools.NewWebSearch(),
	}
	agentTools = append(agentTools, sbx.Tools()...)

	return agent.SubAgentConfig{
		Name:        "exploit_runner",
		Description: "Exploitation specialist. Executes operator-approved exploitation steps using shell commands and HTTP tools. ONLY runs exploits that have been explicitly approved. Returns structured findings with evidence.",
		Agent: agent.New(llmClient,
			agent.WithSystemPrompt(prompt.ExploitRunnerAgentPrompt),
			agent.WithTools(agentTools...),
		),
	}
}
