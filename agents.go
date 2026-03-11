package squeeze

import (
	"github.com/joakimcarlsson/ai/agent"
	llm "github.com/joakimcarlsson/ai/providers"
	"github.com/joakimcarlsson/squeeze/internal/prompt"
	"github.com/joakimcarlsson/squeeze/internal/tools"
)

func defaultSubAgents(llmClient llm.LLM) []agent.SubAgentConfig {
	return []agent.SubAgentConfig{
		ReconAgent(llmClient),
		WebAnalystAgent(llmClient),
		ExploitRunnerAgent(llmClient),
	}
}

func ReconAgent(llmClient llm.LLM) agent.SubAgentConfig {
	return agent.SubAgentConfig{
		Name:        "recon",
		Description: "Reconnaissance specialist. Delegates DNS enumeration, port scanning, technology fingerprinting, WHOIS, and SSL/TLS analysis. Returns structured findings.",
		Agent: agent.New(llmClient,
			agent.WithSystemPrompt(prompt.ReconAgentPrompt),
			agent.WithTools(
				tools.NewDNSLookup(),
				tools.NewPortScan(),
				tools.NewTechFingerprint(),
				tools.NewWhois(),
				tools.NewSSLInfo(),
				tools.NewWebSearch(),
				tools.NewFetch(),
			),
		),
	}
}

func WebAnalystAgent(llmClient llm.LLM) agent.SubAgentConfig {
	return agent.SubAgentConfig{
		Name:        "web_analyst",
		Description: "Web application analysis specialist. Probes HTTP endpoints, checks for misconfigurations, looks up CVEs, inspects JWTs, and analyzes web content. Returns structured findings.",
		Agent: agent.New(llmClient,
			agent.WithSystemPrompt(prompt.WebAnalystAgentPrompt),
			agent.WithTools(
				tools.NewHTTPProbe(),
				tools.NewFetch(),
				tools.NewWebSearch(),
				tools.NewCVELookup(),
				tools.NewTechFingerprint(),
				tools.NewJWTInspect(),
			),
		),
	}
}

func ExploitRunnerAgent(llmClient llm.LLM) agent.SubAgentConfig {
	return agent.SubAgentConfig{
		Name:        "exploit_runner",
		Description: "Exploitation specialist. Executes operator-approved exploitation steps using shell commands and HTTP tools. ONLY runs exploits that have been explicitly approved. Returns structured findings with evidence.",
		Agent: agent.New(llmClient,
			agent.WithSystemPrompt(prompt.ExploitRunnerAgentPrompt),
			agent.WithTools(
				tools.NewBash(),
				tools.NewHTTPProbe(),
				tools.NewFetch(),
				tools.NewWebSearch(),
			),
		),
	}
}
