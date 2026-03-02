package squeeze

import (
	"github.com/joakimcarlsson/ai/agent"
	llm "github.com/joakimcarlsson/ai/providers"
	"github.com/joakimcarlsson/ai/tool"
	"github.com/joakimcarlsson/squeeze/internal/prompt"
	"github.com/joakimcarlsson/squeeze/internal/tools"
)

type Option func(*config)

type config struct {
	extraTools []tool.BaseTool
	agentOpts  []agent.AgentOption
}

func WithTools(t ...tool.BaseTool) Option {
	return func(c *config) {
		c.extraTools = append(c.extraTools, t...)
	}
}

func WithAgentOptions(opts ...agent.AgentOption) Option {
	return func(c *config) {
		c.agentOpts = append(c.agentOpts, opts...)
	}
}

func NewAgent(llmClient llm.LLM, opts ...Option) *agent.Agent {
	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}

	allTools := Tools()
	allTools = append(allTools, cfg.extraTools...)

	agentOpts := []agent.AgentOption{
		agent.WithSystemPrompt(prompt.SystemPrompt),
		agent.WithTools(allTools...),
	}
	agentOpts = append(agentOpts, cfg.agentOpts...)

	return agent.New(llmClient, agentOpts...)
}

func Tools() []tool.BaseTool {
	return []tool.BaseTool{
		tools.NewBash(),
		tools.NewWebSearch(),
		tools.NewFetch(),
		tools.NewHTTPProbe(),
		tools.NewTechFingerprint(),
		tools.NewPortScan(),
		tools.NewCVELookup(),
		tools.NewDNSLookup(),
		tools.NewJWTInspect(),
	}
}
