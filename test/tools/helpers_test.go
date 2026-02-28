package tools

import (
	"github.com/joakimcarlsson/ai/tool"
)

func makeCall(name, input string) tool.ToolCall {
	return tool.ToolCall{ID: "test-1", Name: name, Input: input}
}
