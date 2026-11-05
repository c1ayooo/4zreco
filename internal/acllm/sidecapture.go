// The eino-side half of the sidequestion CallModel snapshot (方案 §3 挂点表
// sidequestion 行): a model.ToolCallingChatModel decorator with the same
// snapshot semantics the norma-side halves (sidequestion Attach + Bind) have
// always provided, so the P1 kernel keeps immutable main-agent checkpoints
// when the loop switches over. Same layer as the llmpool/llmrec model
// decorators (刀① pattern: the norma path stays untouched until 切换, 刀④).
//
// Placement note: this decorator lives in acllm, not in internal/sidequestion —
// internal/db imports sidequestion (snapshot persistence), and R1 (方案 §0.1)
// forbids eino in db's dependency tree; sidequestion must therefore stay
// eino-free, while acllm is the sanctioned place where the eino and DTO
// vocabularies meet. The decorator reads the per-run Capture from the call
// context (sidequestion.WithAttempt / sidequestion.AttemptFrom — the same
// attemptKey Attach stamps), and the decorator is bound immediately around the
// concrete model, inside any routing pool (Bind's rule).
//
// Model identity rides the decorator (Bind's second argument), because eino
// calls carry no request-level model field. The snapshot's Tools field is
// approximated: eino tool infos are projected to name+description only (the
// schema cannot be reversed from ParamsOneOf losslessly); consumers
// (sidequestion EstimateInputTokens) use it for budget sizing, which stays
// conservative. The frozen llm.CompletionRequest JSON shape is preserved via
// acllm.FromSchema — the on-disk/DB shape does not change.
package acllm

import (
	"context"
	"errors"
	"io"

	"github.com/Autumn-27/norma/llm"
	"github.com/c1ayooo/4zreco/internal/sidequestion"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// CaptureModel wraps a model.ToolCallingChatModel and saves a CallModel
// snapshot around every call made through it (and through any model derived
// from it via WithTools).
type CaptureModel struct {
	inner model.ToolCallingChatModel
	m     sidequestion.Model
	// boundTools accumulates the tool infos attached via WithTools, for the
	// snapshot's Tools field (names + descriptions).
	boundTools []*schema.ToolInfo
}

// BindCaptureModel is the eino-side sidequestion.Bind: wrap the concrete model.
func BindCaptureModel(inner model.ToolCallingChatModel, m sidequestion.Model) *CaptureModel {
	return &CaptureModel{inner: inner, m: m}
}

// WithTools re-wraps the derived model so snapshotting survives tool binding.
func (c *CaptureModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	inner, err := c.inner.WithTools(tools)
	if err != nil {
		return nil, err
	}
	out := *c
	out.inner = inner
	out.boundTools = append(append([]*schema.ToolInfo{}, c.boundTools...), tools...)
	return &out, nil
}

// requestFromEino reconstructs the frozen CompletionRequest shape from the
// eino call input: system segments, the DTO-projected messages, bound tool
// names+descriptions, and the effective max tokens.
func (c *CaptureModel) requestFromEino(input []*schema.Message, opts []model.Option) (llm.CompletionRequest, error) {
	req := llm.CompletionRequest{}
	var nonSystem []*schema.Message
	for _, m := range input {
		if m == nil {
			continue
		}
		if m.Role == schema.System {
			req.System = append(req.System, m.Content)
			continue
		}
		nonSystem = append(nonSystem, m)
	}
	req.Messages = FromSchema(nonSystem)
	for _, ti := range c.boundTools {
		if ti == nil {
			continue
		}
		req.Tools = append(req.Tools, llm.ToolSchema{Name: ti.Name, Description: ti.Desc})
	}
	if common := model.GetCommonOptions(&model.Options{}, opts...); common.MaxTokens != nil {
		req.MaxTokens = *common.MaxTokens
	}
	return req, nil
}

// saveFinal persists the final snapshot: the request's messages (already the
// request view) plus the assembled assistant, folded through MessagesForAPI —
// boundProvider's post-success save, byte-shape identical.
func (c *CaptureModel) saveFinal(cap *sidequestion.Capture, base llm.CompletionRequest, assistant llm.Message) {
	req := base
	req.Messages = llm.MessagesForAPI(append(append([]llm.Message{}, base.Messages...), assistant))
	cap.Save(req, c.m)
}

func (c *CaptureModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	cap := sidequestion.AttemptFrom(ctx)
	if cap == nil {
		return c.inner.Generate(ctx, input, opts...)
	}
	base, err := c.requestFromEino(input, opts)
	if err != nil {
		return nil, err
	}
	cap.Save(base, c.m)
	msg, err := c.inner.Generate(ctx, input, opts...)
	if err == nil && ctx.Err() == nil {
		c.saveFinal(cap, base, captureAssistantDTO(msg))
	}
	return msg, err
}

func (c *CaptureModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	cap := sidequestion.AttemptFrom(ctx)
	if cap == nil {
		return c.inner.Stream(ctx, input, opts...)
	}
	base, err := c.requestFromEino(input, opts)
	if err != nil {
		return nil, err
	}
	cap.Save(base, c.m)

	sr, err := c.inner.Stream(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	// eino stream readers are single-reader: tee so the caller's branch is
	// untouched and an observer folds the deltas into the assistant message for
	// the final snapshot (llmrec's observe pattern; boundProvider folds inline
	// because norma streams are pull-based iterators).
	branches := sr.Copy(2)
	go c.observe(cap, base, branches[1], ctx)
	return branches[0], nil
}

func (c *CaptureModel) observe(cap *sidequestion.Capture, base llm.CompletionRequest, sr *schema.StreamReader[*schema.Message], ctx context.Context) {
	defer sr.Close()
	var chunks []*schema.Message
	clean := true
	for {
		chunk, err := sr.Recv()
		if err != nil {
			// boundProvider's rule: save the final snapshot only on a clean end
			// (norma saw SEMessageStop; here io.EOF) with no cancellation.
			clean = errors.Is(err, io.EOF)
			break
		}
		if chunk != nil {
			chunks = append(chunks, chunk)
		}
	}
	if !clean || len(chunks) == 0 || ctx.Err() != nil {
		return
	}
	final, err := schema.ConcatMessages(chunks)
	if err != nil || final == nil {
		return
	}
	c.saveFinal(cap, base, captureAssistantDTO(final))
}

// captureAssistantDTO projects one eino assistant message into the DTO
// vocabulary (FromSchema single-message view; empty messages keep a blank text
// block so the snapshot's final save never loses the turn).
func captureAssistantDTO(m *schema.Message) llm.Message {
	out := FromSchema([]*schema.Message{m})
	if len(out) == 0 {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("")}}
	}
	return out[0]
}
