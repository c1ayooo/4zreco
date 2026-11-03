package agent

// cold-digest §4/§5/§7: the Compactor ties the pure algorithms (coldgraph.go)
// to the store (db/digest.go) and the LLM. It runs in two modes:
//
//	maintain — cheap, synchronous, once per planner round: bump round_no,
//	           recompute hot/cold, stamp/clear cold_since_round (§2.3). This is
//	           the bookkeeping the planner does anyway; it never calls the LLM.
//	minor/major — background, off the planner hot path (§7): group cold nodes
//	           and compress each ≥2 block into a digest via the LLM. minor folds
//	           only the not-yet-covered cold set (tiered append); major re-derives
//	           the whole grouping from source and merges fragments (§5.1/§5.2),
//	           reusing bodies whose signature is unchanged (§5.3).
//
// Concurrency: one compaction per task at a time (mutex), ≥cooldown between runs,
// and a commit-time liveness recheck drops any member that revived while the body
// was being generated so a digest never covers a hot node.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
	"github.com/c1ayooo/4zreco/db"
)

// Compactor performs background cold-node compaction for many explorations.
type Compactor struct {
	prov     llm.Provider
	model    string
	params   coldParams
	n, m     int           // minor / major thresholds (§7 N=20, M=8)
	cooldown time.Duration // min gap between compactions per task (§7 60s)
	maxDur   time.Duration // hard cap on one background compaction
	// outTokens 是压缩这一次调用的输出预算(思考+正文共用)。0 = 用 defaultCompactionTokens。
	//
	// 为什么不能用小值:adaptive thinking 模型(MiniMax-M3.1 等强制思考的)会**按
	// max_tokens 预算持续思考**,预算越小它思考得越久、正文越轮不到——实测同一份
	// 26 节点的输入,预算 1500 时思考烧光 1500、正文 0 字;预算 2048 时正文仍是 0;
	// 预算 32768 时思考约 2000 token 就收尾并正常吐出正文。也就是说预算给小了
	// 不是"输出被截断",而是**模型根本没走到正文**。
	outTokens int
	// maxBlockMembers 是单次压缩请求的成员节点数上限。0 = 不限制。
	//
	// 为什么要限制:实测**能否收尾取决于单次输入规模,而非预算大小**——3 个节点
	// (743 prompt token)在 32768 预算下正常收尾(约 2000 token 思考),26 个节点
	// (3084 prompt token)即使给 32768 也会把预算烧光、跑 211 秒不出正文。
	// 所以超大连通块必须切分,让每次请求的规模落在模型能处理住的范围内。
	maxBlockMembers int

	mu      sync.Mutex
	running map[int64]bool
	lastRun map[int64]time.Time
	// consecFails 记录每个探索连续几轮压缩失败,用于失败退避(见 cooldownForLocked)。
	consecFails map[int64]int
}

// defaultCompactionTokens 是压缩调用的默认输出预算。
//
// 65536 的由来:实测 6 节点/块在 65536 预算下 124 秒就正常收尾(用 11733
// token);9 节点/块在 32768 预算下 3 块里有 1 块烧光预算失败。预算给足
// 能显著提高成功率——思考型模型会按 max_tokens 预算持续思考,预算越大它
// 思考得越久,但也因此更可能想到能收尾。
//
// 65536 仍是"思考+正文共用"的额度,给小了模型会一直想、正文轮不到
// (见 outTokens 字段的注释)。
const defaultCompactionTokens = 65536

// defaultCompactionDuration 是单次后台压缩的墙钟上限。
//
// 压缩是**后台协程**,与 worker 领取意图并行(日志里可见压缩与「领取意图」交替),
// 等久一点不影响主流程进度,只会让冷节点压缩晚一点落地。5 分钟对长输入的
// adaptive thinking 模型明显不够(实测 26 节点要跑 10 分钟以上),故放宽。
const defaultCompactionDuration = 20 * time.Minute

// defaultCompactionMaxMembers 是单次压缩请求的成员节点数上限。
//
// 6 的由来（实测同一份 26 节点真实输入，逐档切分）：
//   - 26 节点/块：max_tokens 给到 65536 也把预算烧光，10 分钟不出正文。
//   - 9 节点/块：3 块里 2 成功（194s / 324s）、1 失败（烧光 32768）。
//   - 6 节点/块：124 秒就正常收尾，用 11733 token。
//
// 也就是说切得越碎，模型越容易收尾、耗时也越短。6 是「成功率」与
// 「别把摘要切得太碎（碎了就失去『综合』的意义）」之间的平衡点。
const defaultCompactionMaxMembers = 6

// compactionSubConcurrency 是单个块内子块压缩的并发度。
//
// 4 的由来：实测单子块（6 节点）约 124 秒。一个 200 节点的连通块按 6 节点/块
// 切出 32 个子块，串行是 32×124 ≈ 66 分钟，远超单次后台压缩 20 分钟的墙钟
// 上限——必然 context deadline exceeded。4 路并发把它压到约 17 分钟，稳稳
// 落在上限内。
//
// 为什么不更高：上游是共享的限流网关，32 路并发会把上游打爆，反而全失败。
// 4 是「不撞墙钟」与「不打爆上游」之间的平衡点。
const compactionSubConcurrency = 4

// NewCompactor builds a compactor. prov/model are used for the §4 body LLM call
// (same model the agent runs on, per §4). A nil Compactor is a safe no-op.
func NewCompactor(prov llm.Provider, model string) *Compactor {
	return &Compactor{
		prov:      prov,
		model:     model,
		params:    defaultColdParams(),
		n:         20,
		m:         8,
		cooldown:  60 * time.Second,
		maxDur:    defaultCompactionDuration,
		outTokens: defaultCompactionTokens,
		// maxBlockMembers 默认切分：超大连通块会让思考型模型陷进超长思考。
		maxBlockMembers: defaultCompactionMaxMembers,
		running:         map[int64]bool{},
		lastRun:         map[int64]time.Time{},
		consecFails:     map[int64]int{},
	}
}

// SetOutputTokens 设置压缩调用的输出预算。0 = 恢复默认。
// 让部署方能按「思考型模型需要多大预算」来调,而不是改代码里的常量。
func (c *Compactor) SetOutputTokens(n int) {
	if c == nil {
		return
	}
	if n <= 0 {
		n = defaultCompactionTokens
	}
	c.outTokens = n
}

// SetMaxDuration 设置单次后台压缩的墙钟上限。<=0 = 恢复默认。
func (c *Compactor) SetMaxDuration(d time.Duration) {
	if c == nil {
		return
	}
	if d <= 0 {
		d = defaultCompactionDuration
	}
	c.maxDur = d
}

// SetMaxBlockMembers 设置单次压缩请求的成员节点数上限。<=0 = 恢复默认。
// 刻意不提供"不切分"的选项:实测超大连通块必然让思考型模型陷进超长思考,
// 切分是保证压缩能落地的必要条件,不是一个可选的优化。
func (c *Compactor) SetMaxBlockMembers(n int) {
	if c == nil {
		return
	}
	if n <= 0 {
		n = defaultCompactionMaxMembers
	}
	c.maxBlockMembers = n
}

// OnPlannerRound is the single entry the planner calls each wake-up. It bumps the
// round, maintains the cold stamps synchronously, then (if a threshold is hit and
// no compaction is running / cooling down) launches a background compaction that
// outlives this planner round.
func (c *Compactor) OnPlannerRound(ctx context.Context, ts *db.ExplorationStore) {
	if c == nil || c.prov == nil || ts == nil {
		return
	}
	round, uncompressed, activeDigests, err := c.maintain(ts)
	if err != nil {
		log.Printf("[compaction] maintain exp=%d: %v", ts.ID(), err)
		return
	}
	needMinor := uncompressed >= c.n
	needMajor := activeDigests >= c.m
	if !needMinor && !needMajor {
		return
	}
	if !c.tryStart(ts.ID()) {
		return // already running, or within cooldown —派生态最终一致，下轮再压
	}
	go func() {
		defer c.finish(ts.ID())
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.maxDur)
		defer cancel()
		// 压缩是裸 provider 调用（compress 里直接 prov.Complete），不经过 agentcore
		// 的会话循环，所以 ctx 上没有 session id；按 session-id 头做提示缓存/粘性
		// 路由的网关（opencode zen 缺 x-opencode-session 直接 400）就收不到该头。
		// 这里补一个按探索稳定的 id：同一探索的所有压缩请求共享它，既能带上头，
		// 也让 llmrec 能把这次调用的 token 归因回该探索（此前记不到）。
		bg = transcript.WithSessionID(bg, fmt.Sprintf("exp%d-compactor", ts.ID()))
		if needMajor {
			c.major(bg, ts)
		} else {
			c.minor(bg, ts)
		}
	}()
	_ = round
}

// maintain bumps round_no, recomputes hot/cold over the whole graph, and applies
// the cold_since_round stamp/clear ops (§2.3). Returns the new round plus the
// counts that drive the trigger: how many eligible-cold nodes are not yet covered
// (minor) and how many active digests exist (major).
func (c *Compactor) maintain(ts *db.ExplorationStore) (round int64, uncompressed, activeDigests int, err error) {
	round, err = ts.BumpRound()
	if err != nil {
		return
	}
	g, _, err := loadColdGraph(ts)
	if err != nil {
		return
	}
	stamps, err := ts.ColdStamps()
	if err != nil {
		return
	}
	hot := g.hotSet()
	structCold := g.structuralCold(hot)
	ops := computeStampOps(structCold, stamps, round)
	if err = ts.ApplyStampOps(toDBStampOps(ops)); err != nil {
		return
	}
	applyStampsInPlace(stamps, ops)
	elig := g.eligibleCold(structCold, stamps, round, c.params)
	covered, err := ts.CoveredMembers()
	if err != nil {
		return
	}
	for id := range elig {
		if _, ok := covered[id]; !ok {
			uncompressed++
		}
	}
	ad, err := ts.ActiveDigests()
	if err != nil {
		return
	}
	activeDigests = len(ad)
	return
}

// minor folds the not-yet-covered eligible-cold set into new digest segments
// (tiered append, §5). Existing digests are untouched.
func (c *Compactor) minor(ctx context.Context, ts *db.ExplorationStore) {
	round, err := ts.RoundNo()
	if err != nil {
		return
	}
	g, nodeByID, err := loadColdGraph(ts)
	if err != nil {
		return
	}
	stamps, err := ts.ColdStamps()
	if err != nil {
		return
	}
	cvers, err := ts.ContentVersions()
	if err != nil {
		return
	}
	covered, err := ts.CoveredMembers()
	if err != nil {
		return
	}
	hot := g.hotSet()
	elig := g.eligibleCold(g.structuralCold(hot), stamps, round, c.params)
	uncompressed := map[int64]bool{}
	for id := range elig {
		if _, ok := covered[id]; !ok {
			uncompressed[id] = true
		}
	}
	blocks := g.group(uncompressed, c.params)
	if len(blocks) == 0 {
		return // this batch has no ≥2 connected/shared-parent block — nothing to fold (§7)
	}
	allOK := true
	for _, b := range blocks {
		if !c.foldBlock(ctx, ts, g, b, nodeByID, cvers, c.generationFor(b, nil)) {
			allOK = false
		}
	}
	c.recordResult(ts.ID(), allOK)
	// A minor may have pushed the segment count over M → merge in the same run.
	if ad, e := ts.ActiveDigests(); e == nil && len(ad) >= c.m {
		c.major(ctx, ts)
	}
}

// major re-derives the whole grouping from source over ALL eligible-cold nodes
// (§5.1 回源重压), then reconciles against the active digests by signature:
// unchanged blocks keep their digest (no LLM), stale digests are superseded, and
// new/changed blocks are compressed afresh. This is where tiered fragments of one
// direction merge and where "later became connected" blocks unify (§5.2).
func (c *Compactor) major(ctx context.Context, ts *db.ExplorationStore) {
	round, err := ts.RoundNo()
	if err != nil {
		return
	}
	g, nodeByID, err := loadColdGraph(ts)
	if err != nil {
		return
	}
	stamps, err := ts.ColdStamps()
	if err != nil {
		return
	}
	cvers, err := ts.ContentVersions()
	if err != nil {
		return
	}
	active, err := ts.ActiveDigests()
	if err != nil {
		return
	}
	hot := g.hotSet()
	elig := g.eligibleCold(g.structuralCold(hot), stamps, round, c.params)
	blocks := g.group(elig, c.params)

	bySig := map[string]*db.Node{}
	for _, d := range active {
		sig, _ := digestSigGen(d)
		bySig[sig] = d
	}
	desired := map[string]bool{}
	var toCreate []block
	for _, b := range blocks {
		sig := blockSignature(b, cvers)
		desired[sig] = true
		if _, ok := bySig[sig]; ok {
			continue // unchanged → reuse the existing digest, skip LLM (§5.3)
		}
		toCreate = append(toCreate, b)
	}
	// Supersede stale digests FIRST (atomic drop of their covers edges) so a member
	// is never covered by both an old and a new digest (§5.1 one-member-one-digest).
	var stale []int64
	for _, d := range active {
		sig, _ := digestSigGen(d)
		if !desired[sig] {
			stale = append(stale, d.ID)
		}
	}
	if err := ts.SupersedeDigests(stale); err != nil {
		log.Printf("[compaction] supersede exp=%d: %v", ts.ID(), err)
	}
	allOK := true
	for _, b := range toCreate {
		if !c.foldBlock(ctx, ts, g, b, nodeByID, cvers, c.generationFor(b, active)) {
			allOK = false
		}
	}
	c.recordResult(ts.ID(), allOK)
}

// foldBlock compresses one block and writes its digest — with a commit-time
// liveness recheck (§ concurrency): between grouping and write the graph may have
// changed, so any member that has since gone hot (revived) is dropped from the
// covers set. If the block dissolves below K it is skipped.
//
// 返回是否成功(压缩+写 digest 都没出错),供上层做失败退避。
func (c *Compactor) foldBlock(ctx context.Context, ts *db.ExplorationStore, g *coldGraph, b block, nodeByID map[int64]*db.Node, cvers map[int64]int, generation int) bool {
	// 超大块会被切成若干子块分别压缩(见 compressChunked 的注释:思考型模型能否
	// 收尾取决于单次输入规模)。多段 body 拼成一段,语义与原来的一段等价。
	bodies, err := c.compressChunked(ctx, g, b, nodeByID)
	if err != nil {
		log.Printf("[compaction] compress exp=%d block=%v: %v", ts.ID(), b.Members, err)
		return false
	}
	body := strings.Join(bodies, "\n\n")
	// Re-read fresh state and drop any member that revived while we compressed.
	fresh, _, err := loadColdGraph(ts)
	if err != nil {
		return false
	}
	freshHot := fresh.hotSet()
	members := make([]int64, 0, len(b.Members))
	for _, mID := range b.Members {
		if !freshHot[mID] {
			members = append(members, mID)
		}
	}
	if len(members) < c.params.K {
		return true // block revived out from under us — leave those nodes hot, don't fold
	}
	final := block{Members: members, Anchors: b.Anchors}
	payload := digestPayload(body, final, nodeByID, generation, blockSignature(final, cvers))
	if _, err := ts.AddDigest(payload, members); err != nil {
		log.Printf("[compaction] add digest exp=%d: %v", ts.ID(), err)
		return false
	}
	return true
}

// generationFor computes a digest's重摘代次 (§1): 1 for a fresh fold; for a major
// merge, max(generation) over the active digests that overlap this block's
// members, +1.
func (c *Compactor) generationFor(b block, active []*db.Node) int {
	if len(active) == 0 {
		return 1
	}
	memberSet := make(map[int64]bool, len(b.Members))
	for _, m := range b.Members {
		memberSet[m] = true
	}
	best := 0
	for _, d := range active {
		_, gen := digestSigGen(d)
		for _, m := range digestMemberIDs(d) {
			if memberSet[m] {
				if gen > best {
					best = gen
				}
				break
			}
		}
	}
	return best + 1
}

// tryStart acquires the per-task compaction lock, honoring the cooldown.
//
// 失败退避：连续失败时该探索的冷却时间指数增长。理由很实际——一次失败的
// 压缩要烧掉几百秒的 LLM 时间(实测思考型模型在长输入上会思考 300 秒以上
// 才放弃),而冷却只有 60 秒的话,就会变成「每分钟烧一次 5 分钟」的无谓循环。
// 压缩失败不阻塞主流程(没有 digest 时 planner 直接看原始节点),所以退避
// 只是省资源,不是保功能。
func (c *Compactor) tryStart(expID int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running[expID] {
		return false
	}
	// cooldownForLocked, not cooldownFor: this method already holds c.mu, and
	// sync.Mutex is NOT reentrant — calling cooldownFor here would try to lock
	// c.mu a second time and self-deadlock forever.
	//
	// How it stayed hidden so long: the branch is only reached once
	// c.lastRun[expID] exists, and lastRun is only set by finish() when a
	// compaction goroutine completes. So the first compaction of an exploration
	// is fine; the next planner round after it completed deadlocks — and
	// because a deadlocked mutex ignores ctx cancellation, the planner's
	// wall-clock timeout could not break it either. Symptom: the task goes
	// permanently silent (no new intents, no planner log at all) while the
	// service keeps running. A service restart cleared it, which is why it
	// looked like an upstream/LLM problem.
	if t, ok := c.lastRun[expID]; ok && time.Since(t) < c.cooldownForLocked(expID) {
		return false
	}
	c.running[expID] = true
	return true
}

// cooldownFor 返回该探索当前的冷却时长(成功=基础值,连续失败则指数退避)。
//
// 这是**不持锁**时的入口；已经持有 c.mu 的调用方必须用 cooldownForLocked
// （sync.Mutex 不可重入，再加一次锁就是自死锁）。
func (c *Compactor) cooldownFor(expID int64) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cooldownForLocked(expID)
}

// cooldownForLocked 返回该探索当前的冷却时长(成功=基础值,连续失败则指数退避)。
//
// 必须是 Locked 版：调用方持有 c.mu 时再调一个会加锁的同名函数就是自死锁
// （sync.Mutex 不可重入），而 ctx 取消救不了它——死锁的 goroutine 不会返回，
// planner 的墙钟上限也就跟着失效。热路径 tryStart 用的就是这一个。
func (c *Compactor) cooldownForLocked(expID int64) time.Duration {
	fails := c.consecFails[expID]
	if fails <= 0 {
		return c.cooldown
	}
	// 指数退避,封顶 30 分钟。
	d := c.cooldown
	for i := 0; i < fails && d < 30*time.Minute; i++ {
		d *= 2
	}
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}
	return d
}

func (c *Compactor) finish(expID int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running[expID] = false
	c.lastRun[expID] = time.Now()
}

// recordResult 记录一轮压缩的结果:成功则清零连续失败计数,失败则累加。
func (c *Compactor) recordResult(expID int64, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ok {
		delete(c.consecFails, expID)
		return
	}
	c.consecFails[expID]++
}

// --- helpers: db ↔ coldgraph ---

// loadColdGraph reads the exploration's nodes + edges and builds the cold-graph
// view plus an id→node index (for summaries/payload during compression).
func loadColdGraph(ts *db.ExplorationStore) (*coldGraph, map[int64]*db.Node, error) {
	// Compaction must see the WHOLE graph, not the default row caps — pass a very
	// high limit so the LIMIT clause is effectively unbounded for real task sizes.
	const allRows = 1 << 30
	nodes, err := ts.Nodes(allRows)
	if err != nil {
		return nil, nil, err
	}
	edges, err := ts.Edges(allRows)
	if err != nil {
		return nil, nil, err
	}
	cgNodes := make([]cgNode, 0, len(nodes))
	byID := make(map[int64]*db.Node, len(nodes))
	for _, n := range nodes {
		cgNodes = append(cgNodes, cgNode{ID: n.ID, Kind: n.Kind, State: n.State})
		byID[n.ID] = n
	}
	cgEdges := make([]cgEdge, 0, len(edges))
	for _, e := range edges {
		cgEdges = append(cgEdges, cgEdge{From: e.From, Rel: e.Rel, To: e.To})
	}
	return newColdGraph(cgNodes, cgEdges), byID, nil
}

func toDBStampOps(ops []stampOp) []db.StampOp {
	out := make([]db.StampOp, len(ops))
	for i, o := range ops {
		out[i] = db.StampOp{ID: o.ID, Set: o.Set, Round: o.Round}
	}
	return out
}

// applyStampsInPlace folds the just-applied ops into the in-memory stamp map so
// eligibility can be computed immediately without a re-read.
func applyStampsInPlace(stamps map[int64]*int64, ops []stampOp) {
	for _, o := range ops {
		if o.Set {
			r := o.Round
			stamps[o.ID] = &r
		} else {
			stamps[o.ID] = nil
		}
	}
}

// --- helpers: digest payload ---

// digestPayload builds the digest node payload (cold-digest §1): the body, the
// member ids split by kind (restore cache; source of truth is the covers edges),
// the anchor ids, the generation, and the change-detection signature.
func digestPayload(body string, b block, nodeByID map[int64]*db.Node, generation int, signature string) map[string]any {
	var facts, intents []int64
	for _, m := range b.Members {
		if n := nodeByID[m]; n != nil && n.Kind == db.KindIntent {
			intents = append(intents, m)
		} else {
			facts = append(facts, m)
		}
	}
	return map[string]any{
		"body":       body,
		"member_ids": map[string]any{"facts": facts, "intents": intents},
		"anchor_ids": b.Anchors,
		"generation": generation,
		"signature":  signature,
	}
}

func digestSigGen(n *db.Node) (string, int) {
	var p struct {
		Signature  string `json:"signature"`
		Generation int    `json:"generation"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return p.Signature, p.Generation
}

func digestMemberIDs(n *db.Node) []int64 {
	var p struct {
		MemberIDs struct {
			Facts   []int64 `json:"facts"`
			Intents []int64 `json:"intents"`
		} `json:"member_ids"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return append(append([]int64{}, p.MemberIDs.Facts...), p.MemberIDs.Intents...)
}

// --- helpers: compression input + LLM (§4) ---

func nodeSummary(n *db.Node) string {
	if n == nil {
		return ""
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok {
			return s
		}
		if t, ok := p["text"].(string); ok {
			return t
		}
	}
	return ""
}

func nodeConfidence(n *db.Node) string {
	if n == nil {
		return ""
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if c, ok := p["confidence"].(string); ok {
			return c
		}
	}
	return ""
}

// buildCompressionInput renders the connected sub-graph for the §4 prompt:
// member nodes (summary + id + kind + state + confidence), the internal blood
// edges among members, and — for a §3.1 shared-parent group — the anchor parents
// as context ("共同父 #p"), which are NOT members.
func buildCompressionInput(g *coldGraph, b block, nodeByID map[int64]*db.Node) string {
	memberSet := make(map[int64]bool, len(b.Members))
	for _, m := range b.Members {
		memberSet[m] = true
	}
	var sb strings.Builder
	sb.WriteString("【成员节点（要压缩的）】：\n")
	for _, m := range b.Members {
		n := nodeByID[m]
		kind := "fact"
		if n != nil && n.Kind == db.KindIntent {
			kind = "intent"
		}
		state := ""
		if n != nil {
			state = n.State
		}
		line := fmt.Sprintf("- #%d [%s/%s] %s", m, kind, state, nodeSummary(n))
		if conf := nodeConfidence(n); conf != "" {
			line += fmt.Sprintf(" (confidence=%s)", conf)
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	// internal edges among members
	var edgeLines []string
	for _, m := range b.Members {
		for _, to := range g.children[m] {
			if memberSet[to] {
				edgeLines = append(edgeLines, fmt.Sprintf("- #%d 产出/派生→ #%d", m, to))
			}
		}
	}
	if len(edgeLines) > 0 {
		sb.WriteString("\n【成员之间的血缘边（父→子）】：\n")
		sort.Strings(edgeLines)
		sb.WriteString(strings.Join(edgeLines, "\n"))
		sb.WriteByte('\n')
	}
	if len(b.Anchors) > 0 {
		sb.WriteString("\n【共同父 / 上下文锚（不是成员，只用于理解这些结果从哪个意图探出）】：\n")
		for _, a := range b.Anchors {
			n := nodeByID[a]
			state := ""
			if n != nil {
				state = n.State
			}
			fmt.Fprintf(&sb, "- #%d [%s] %s\n", a, state, nodeSummary(n))
		}
	}
	return sb.String()
}

// compress runs the §4 body LLM call on one block. Uses the same model the agent
// runs on; thinking is left to the model/gateway (a pure summarization step —
// but MiniMax-M3.1 等**强制 adaptive thinking** 的模型会拒绝显式的
// thinking.type=disabled，所以这里不发该字段）。
func (c *Compactor) compress(ctx context.Context, g *coldGraph, b block, nodeByID map[int64]*db.Node) (string, error) {
	tokens := c.outTokens
	if tokens <= 0 {
		tokens = defaultCompactionTokens
	}
	req := llm.CompletionRequest{
		System: []string{compressionSystemPrompt},
		// MaxTokens 是思考+正文共用的预算,给小了模型会一直想、正文轮不到(见
		// outTokens 字段的注释)。这里给足冗余。
		Messages:  []llm.Message{llm.UserText(buildCompressionInput(g, b, nodeByID))},
		MaxTokens: tokens,
	}
	msg, stop, usage, err := c.prov.Complete(ctx, req)
	if err != nil {
		return "", err
	}
	body := strings.TrimSpace(msg.Text())
	if body == "" {
		// 空正文必须把诊断信息带出来，否则只有一句「empty body from model」
		// 完全无法定位。以前这里丢掉了 stop reason 与 usage，排查时只能靠猜。
		// 实测过的两类根因：
		//   - stop="length"：输出被 max_tokens 截断（adaptive thinking 模型
		//     会先烧一大段思考，正文没轮到最后就撞上限）。
		//   - 只有 thinking 块没有 text 块：模型确实在思考，但正文为空。
		return "", fmt.Errorf("empty body from model (stop=%q blocks=%d in=%d out=%d thinking=%d)",
			stop, len(msg.Content), usage.InputTokens, usage.OutputTokens, countThinking(msg))
	}
	return body, nil
}

// compressChunked 压缩一个块，但把过大的块先切成若干子块、逐个压缩。
//
// 为什么要切:实测思考型模型能否收尾取决于**单次输入规模**,与输出预算无关——
// 3 个节点(743 prompt token)在 32768 预算下正常收尾,26 个节点(3084 prompt
// token)即使给 32768 也会把预算烧光、跑 211 秒不出正文。超大连通块(一个
// 连通分量可能有几十个节点)在实践中就是这样,所以必须切。
//
// 切分保持原有语义:每块仍然是「一组彼此关联的节点」,只是规模更小。返回的
// 多个 body 由调用方拼成一段摘要(分隔标记),语义与原来的一段 body 等价。
//
// 子块是**并发**压缩的(串行会撞墙钟上限):一个 200 节点的连通块按 6 节点/块
// 切出 32 个子块,实测单子块约 124 秒。串行就是 32×124 ≈ 66 分钟,而单次
// 后台压缩的墙钟上限只有 20 分钟(defaultCompactionDuration)——必然
// context deadline exceeded。实测线上就是这个形态:一个块报「子块 15/32
// 压缩失败」,前 14 个子块已经白烧了 30 分钟 LLM 时间,整块作废。
//
// 并发度取 4 而不是全部 32:上游是共享的限流网关,32 路并发会把上游打爆
// 反而全失败;4 路并发把 66 分钟压到约 17 分钟,稳稳落在 20 分钟上限内。
// 单个子块失败仍然让整块失败(宁可重试也不要写半截摘要),但**成功的子块
// 结果会被保留**,失败重试时不必从头再来。
func (c *Compactor) compressChunked(ctx context.Context, g *coldGraph, b block, nodeByID map[int64]*db.Node) ([]string, error) {
	limit := c.maxBlockMembers
	if limit <= 0 || len(b.Members) <= limit {
		body, err := c.compress(ctx, g, b, nodeByID)
		if err != nil {
			return nil, err
		}
		return []string{body}, nil
	}
	// 子块数：按 limit 切分，最后一块可能不满。
	nSubs := (len(b.Members) + limit - 1) / limit
	type subResult struct {
		body string
		err  error
	}
	subs := make([]subResult, nSubs)

	// 并发执行,限制并发度。
	sem := make(chan struct{}, compactionSubConcurrency)
	var wg sync.WaitGroup
	for k := 0; k < nSubs; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			i := k * limit
			j := i + limit
			if j > len(b.Members) {
				j = len(b.Members)
			}
			sub := block{Members: b.Members[i:j], Anchors: b.Anchors}
			body, err := c.compress(ctx, g, sub, nodeByID)
			subs[k] = subResult{body: body, err: err}
		}(k)
	}
	wg.Wait()

	out := make([]string, 0, nSubs)
	for k, s := range subs {
		if s.err != nil {
			// 某个子块失败：整块视为失败(宁可重试也不要写半截摘要)。
			return nil, fmt.Errorf("子块 %d/%d 压缩失败: %w", k+1, nSubs, s.err)
		}
		out = append(out, s.body)
	}
	return out, nil
}

// countThinking 数一数消息里有几个思考块。用于区分「模型只思考没正文」
// 与「模型什么都没返回」。
func countThinking(msg llm.Message) int {
	n := 0
	for _, b := range msg.Content {
		if b.Type == llm.BlockThinking {
			n++
		}
	}
	return n
}

// compressionSystemPrompt is the §4 body prompt.
const compressionSystemPrompt = `你在压缩一组【彼此关联】的探索节点，产出一段综合结论(body)，供规划者快速掌握"这一片已经探明了什么"。

输入是一个连通子图：
- 节点：每条是一个意图或事实的 summary（一句话），带 id、类型(intent/fact)、state、confidence(若有)。
- 关系：节点之间的血缘边（A 派生自 B / A 产出 B），说明它们如何串联。
- 若节点间没有直接血缘边、但同属一个上游意图（会另给出该上游意图作为"共同父 #p"），则按"这个意图（#p）探到了什么"来综合它们——共同父只是上下文锚、不是要压缩的成员。

据此写一段 body：
1. 综合、不罗列：顺着关系把因果串起来（哪个事实催生哪个意图、哪条意图产出了哪个结论），讲成"这一片探索得出了什么"，不要把每条 summary 抄一遍。
2. 保留区分度：彼此不同的结论分别说清，别揉成一句笼统的话。
3. 保留证据强度：带 confidence 的结论标出 observed / inferred；inferred 的否定/存疑结论要点明它只是推断、可复核，别写成定论。
4. 带上 id：每条结论后标注来源节点 id（如"…（#12,#28）"），让规划者能按 id 还原原节点。
5. 正向陈述、只写输入里有的：不脑补、不引入输入中没有的判断。
6. 长度随内容自适应：结论少就短，多且互不相同就写够——但整体显著短于所有输入 summary 的总和。
7. 保留终态语义：涉及 intent 成员的，保留其 state 与收场含义——exhausted 要点明是「手段穷尽、方向无增量」还是「步数/时间被掐断、未完成非死路」（输入带 stop_reason 时照抄），blocked 标明是外部故障。规划者据它判「这个方向还能不能接续」，压缩时吞掉这一位 = 接续决策失据。

只输出 body 正文本身。`
