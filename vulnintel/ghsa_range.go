package vulnintel

import (
	"fmt"
	"strconv"
	"strings"
)

// semver 区间判定：把 GHSA 的 `vulnerable_version_range` 表达式与目标版本比较。
//
// ## 为什么自己写而不是用库
//
// 1) 宿主环境不保证有 semver 工具链（这是 agent 跑在里面的最小镜像）；
// 2) 表达式形态其实很窄：GHSA 只用逗号分隔的 AND 条件，每条是
//    `<op> <version>`（op ∈ {<, <=, >, >=, =}），**没有** `||` 析取、
//    **没有** `^`/`~` 范围简写（实测 GitHub 的数据里都是显式边界）。
// 3) 判定错了的代价不对称：**误判「不受影响」会让模型直接跳过漏洞**——
//    这正是新披露 CVE 最容易丢的地方。所以拿不准时一律判「可能受影响」。
//
// ## 保守策略
//
// - 目标版本解析不出来（带后缀的预发布版、自定义版本号）→ 判 **不受影响**是错的，
//   判「可能受影响」才对。所以解析失败 → Affected=true，Reason 写明「无法解析」。
// - 区间表达式里有不认识的算子 → 同样 Affected=true（保守）。
// - 区间为空（GHSA 给了包但没给区间）→ Affected=true + 明确说明「GHSA 未给区间」。

// semverRange 是一条已解析的版本约束。
type semverRange struct {
	// Op 是比较算子：< <= > >= =。
	Op string
	// Ver 是比较目标版本。
	Ver semver
	// Raw 是原始文本（错误说明用）。
	Raw string
}

// semver 是一个可比较的版本号。
type semver struct {
	Major, Minor, Patch int
	// Pre 是预发布标识（1.0.0-alpha → "alpha"）。空 = 正式版。
	Pre string
	// Valid 为 false 表示解析失败。
	Valid bool
	// Comparable 为 false 表示「解析出来了但不该拿它跟稳定版比大小」。
	//
	// 例：8.3.1-dev-build、1.0.0-SNAPSHOT、2.0.0-patch1——这些是**开发/构建
	// 版本**，版本号本身不稳定（下次构建可能还是 8.3.1-dev-build，但内容不同）。
	// 拿它们跟 GHSA 的「< 3.10.0」比大小得到的是**假结论**。
	//
	// 判错方向不对称：误判「不受影响」会让模型直接跳过漏洞，所以这种情况
	// 一律按「可能受影响」处理。
	Comparable bool
}

// parseSemver 解析版本号。
//
// 支持：`1`、`1.2`、`1.2.3`、`1.2.3-alpha.1`、`v1.2.3`、`1.2.3-rc1`。
// 只取前 3 段数字，后面的忽略（PHP 的 8.3.1、.NET 的 4.8.1 都够用）。
func parseSemver(s string) semver {
	v := semver{}
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if s == "" {
		return v
	}
	// 预发布：拆出 - 之后的部分。
	pre := ""
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	nums := make([]int, 0, 3)
	for _, p := range parts {
		if len(nums) >= 3 {
			break
		}
		// 段里可能有非数字后缀（8.3.1RC1）——取数字前缀。
		digits := leadingDigits(p)
		if digits == "" {
			break
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			break
		}
		nums = append(nums, n)
	}
	if len(nums) == 0 {
		return v
	}
	v.Major = nums[0]
	if len(nums) > 1 {
		v.Minor = nums[1]
	}
	if len(nums) > 2 {
		v.Patch = nums[2]
	}
	v.Pre = pre
	v.Valid = true
	// 预发布/开发后缀 → 解析出来了但不可比（见 semver.Comparable 的说明）。
	v.Comparable = isComparablePre(pre)
	return v
}

// isComparablePre 判断预发布标识是否可与稳定版比大小。
//
// 规范里的预发布（alpha/beta/rc）**有确定的顺序**（1.0.0-alpha < 1.0.0），
// 可以比。但开发/构建标识（dev、snapshot、build、rc1、patch1…）没有这种保证——
// 版本号不稳定，比出来的结论是假的。
func isComparablePre(pre string) bool {
	if pre == "" {
		return true
	}
	p := strings.ToLower(pre)
	for _, marker := range []string{"dev", "snapshot", "build", "nightly", "git", "dirty", "local", "patch"} {
		if strings.Contains(p, marker) {
			return false
		}
	}
	// 规范预发布：alpha / beta / rc（可带数字后缀）。
	normalized := strings.TrimRight(p, "0123456789")
	switch normalized {
	case "alpha", "beta", "rc", "pre", "preview":
		return true
	}
	// 认不出来的形态 → 不可比（保守）。
	return false
}

// leadingDigits 取一段开头的连续数字。
func leadingDigits(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return s[:i]
		}
	}
	return s
}

// compareSemver 比较两个版本：-1 / 0 / 1。
//
// 预发布版本**小于**同号正式版（semver 规范：1.0.0-alpha < 1.0.0）。
func compareSemver(a, b semver) int {
	if a.Major != b.Major {
		if a.Major < b.Major {
			return -1
		}
		return 1
	}
	if a.Minor != b.Minor {
		if a.Minor < b.Minor {
			return -1
		}
		return 1
	}
	if a.Patch != b.Patch {
		if a.Patch < b.Patch {
			return -1
		}
		return 1
	}
	switch {
	case a.Pre == "" && b.Pre == "":
		return 0
	case a.Pre == "":
		return 1 // 正式版 > 预发布
	case b.Pre == "":
		return -1
	case a.Pre < b.Pre:
		return -1
	case a.Pre > b.Pre:
		return 1
	}
	return 0
}

// String 把版本还原成字符串（用于写进 CPE 区间列）。
//
// 还原成「补零到三段」的形式（1 → 1.0.0），因为 VersionInRange 的
// cmpVersions 按段比大小，段数不同不影响结果，但写全三段更便于展示。
func (v semver) String() string {
	if !v.Valid {
		return ""
	}
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// ParseGhsaRange 解析 GHSA 的版本区间表达式。
//
// 支持形态：逗号分隔的 AND 条件，每条 `<op> <version>`。
// 解析不了的条目会被跳过并记在 unknown 里——调用方据此走保守路径。
func ParseGhsaRange(expr string) (conds []semverRange, unknown []string) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}
	for _, part := range strings.Split(expr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 1 {
			// 裸版本号：当作「= 该版本」。
			if v := parseSemver(fields[0]); v.Valid {
				conds = append(conds, semverRange{Op: "=", Ver: v, Raw: part})
				continue
			}
			unknown = append(unknown, part)
			continue
		}
		op := fields[0]
		switch op {
		case "<", "<=", ">", ">=", "=":
		default:
			unknown = append(unknown, part)
			continue
		}
		verStr := fields[1]
		// 处理 `<= 2.0` 这种带空格的，也处理 `<=2.0`（已被 Fields 拆开）。
		v := parseSemver(verStr)
		if !v.Valid {
			unknown = append(unknown, part)
			continue
		}
		if !v.Comparable {
			// 区间端点本身是开发版 → 这条条件没法判，交给调用方走保守路径。
			unknown = append(unknown, part)
			continue
		}
		conds = append(conds, semverRange{Op: op, Ver: v, Raw: part})
	}
	return conds, unknown
}

// GhsaVersionAffected 判断目标版本是否落在 GHSA 给的受影响区间里。
//
// 返回值：
//   - Affected=false：**确定**不在区间内（区间可解析且目标版本可解析）。
//   - Affected=true：可能受影响——要么确实在区间内，要么**拿不准**
//     （版本解析不出、区间有不懂的算子、区间为空）。保守方向是「宁可误报」。
//   - Reason：给人/模型看的判定依据。
func GhsaVersionAffected(pkg GhsaPackage, targetVersion string) GhsaAffected {
	res := GhsaAffected{Package: pkg}
	target := parseSemver(targetVersion)
	if strings.TrimSpace(pkg.Range) == "" {
		res.Affected = true
		res.Reason = fmt.Sprintf("GHSA 未给出受影响版本区间（包 %s）——按可能受影响处理", pkg.Name)
		return res
	}
	conds, unknown := ParseGhsaRange(pkg.Range)
	if len(conds) == 0 {
		res.Affected = true
		res.Reason = fmt.Sprintf("GHSA 版本区间 %q 无法解析（%s）——按可能受影响处理", pkg.Range, strings.Join(unknown, "; "))
		return res
	}
	if !target.Valid {
		res.Affected = true
		res.Reason = fmt.Sprintf("目标版本 %q 无法解析，GHSA 区间为 %q——按可能受影响处理（请手工核对）", targetVersion, pkg.Range)
		return res
	}
	if !target.Comparable {
		res.Affected = true
		res.Reason = fmt.Sprintf("目标版本 %q 是开发/预发布构建（版本号不稳定，与稳定版区间不可直接比大小），"+
			"GHSA 区间为 %q——按可能受影响处理（请手工核对）", targetVersion, pkg.Range)
		return res
	}
	// 区间内所有条件都要满足（AND）。
	for _, c := range conds {
		cmp := compareSemver(target, c.Ver)
		ok := false
		switch c.Op {
		case "<":
			ok = cmp < 0
		case "<=":
			ok = cmp <= 0
		case ">":
			ok = cmp > 0
		case ">=":
			ok = cmp >= 0
		case "=":
			ok = cmp == 0
		}
		if !ok {
			res.Affected = false
			res.Reason = fmt.Sprintf("版本 %s 不满足 %s（GHSA 区间 %q）", targetVersion, c.Raw, pkg.Range)
			return res
		}
	}
	res.Affected = true
	res.Reason = fmt.Sprintf("版本 %s 落在 GHSA 受影响区间 %q 内", targetVersion, pkg.Range)
	if len(unknown) > 0 {
		res.Reason += fmt.Sprintf("（区间里 %s 未识别，已按满足处理）", strings.Join(unknown, "; "))
	}
	return res
}

// GhsaRangeUndetermined 判断一条 GHSA 条目的版本信息是否「未确认」。
//
// 两种「未确认」：
//  1. 根本没有包信息（GHSA 条目没给 affected）——不是包级漏洞（比如是仓库级 advisory）；
//  2. 有包但区间为空——GHSA 自己也还没定范围。
//
// 与 NVD 的 VersionRangeUndetermined 是同一件事的两个来源——**任一来源能确定
// 就算确定**。
func GhsaRangeUndetermined(f GhsaFinding) bool {
	if len(f.Packages) == 0 {
		return true
	}
	for _, p := range f.Packages {
		if strings.TrimSpace(p.Range) == "" {
			return true
		}
	}
	return false
}
