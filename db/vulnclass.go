package db

// 漏洞类别(vulnclass)标准枚举与归一。
// 背景:模型上报的 vulnclass 是自由文本,同一漏洞类出现 SQLi/SQL注入/sql_injection
// 等十几种写法,聚合视图与指纹去重都被同义词稀释。这里定义一份稳定白名单 +
// 别名归一表,在写入层(RecordFindingTx/add_goal)把变体折到标准类别;
// 白名单之外的输入保留原值(不销毁信息),聚合时同值自然折叠。

import "strings"

// VulnClassList 标准类别白名单(给提示词引导模型用,顺序即报告展示顺序)。
var VulnClassList = []string{
	"注入", // SQL/命令/LDAP/XPath/模板注入等
	"XSS",
	"未授权访问", // 越权/IDOR/broken access control
	"弱口令",   // 默认凭据/简单密码
	"任意文件上传",
	"任意文件读取", // 路径穿越/LFI/任意下载
	"反序列化",
	"RCE", // 远程代码/命令执行
	"SSRF",
	"XXE",
	"信息泄露", // 敏感信息/源码/备份/目录列表
	"权限提升", // 本地提权
	"认证绕过",
	"逻辑漏洞", // 支付/验证码/竞态等业务逻辑
	"拒绝服务",
	"中间人劫持", // 明文传输/弱加密/证书问题
	"已知漏洞",  // CVE/NDay 命中,具体编号放 name
	"配置错误",  // CORS/服务错误配置等
	"其他",
}

// vulnClassAliases 变体→标准类别。键一律小写、去空格去连字符后匹配;
// 未命中的输入原样保留(TrimSpace),让新类别也能自洽存在。
var vulnClassAliases = map[string]string{
	// 注入
	"sqli": "注入", "sql注入": "注入", "sql_injection": "注入", "sql injection": "注入",
	"sqlinjection": "注入", "commandinjection": "注入", "命令注入": "注入", "ldap注入": "注入",
	"模板注入": "注入", "ssti": "注入", "injection": "注入", "nosql注入": "注入",
	"xpath注入": "注入", "注入漏洞": "注入", "promptinjection": "注入",
	"cmdinjection": "注入",
	// XSS
	"xss": "XSS", "crosssitescripting": "XSS", "存储型xss": "XSS", "反射型xss": "XSS",
	"domxss": "XSS", "跨站脚本": "XSS",
	// 未授权访问
	"idor": "未授权访问", "越权": "未授权访问", "水平越权": "未授权访问", "垂直越权": "未授权访问",
	"未授权": "未授权访问", "unauthorized": "未授权访问", "unauthorizedaccess": "未授权访问",
	"brokenaccesscontrol": "未授权访问", "访问控制": "未授权访问", "权限绕过": "未授权访问",
	// 弱口令
	"weakpassword": "弱口令", "默认凭据": "弱口令", "defaultcredentials": "弱口令",
	"默认密码": "弱口令", "弱密码": "弱口令", "口令爆破": "弱口令", "bruteforce": "弱口令",
	// 文件上传
	"文件上传": "任意文件上传", "任意文件上传漏洞": "任意文件上传", "unrestrictedfileupload": "任意文件上传",
	"fileupload": "任意文件上传", "上传漏洞": "任意文件上传", "webshell": "任意文件上传",
	// 文件读取
	"lfi": "任意文件读取", "路径穿越": "任意文件读取", "目录穿越": "任意文件读取", "pathtraversal": "任意文件读取",
	"任意文件下载": "任意文件读取", "任意文件包含": "任意文件读取", "文件包含": "任意文件读取",
	"fileread": "任意文件读取", "localfileinclusion": "任意文件读取",
	// 反序列化
	"deserialization": "反序列化", "反序列化漏洞": "反序列化", "java反序列化": "反序列化",
	"insecuredeserialization": "反序列化",
	// RCE
	"rce": "RCE", "remotecodeexecution": "RCE", "远程代码执行": "RCE", "远程命令执行": "RCE",
	"命令执行": "RCE", "代码执行": "RCE", "命令注入漏洞": "RCE", "oscommandinjection": "RCE",
	// SSRF
	"ssrf": "SSRF", "serversiderequestforgery": "SSRF", "服务端请求伪造": "SSRF",
	// XXE
	"xxe": "XXE", "xmlexternalentity": "XXE", "xml实体注入": "XXE",
	// 信息泄露
	"informationdisclosure": "信息泄露", "敏感信息泄露": "信息泄露", "信息泄漏": "信息泄露",
	"源码泄露": "信息泄露", "备份文件": "信息泄露", "目录列表": "信息泄露", "directorylisting": "信息泄露",
	"堆栈泄露": "信息泄露", "debug信息泄露": "信息泄露", "泄露": "信息泄露",
	// 权限提升
	"提权": "权限提升", "privesc": "权限提升", "privilegeescalation": "权限提升",
	"本地提权": "权限提升", "提权漏洞": "权限提升",
	// 认证绕过
	"authbypass": "认证绕过", "authenticationbypass": "认证绕过", "登陆绕过": "认证绕过",
	"登录绕过": "认证绕过", "身份认证绕过": "认证绕过",
	// 逻辑漏洞
	"业务逻辑": "逻辑漏洞", "businesslogic": "逻辑漏洞", "支付逻辑": "逻辑漏洞",
	"验证码绕过": "逻辑漏洞", "逻辑缺陷": "逻辑漏洞", "重放攻击": "逻辑漏洞", "竞态": "逻辑漏洞",
	// 拒绝服务
	"dos": "拒绝服务", "ddos": "拒绝服务", "denialofservice": "拒绝服务", "慢速攻击": "拒绝服务",
	// 中间人劫持
	"mitm": "中间人劫持", "中间人攻击": "中间人劫持", "明文传输": "中间人劫持", "弱加密": "中间人劫持",
	"证书问题": "中间人劫持", "https降级": "中间人劫持", "arp欺骗": "中间人劫持",
	// 已知漏洞
	"cve": "已知漏洞", "nday": "已知漏洞", "knownvulnerability": "已知漏洞",
	"永恒之蓝": "已知漏洞", "历史漏洞": "已知漏洞", "组件漏洞": "已知漏洞",
	// 配置错误
	"misconfiguration": "配置错误", "错误配置": "配置错误", "cors": "配置错误",
	"安全配置": "配置错误", "服务配置": "配置错误",
	// 其他
	"other": "其他", "uncategorized": "其他", "未知": "其他",
}

// NormalizeVulnClass 把上报的漏洞类别归一到标准枚举:
// 大小写/空白/连字符不敏感;命中别名表→标准类别;未命中→TrimSpace 原值保留。
// 空串归一后仍是空串(上游校验必填)。
func NormalizeVulnClass(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	key := strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "", "　", "").Replace(s))
	if v, ok := vulnClassAliases[key]; ok {
		return v
	}
	// CVE/MS 编号当类别写 → 已知漏洞(具体编号进 name 才是正道,但不销毁这类输入的归类)
	if strings.HasPrefix(key, "cve") || strings.HasPrefix(key, "ms") && isDigits(key[2:]) {
		return "已知漏洞"
	}
	// 白名单成员本身(含大小写变体如 "xss"/"RCE"/"注入")直接回标准写法
	for _, c := range VulnClassList {
		if strings.EqualFold(c, s) {
			return c
		}
	}
	return s
}

// VulnClassPromptText 提示词用白名单文本(schema description 引用,单一出处)。
func VulnClassPromptText() string {
	return strings.Join(VulnClassList, "/")
}

// isDigits 纯数字判断(CVE/MS 编号前缀归一用)。
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
