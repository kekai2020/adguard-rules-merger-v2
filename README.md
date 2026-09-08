# AdGuard Rules Merger V2

自动合并多个 AdGuard Home 拦截规则订阅源，实现智能去重和优化。

## 特性

- **三阶段精确去重** — 精确匹配 + 通配符覆盖 + Allow 覆盖 Block
- **来源追踪** — 每条规则记录所有贡献源，方便审计
- **多格式支持** — AdGuard (`||domain^`)、Hosts (`0.0.0.0`)、纯域名
- **并发获取** — 多线程并行下载，高效处理大量源
- **冲突检测** — 识别同域名的 block/allow 冲突
- **完整验证** — 内置验证工具，确保合并结果无遗漏

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 使用配置文件合并
python merge_rules.py --config config/sources.yaml

# 合并并验证
python merge_rules.py -c config/sources.yaml --verify --report

# 试运行（不写文件）
python merge_rules.py -c config/sources.yaml --dry-run

# 指定源 URL
python merge_rules.py -s https://example.com/rules1.txt https://example.com/rules2.txt
```

## 去重算法

```
Phase 1 — 精确去重
  Key = (normalized_domain, rule_type, wildcard)
  重复规则合并来源集合，保留一条。
  *.a.com 和 a.com 视为不同规则。

Phase 2 — 通配符覆盖
  构建 DomainTrie，移除被通配符覆盖的子域名规则。
  *.a.com 移除 sub.a.com，但不移除 a.com 本身。

Phase 3 — Allow 覆盖 Block（可选）
  同域名同时存在 block + allow → 保留 allow（AdGuard 语义）。
  通过 --no-allow-override 禁用。
```

## CLI 参数

| 参数 | 说明 |
|------|------|
| `-c, --config` | YAML 配置文件路径 |
| `-s, --sources` | 直接指定源 URL 列表 |
| `-o, --output` | 输出文件路径（默认 `merged_rules.txt`） |
| `-r, --report` | 生成详细报告 |
| `--report-format` | 报告格式：markdown / text / json |
| `--detect-conflicts` | 检测 block/allow 冲突 |
| `--no-allow-override` | 禁用 Phase 3 冲突解决 |
| `--verify` | 合并后自动验证完整性 |
| `--dry-run` | 只处理不写文件 |
| `--timeout` | HTTP 超时秒数（默认 60） |
| `--max-workers` | 并发数（默认 10） |
| `-v, --verbose` | 详细日志 |
| `-q, --quiet` | 安静模式 |

## 项目结构

```
merger/
  __init__.py       包初始化
  core.py           RuleEngine + DomainTrie + DedupReport
  models.py         Rule 数据模型（一致的 __eq__/__hash__）
  parser.py         RuleParser（多格式解析）
  reporter.py       MergeReporter（按源归因报告）
config/
  sources.yaml      订阅源配置
tests/
  test_core.py      65 个单元测试
merge_rules.py      CLI 入口
validate_output.py  独立验证工具
config_loader.py    配置加载 + 校验
```

## 测试

```bash
# 运行全部测试
pytest tests/ -v

# 带覆盖率
pytest tests/ --cov=merger --cov-report=html
```

## 验证合并结果

```bash
# 独立验证
python validate_output.py --config config/sources.yaml --merged output/merged_rules.txt

# 合并时自动验证
python merge_rules.py -c config/sources.yaml --verify
```

## 配置示例

```yaml
sources:
  - name: "AdGuard DNS filter"
    url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
    enabled: true

  - name: "CHN: anti-AD"
    url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt"
    enabled: true
```

## GitHub Actions

项目配置了自动合并 workflow，每 6 小时运行一次。也可手动触发。

## License

MIT
