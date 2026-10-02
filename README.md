# 星载参数库 · 多版本事务可串行化审查服务

地面批处理并发提交星载参数事务时，审查员需要确认：各事务读取的版本与最终写入
能否解释为**同一串行执行**，避免两个彼此独立的安全修改在快照下共同越过联锁。

本服务对一份冻结审计载荷执行两步裁决：

1. **版本核验**——每次读取是否取到其事务 `start` 时刻之前最新的已提交版本
   （提交时刻恰等于开始时刻不可见）。不合规读取报告为输入错误 `INVALID_READ`，
   列出期望写入者/值与实际声明，且不进入图裁决。
2. **多版本串行化图（MVSG）**——精确构造三类依赖：
   - `wr` 写读依赖：读取者读到某写入者安装的版本；
   - `ww` 写写版本序：同键写入按提交时刻（并列按事务标识）排序；
   - `rw` 读写反依赖：读取版本之后又有同键提交写入，写入者必须排在读取之后。

   - 图无环：返回按事务标识做稳定平局裁决（Kahn + 最小堆）的**一条串行顺序**，
     并按该顺序从初始键值逐读复算，给出每步读到的值与最终键值；
   - 图有环：返回**边数最少**的闭环；同长度取以最小事务标识为起点旋转后
     字典序最小者，逐边列出类型、键、双方步骤序号与版本依据。

## 冻结语义

- 相同 `audit_id` + 相同载荷（按规范化 JSON 指纹比较）重传 → 回放原结论
  （HTTP 200，响应头 `X-Audit-Replayed: true`），不重新计算；
- 相同 `audit_id` + 不同载荷 → `409 AUDIT_ID_CONFLICT`，**绝不覆盖**已冻结记录；
- 审查页面上对草稿的任何修改都会立即清除当前展示的旧证据；
- `INVALID_READ` 属于输入错误（HTTP 422），结论确定性可复现但不予冻结。

### 掉电 / 重启后的可校验持久化

首次成功冻结前，服务会把**规范化载荷指纹与完整裁决证据**写成一条自描述记录
（`version / audit_id / fingerprint / verdict / checksum`，校验和为除 `checksum`
字段外整条记录的 SHA-256），写入采用「临时文件 → fsync → 原子 rename →
目录 fsync」，并以末尾换行作为提交标记：**只有记录完整落盘并回读校验通过后，
才向调用方返回成功**；写盘失败返回 5xx 且内存索引不落该记录，调用方可安全重试。

服务启动时重放日志恢复审计索引：

- 以换行提交的合法记录逐条重建索引；重启后相同标识相同载荷仍回放原结论，
  改换载荷仍返回 `409`，并发同载荷提交在锁下只产生**一条**冻结记录；
- 末尾**未完成或校验不全**的写入（无提交换行的尾段，如异常断电残留）一律丢弃，
  绝不形成可读取结论；同目录遗留的 `*.tmp` 临时文件启动时清理；
- 已提交但**已损坏**（JSON 截断 / 字段缺失 / 校验和不符）的既有完整记录使
  健康状态明确失败：`GET /healthz` 返回 `503 AUDIT_LOG_CORRUPT`，该日志不提供
  任何结论、拒绝一切新冻结（`503 AUDIT_LOG_INTEGRITY`），且不会被重写掩盖。

重新打开审查页面时，页面会按当前审计标识静默取回重启后恢复的结论；未冻结的
标识仍显示草稿提示。

持久化日志默认位于 `/app/data/audit.log`（Compose 以 `./data` 绑定挂载，故
容器重启 / 主机断电均不丢失），可用环境变量 `AUDIT_LOG` 覆盖路径；置为空串
可退回纯内存存储。

## 快速运行（Docker Compose）

宿主机端口通过 `HOST_PORT` 配置（默认 8080）：

```bash
cp .env.example .env          # 可改 HOST_PORT
docker compose up -d --build  # web 服务带 /healthz 健康检查
# 打开 http://localhost:${HOST_PORT:-8080}/
```

单次验收服务（代码测试 → 差分模糊 → 镜像构建检查 → HTTP 冒烟 → Compose 重启
耐久性验收），退出码即验收结论：

```bash
docker compose run --rm verify; echo "verify exit code: $?"
# 或：
docker compose up --abort-on-container-exit --exit-code-from verify
```

`verify` 容器通过挂载 `/var/run/docker.sock` 以 Docker Engine API（UNIX socket，
纯标准库实现，容器内无需 docker CLI / pip 包）完成镜像构建检查；其中差分模糊阶段
使用一份独立 oracle（三色 DFS 判环 + 枚举全部简单环 + 朴素时间线）对 400 组随机
历史及注入的 2/3/4/5 长度写偏差环做交叉验证。最后的重启耐久性阶段会经同一
Engine API 先停掉 `web`、把旧日志归档为 `audit.log.preverify.<ts>` 并冷启动一个
空日志服务（保证验收可重复：首次冻结确为 201），随后真正重启 `web` 容器，
覆盖：已创建结论的原样回放、相同标识改载荷仍冲突、并发同载荷只产生一条冻结
记录、异常断电留下的未完成尾记录被丢弃且不可读、以及已损坏的已提交完整记录
使健康检查明确失败（`503`）；验收结束后自动还原完整日志，退出码汇总全部阶段。

## 载荷格式

```json
{
  "audit_id": "orbit-2026-09-30-batch-07",
  "initial": {"x": 100, "y": 100},
  "transactions": [
    {
      "id": "T1",
      "start": 1,
      "commit": 5,
      "steps": [
        {"op": "read",  "key": "x", "observed": "initial"},
        {"op": "write", "key": "y", "value": -100}
      ]
    },
    {
      "id": "T2", "start": 2, "commit": 6,
      "steps": [
        {"op": "read",  "key": "y", "observed": "initial"},
        {"op": "write", "key": "x", "value": -100}
      ]
    }
  ]
}
```

- 事务数量 1..24，`start <= commit`，步骤必须按真实发生顺序排列；
- 读步骤的 `observed`：
  - `"initial"`：声明读到初始版本（值由 `initial` 给出）；
  - JSON 标量：声明读到的初始版本具体字面值（会与初始值比对）；
  - `{"source": "txn", "writer": "<事务标识>"}`：声明读到该事务的写入；
- 同一事务内不允许重复写同一键；写入值与初始值均为 JSON 标量。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET  | `/healthz` | 健康检查；重放发现已损坏的已冻结记录时返回 503 `AUDIT_LOG_CORRUPT` |
| GET  | `/` | 审查页面（三个预设场景：过期读 / 写偏差环 / 可串行历史；重开页面自动取回已恢复结论） |
| POST | `/api/audits` | 提交并冻结/回放（201 首次冻结，200 回放，400 结构错误，409 标识冲突，422 过期版本读；落盘失败 500，日志校验失败 503） |
| GET  | `/api/audits/<audit_id>` | 取回冻结结论（404 不存在） |
| GET  | `/api/audits` | 已冻结审计标识列表 |

## 不使用容器的本地开发

仅依赖 Python 3.11 标准库：

```bash
python3 src/server.py            # 默认 0.0.0.0:8080，PORT 环境变量可改
python3 -m unittest discover -s verify/tests -p 'test_*.py' -v
```

## 目录结构

```
src/mvscc.py          版本核验 + MVSG 构造 + 稳定拓扑序/最短环裁决 + 串行复算
src/store.py          规范化指纹、可校验冻结记录（fsync 原子落盘 + 启动重放/尾记录丢弃/损坏失败）
src/server.py         标准库 HTTP 服务（/healthz 反映日志健康）
static/index.html     审查页面（编辑草稿、提交真实接口、重开自动展示恢复结论）
verify/run_verify.py  单次验收：单测 + 差分模糊 + 镜像构建检查 + HTTP 冒烟 + Compose 重启耐久性
verify/fuzz_oracle.py 独立 oracle（DFS 判环 / 全简单环枚举 / 朴素时间线）
verify/tests/         单元/集成测试（含模拟 Docker daemon、HTTP 端到端、掉电尾记录与损坏恢复）
verify/ui_shim_check.js  本地用最小 DOM shim 执行真实页面脚本校验序列化（需 node）
data/audit.log        运行期冻结记录（绑定挂载，不入库不入镜像）
Dockerfile / docker-compose.yml / .env.example / .dockerignore
```
