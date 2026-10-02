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
- 审查页面上对草稿的任何修改都会立即清除当前展示的旧证据。
- `INVALID_READ` 属于输入错误（HTTP 422），结论确定性可复现但不予冻结。

## 快速运行（Docker Compose）

宿主机端口通过 `HOST_PORT` 配置（默认 8080）：

```bash
cp .env.example .env          # 可改 HOST_PORT
docker compose up -d --build  # web 服务带 /healthz 健康检查
# 打开 http://localhost:${HOST_PORT:-8080}/
```

单次验收服务（代码测试 → 差分模糊 → 镜像构建检查 → HTTP 冒烟），退出码即验收结论：

```bash
docker compose run --rm verify; echo "verify exit code: $?"
# 或：
docker compose up --abort-on-container-exit --exit-code-from verify
```

`verify` 容器通过挂载 `/var/run/docker.sock` 以 Docker Engine API（UNIX socket，
纯标准库实现，容器内无需 docker CLI / pip 包）完成镜像构建检查；其中差分模糊阶段
使用一份独立 oracle（三色 DFS 判环 + 枚举全部简单环 + 朴素时间线）对 400 组随机
历史及注入的 2/3/4/5 长度写偏差环做交叉验证。

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
| GET  | `/healthz` | 健康检查 |
| GET  | `/` | 审查页面（三个预设场景：过期读 / 写偏差环 / 可串行历史） |
| POST | `/api/audits` | 提交并冻结/回放（201 首次冻结，200 回放，400 结构错误，409 标识冲突，422 过期版本读） |
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
src/store.py          规范化指纹与冻结记录存储（线程安全）
src/server.py         标准库 HTTP 服务
static/index.html     审查页面（编辑草稿、提交真实接口、渲染三类结论）
verify/run_verify.py  单次验收：单测 + 差分模糊 + 镜像构建检查 + HTTP 冒烟
verify/fuzz_oracle.py 独立 oracle（DFS 判环 / 全简单环枚举 / 朴素时间线）
verify/tests/         51 个单元/集成测试（含模拟 Docker daemon、HTTP 端到端）
verify/ui_shim_check.js  本地用最小 DOM shim 执行真实页面脚本校验序列化（需 node）
Dockerfile / docker-compose.yml / .env.example / .dockerignore
```
