# h2 — 加固的 HTTP/2 帧处理层

面向反向代理的 HTTP/2 连接层，用 Go 重写并在协议解析与资源调度之间插入
硬性边界，专门对抗两类把旧代理打挂的攻击：

1. **快速重置（Rapid Reset, CVE-2023-44487）**：一条连接上高频
   `HEADERS → RST_STREAM`，旧实现为每个流都创建协程与后端请求。
2. **头部炸弹 / 无尽 CONTINUATION（CVE-2024-27316 类）**：用持续的头部
   续传帧和精心构造的 HPACK 动态表把内存与解码状态撑爆。

设计目标：攻击在触及业务协程与后端连接**之前**就被拦住；触发限制时严格
按 RFC 9113 返回正确错误码；正常浏览器拖动进度条、长连接播放器持续开流
等行为不被误断。

## 目录结构

| 文件 | 职责 |
| --- | --- |
| `frame.go` | 9 字节帧头读写、载荷边界、SETTINGS/PING/GOAWAY/RST/WINDOW_UPDATE/HEADERS 编解码 |
| `hpack_limits.go` | HPACK 预扫描计费器 + 有界解码器（动态表、块大小、插入数硬上限） |
| `limiter.go` | 每连接滑动窗口 + 三级状态机（NORMAL/DEGRADED/CLOSING）+ 并发信号量 |
| `flow.go` | 收发双向、连接级/流级流量控制窗口 |
| `stream.go` | 流状态、有界请求体缓冲、Responder（响应侧） |
| `conn.go` | 连接状态机：握手、帧分发、协议校验、GOAWAY 优雅退出 |
| `config.go` | 全部限额与阈值，默认值按视频 CDN 边缘场景调优 |
| `errors.go` | RFC 9113 §7 错误码与 `StreamError`/`ConnError` |
| `example/main.go` | 接入真实后端的反向代理示例 |

## 防护机制如何对应攻击

### 快速重置：先限流，再决定是否起协程

`Conn.handleHeaders` 在创建任何业务协程**之前**依次执行：

```
HEADERS 到达
  ├─ 流 ID 合法性（奇数、严格递增、未被复用）
  ├─ limiter.TryAcquire()          // 并发信号量，超限直接 REFUSED_STREAM
  ├─ limiter.RecordOpen()          // 滑窗记账
  └─ 头部块重组 + 解码（受全部 HPACK 硬上限约束）
        └─ 全部通过才 dispatchHandler() 起协程
```

攻击者无法再用一个 HEADERS 换一个协程：超并发的流在信号量处就被
`REFUSED_STREAM`（可重试错误码）挡回，业务协程只在通过所有检查后才创建。

### 三级自适应状态机（`limiter.go`）

- **NORMAL**：完整并发上限，仅记账。
- **DEGRADED**：有效并发上限降到 `DegradedMaxConcurrentStreams`（默认 32），
  连接继续服务；安静度过 `Cooldown` 后自动恢复 NORMAL（迟滞，避免抖动）。
- **CLOSING**：不再接收新流，发送 `GOAWAY(ENHANCE_YOUR_CALM)`，排空在途
  流后按 `GoAwayGrace` 关闭 TCP。

### 为什么不会误伤正常观众

判断"快速重置"而非"正常取消"靠两道独立闸门 + 一个绝对预算：

1. **最小样本数 `MinSamples`（默认 50）**：窗口内开流数不足时不看比率。
   小样本下 2/3 的取消率没有统计意义，浏览器的偶发取消直接被忽略。
2. **幻影流比例 `ShortStreamFraction`**：只有在后端工作真正开始
   （处理器调用 `r.MarkDispatched()`，即上游连接已建立）**之前**收到的
   RST 才记为 phantom。拖动进度条取消的是已经在跑的请求 → 非 phantom →
   即使原始重置比率很高也不升级。这是区分攻击与正常 seek 的核心。
3. **幻影流绝对上限 `MaxConcurrentShortStreams`（默认 200/窗口）**：绕过
   比率数学的硬预算，任何真实 UI 手势都不可能在 10 秒内产生 200 个
   "未干活就取消"的流，但攻击轻松突破。

长连接播放器持续开新流不会累积：计数在 `StatWindow` 滑动窗口内，窗口滑过
即老化，不是连接生命周期内的单调累加（见
`TestLimiterSteadyPlayerTraffic`）。

### 头部炸弹：解码前预扫描 + 多层硬上限

`BoundedDecoder` 对每个重组完成的头部块先做**表示层预扫描**（线性、不解
Huffman、不改表），再交给有状态的 `hpack.Decoder`：

| 上限 | 默认值 | 触发错误码 |
| --- | --- | --- |
| 原始头部块字节 `MaxHeaderBlockBytes` | 64 KiB | ENHANCE_YOUR_CALM |
| CONTINUATION 帧数 `MaxContinuationFrames` | 8 | ENHANCE_YOUR_CALM |
| 头部字段数 `MaxHeaderFields` | 100 | ENHANCE_YOUR_CALM |
| 单字段名/值 `MaxHeaderFieldSize` | 16 KiB | COMPRESSION_ERROR |
| 每块动态表插入 `MaxHPACKInsertsPerBlock` | 256 | ENHANCE_YOUR_CALM |
| 表大小更新次数 `MaxHPACKTableUpdates` | 4 | ENHANCE_YOUR_CALM |
| 连接累计插入 `MaxHPACKInsertsPerConn` | 10000 | ENHANCE_YOUR_CALM |
| 动态表大小 `HardMaxDynamicTableSize` | 4 KiB | 协商钳制 / COMPRESSION_ERROR |

无尽 CONTINUATION 还有一道**读截止时间** `HeaderTimeout`：HEADERS 未以
END_HEADERS 结束时，读循环给 socket 设截止时间，对端一个字节都不发也会在
超时后被 `GOAWAY(ENHANCE_YOUR_CALM)` 切断——因为 CONTINUATION 序列会阻塞
同连接所有其他流，这是该攻击能造成单点卡死的根源。

## 错误码映射（RFC 9113 §7）

| 情形 | 范围 | 错误码 |
| --- | --- | --- |
| 自适应并发上限 reached | 流 | `REFUSED_STREAM`（0x7，可重试） |
| 头部资源预算超限（编码合法但过量） | 连接 | `ENHANCE_YOUR_CALM`（0xb） |
| CONTINUATION 超时 / 帧数超限 | 连接 | `ENHANCE_YOUR_CALM` |
| 快速重置升级关闭 | 连接 | `ENHANCE_YOUR_CALM` |
| HPACK 状态损坏 / 非法编码 | 连接 | `COMPRESSION_ERROR`（0x9） |
| 流 ID 非法、伪头部顺序错、禁跳头部 | 流或连接 | `PROTOCOL_ERROR`（0x1） |
| 流上帧违反状态机 | 流 | `STREAM_CLOSED`（0x5） |
| 流量控制窗口溢出 / 超发 | 连接 | `FLOW_CONTROL_ERROR`（0x3） |
| 帧长不符规定 | 连接 | `FRAME_SIZE_ERROR`（0x6） |

关键区分：**资源耗尽 ≠ 协议损坏**。预算超限一律 `ENHANCE_YOUR_CALM`
（客户端没做错，只是要得太多）；只有 HPACK 状态机真正损坏才用
`COMPRESSION_ERROR`。流级错误发 RST_STREAM 后连接继续，只有连接级错误才
GOAWAY。

## 集成契约：MarkDispatched

代理处理器必须在**后端工作真正开始的那一刻**调用一次
`r.MarkDispatched()`（见 `example/main.go`）：

```go
resp, err := client.Do(req)   // 上游请求已发出
r.MarkDispatched()            // 此后 RST 不再计为 phantom
```

调用之前 RST = 幻影流（攻击信号），调用之后 RST = 普通取消（seek 信号）。
不调用则所有取消都按幻影记账，会让正常 seek 也触发降级——这是接入时唯一
需要严格遵守的约定。

## 测试

```sh
go test ./...            # 单元 + 真实 TCP loopback 帧级集成
go test -race ./...      # 竞态检测
go test -cover ./...     # 覆盖率
```

覆盖的关键场景：seek 突发不降级、纯幻影流两级升级、绝对预算绕过比率、
冷却恢复、稳态播放器流量、头部块炸弹、停滞 CONTINUATION 超时、HPACK 插入
预算（每块/每连接）、伪头部顺序、并发上限 REFUSED_STREAM、RST 解除阻塞写
协程、请求体 WINDOW_UPDATE 退款不卡死。
