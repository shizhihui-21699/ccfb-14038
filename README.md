# h2guard — 带防护的 HTTP/2 帧处理层

为 Go 反向代理重写的 HTTP/2 连接层，内置对已知 HTTP/2 滥用手法的缓解，
全程按 RFC 7540/7541 返回正确的错误码，且不误伤正常观众。

## 威胁模型与对策

| 攻击 | 机制 | 协议行为 |
|---|---|---|
| 快速重置 (CVE-2023-44487) | 收到 `END_HEADERS` 前流只是几个字节：不起协程、不发后端请求；"早重置"令牌桶耗尽后逐级下调 `SETTINGS_MAX_CONCURRENT_STREAMS`，最后一级耗尽后 GOAWAY + 宽限期关闭 | 降级期拒流用 `REFUSED_STREAM`（可安全重试）；关连用 `GOAWAY(ENHANCE_YOUR_CALM)` |
| 续传帧洪泛 (CVE-2024-27316) | 单个头部块压缩字节上限 + CONTINUATION 帧数上限 + 组装超时三重硬顶；协议上续传帧必须连续，所以全连接最多只有一个组装缓冲 | `GOAWAY(PROTOCOL_ERROR)` |
| HPACK 炸弹 / 动态表搅动 | 广告并强制小动态表（默认 4096）；解码后头部列表按 `name+value+32` 累计设硬顶；压缩头部字节速率限速，堵住"每块都不超限但不停插表"的搅动 | 列表超限：该流回 431，连接不断；表大小更新越界/解码失败：`GOAWAY(COMPRESSION_ERROR)`；字节速率超限：`GOAWAY(ENHANCE_YOUR_CALM)` |
| 超大帧 | 24-bit 长度在分配任何缓冲之前校验 | `GOAWAY(FRAME_SIZE_ERROR)` |

## 为什么不会误伤正常观众

关键区分是**早重置**和**晚重置**：

- 攻击者：开流 → 立刻取消，响应一个字节都没发出去 → **早重置**，扣预算。
- 拖进度条的观众：播放器已经收到一些数据才取消 → **晚重置**，只计数、不惩罚。
  这正是视频站正常流量的形状。

预算是一个令牌桶（默认容量 64、每秒回 4、每正常完成一个流 +1）：
人类操作每秒几次，攻击每秒几千次，即使很宽松的桶也能干净地把两者分开。
降级是**可逆的**：连接保持干净 30 秒（`RecoverAfter`）就回升一级。
被拒的流用 `REFUSED_STREAM`，浏览器会自动重试，观众无感知。

## 错误码速查（RFC 7540 §7）

| 场景 | 码 |
|---|---|
| 快速重置/头部速率触发限流 | GOAWAY `ENHANCE_YOUR_CALM` (0xb) |
| 续传帧违规、伪头部非法、帧序错误 | GOAWAY `PROTOCOL_ERROR` (0x1) |
| HPACK 解码失败、表大小更新越界 | GOAWAY `COMPRESSION_ERROR` (0x9) |
| 帧超过 SETTINGS_MAX_FRAME_SIZE、定长帧长度错 | GOAWAY `FRAME_SIZE_ERROR` (0x6) |
| 并发降级期的新流 | RST_STREAM `REFUSED_STREAM` (0x7)，客户端可重试 |
| 解码头部列表超限 | 该流回 431（类 HTTP/1.1 行为），连接保留 |
| 空闲超时 | GOAWAY `NO_ERROR` (0x0) 后关闭 |

## 用法

```go
ln, _ := net.Listen("tcp", ":8443")
for {
    nc, _ := ln.Accept() // 生产环境先包 TLS
    go h2guard.NewConn(nc, h2guard.Config{
        MaxConcurrentStreams: 100,
        DegradeLevels:        []uint32{32, 8, 1},
    }, func(s *h2guard.Stream) {
        // 在这里做反向代理：s.Headers 是完整请求头，
        // s.Context() 在对端 RST / 连接关闭时取消。
        s.WriteResponse(200, []byte("ok"))
    }).Serve()
}
```

调参入口都在 `Config`：降级阶梯、令牌桶、各类头部上限、超时。
`Conn.DegradeLevel()` 可接指标监控。

## 已知边界（留给代理层/后续）

- 响应方向的 flow control 与后端背压（当前 `WriteData` 不等待对端窗口）。
- 慢速请求体（slowloris）需要流级读超时，本层只有连接级超时。
- PING/SETTINGS 洪泛：可在 `dispatch` 处加按帧类型的速率计数。
- 请求体目前只回 WINDOW_UPDATE 透传窗口，代理层需接管 DATA 转发。
