Tiếng Việt: "MA-HybridFuzz: Fuzzing Hướng Đích Lai Đa Tác Tử với Hướng Dẫn LLM Theo Yêu Cầu cho Việc Tạo PoV Hiệu Quả"


1. Research gaps của các tài liệu đã tham khảo 2 đợt vừa qua: Dựa trên so sánh 4 paper (Attention Distance, DynamicFuzz, RANDLUZZ, PBFuzz), có 4 research gaps cốt lõi cần khắc phục để đưa pp Directed Fuzzing nhằm PoV generation lên tầm hybrid thực sự khả thi và hiệu năng cao:

+Gap 1 – Semantic guidance thiếu chiều sâu: PBFuzz extract constraints bằng pure LLM reasoning nhưng chỉ dựa physical/static distance. Attention Distance đã chứng minh LLM attention scores có thể thay thế physical distance → 3.43× efficiency trên 38 real CVEs mà không thay đổi bất kỳ thành phần fuzzing nào.


+Gap 3 – Randomness trong seeds & mutators chưa loại bỏ triệt để: PBFuzz bắt đầu từ zero → lãng phí search space. RANDLUZZ dùng LLM (FCC-based) generate reachable seeds + bug-specific mutators → 2.1–4.8× speedup và expose 8 bugs chỉ trong 60s.



2. Problem Statement: “Làm thế nào để xây dựng một multi-agent hybrid framework cho directed fuzzing/PoV generation có khả năng: (1) dynamic update confidence-based call graph xử lý indirect calls, (2) dùng attention distance làm semantic metric, (3) tận dụng reachable seeds + bug-specific mutators do LLM sinh trước, (4) chỉ gọi LLM on-demand ở mức cao-level

(không gọi cho từng input/execution/mutation trong fuzzing loop) để tối ưu token usage và giữ runtime fuzzing gần như native, đồng thời vẫn trigger nhiều unique vulnerabilities hơn trên benchmark thực tế?”

3. Ý tưởng giải quyết & hướng nghiên cứu tiếp theo: MA-HybridFuzz (Multi-Agent Hybrid Fuzzing)

Đề xuất MA-HybridFuzz – framework multi-agent kế thừa core agentic 4-phase của PBFuzz nhưng được thiết kế strict on-demand LLM theo đúng lưu ý: main fuzzing loop chạy hoàn toàn native (không LLM cho bất kỳ/mọi input nào), chỉ kích hoạt LLM khi thực sự cần (pre-phase + khi stuck). Điều này đảm bảo tốc độ fuzzing giữ nguyên như classic DGF (AFLGo/DAFL) trong khi vẫn giữ intelligence agentic.

Multi-Agent Architecture (3 agents phối hợp)

- Reasoning Agent (LLM chính): chỉ activate on-demand để hypothesize PoV plan.

- Semantic Agent (lightweight LLM on-demand): tính attention distance.

- Mutation Agent (classic): execute input mutations với pre-mutators.

Workflow chi tiết (tối ưu runtime – LLM chỉ 3–4 calls/target)

Phase 0 (Pre-phase, 1 LLM call): RANDLUZZ-style sinh reachable seeds + bug-specific mutators (không gọi lại nữa).

Main Fuzzing Loop (0 LLM call – chạy native): Hybrid DGF với attention distance + confidence-based CG + pre-mutators. Loop này chạy full speed (hàng nghìn exec/s) như AFLGo, không hề gọi LLM cho bất kỳ input nào.

On-demand Activation (2–3 LLM calls): Chỉ kích hoạt khi no progress (ví dụ: coverage tăng <10% sau 5 phút hoặc stuck ở island). Lúc này:

Reasoning Agent + Semantic Agent validate hypothesis.

PBT Agent search PoV.

Persistent Memory: Lưu attention map + confidence history + executed paths → tránh drift mà không cần gọi LLM thường xuyên.

Mô tả hướng thực hiện khả thi

Công nghệ/Phương pháp tham khảo sẵn có: RANDLUZZ (query scheme), Attention Distance (lightweight model), PBFuzz (cursor-cli prototype) + LangGraph/AutoGen cho multi-agent orchestration.

Implementation:

- Python wrapper; main loop dùng AFLGo instrumentation (native); LLM fallback chỉ qua API khi stuck (Claude-3.5/GPT-4o-mini/....).

- So sánh với trường hợp PBFuzz (toàn bộ các bước trong Agent dùng LLM cho mục tiêu sinh ra tất cả input)

Thời gian: 2 tháng prototype + 1 tháng experiment.

Chi phí: ~$0.5–0.8/vuln (chỉ 3–4 LLM calls).

Đánh giá: Magma + FTS + 10 real binaries; metrics: #CVEs triggered, median TTE, token usage, runtime overhead (<10%), #ineffective mutations. Dự kiến: 3–4× speedup so PBFuzz gốc, trigger ≥20 unique CVEs mới, overhead runtime gần như zero.