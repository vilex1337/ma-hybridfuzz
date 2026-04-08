Tiếng Anh: "MA-HybridFuzz: Multi-Agent Hybrid Directed Fuzzing with On-Demand LLM Guidance for Efficient PoV Generation"

Tiếng Việt: "MA-HybridFuzz: Fuzzing Hướng Đích Lai Đa Tác Tử với Hướng Dẫn LLM Theo Yêu Cầu cho Việc Tạo PoV Hiệu Quả"

- Ý tưởng cốt lõi của hướng đề tài này là kết hợp agentic multi-agent với hybrid classic DGF, tận dụng:

- Pre-generated reachable seeds + bug-specific mutators (từ RANDLUZZ).
- Dynamic confidence-based call graph + function islands (từ DynamicFuzz).
- Semantic attention distance metric (từ Attention Distance/IDFuzz).
- Strict on-demand LLM calls chỉ ở mức cao-level (pre-phase + khi stuck), main fuzzing loop chạy native không LLM cho từng input.
- Agentic reasoning + PBT cho PoV generation (kế thừa PBFuzz).

==> Hướng này định hướng giải quyết 4 research gaps lớn: semantic guidance sâu hơn, unreliable CG dynamic update, randomness seeds/mutators giảm triệt để, và hiệu năng runtime tối ưu (overhead <10%, token usage thấp).

- Problem Statement: “Làm thế nào để xây dựng một multi-agent hybrid framework cho directed fuzzing/PoV generation có khả năng: (1) dynamic update confidence-based call graph xử lý indirect calls, (2) dùng attention distance làm semantic metric, (3) tận dụng reachable seeds + bug-specific mutators do LLM sinh trước, (4) chỉ gọi LLM on-demand ở mức cao-level (không gọi cho từng input/execution/mutation trong fuzzing loop) để tối ưu token usage và giữ runtime fuzzing gần như native, đồng thời vẫn trigger nhiều unique vulnerabilities hơn trên benchmark thực tế?”

* Research gaps của các tài liệu đã tham khảo 2 đợt vừa qua:
Dựa trên so sánh 4 paper (Attention Distance, DynamicFuzz, RANDLUZZ, PBFuzz), có 4 research gaps cốt lõi cần khắc phục để đưa pp Directed Fuzzing nhằm PoV generation lên tầm hybrid thực sự khả thi và hiệu năng cao:

+Gap 1 – Semantic guidance thiếu chiều sâu: PBFuzz extract constraints bằng pure LLM reasoning nhưng chỉ dựa physical/static distance. Attention Distance đã chứng minh LLM attention scores có thể thay thế physical distance → 3.43× efficiency trên 38 real CVEs mà không thay đổi bất kỳ thành phần fuzzing nào.

+Gap 2 – Unreliable call graph chưa dynamic update: PBFuzz dùng static CFG nên dễ bị omission/misjudgment của indirect calls. DynamicFuzz giới thiệu confidence score + function islands + 4 guiding strategies (Target Function Selection, Island Prioritization, High-Confidence Path, Deep Indirect Call) → đạt 5.64× faster target reach và 69.8× faster crash detection.

+Gap 3 – Randomness trong seeds & mutators chưa loại bỏ triệt để: PBFuzz bắt đầu từ zero → lãng phí search space. RANDLUZZ dùng LLM (FCC-based) generate reachable seeds + bug-specific mutators → 2.1–4.8× speedup và expose 8 bugs chỉ trong 60s.

+Gap 4 – Hiệu năng runtime của agentic system chưa tối ưu: PBFuzz gọi LLM ở hầu hết các bước (có nguy cơ gọi cho từng input/execution/mutation) → latency cao, token waste, không scale được. Cần thiết kế strict on-demand LLM calls (chỉ gọi ở mức cao-level, tuyệt đối không gọi cho từng input trong fuzzing loop) để giữ main fuzzing loop chạy native tốc độ cao (hàng nghìn exec/s) mà vẫn duy trì intelligence PoV.

Link phân tích mục tiêu định hướng đồ án chuyên ngành/KLTN: https://1drv.ms/w/c/392e862c42a5d9d1/IQAA1ZfGbx41QIRVTZRLmW-xAfyhgXGYL6zGIvKN8DD47Tg?e=KekeiD