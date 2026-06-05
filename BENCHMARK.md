# Phương pháp benchmark:
## Các metric cần đo:
*Preparation Overhead:*
- Static analysis + CG construction time
- Pre-phase LLM seed/mutator generation time
- Total preparation time

*Effectiveness:*
- Time-to-Reach (TTR): time to reach target location
- Time-to-Exposure (TTE): time to trigger vulnerability/PoV
- #Unique PoVs / Crashes triggered
- Target edge coverage & island coverage

*Efficiency & Cost:*
- Executions per second (exec/s) & overhead (%)
- Ineffective mutation rate
- Token usage (input/output) & #LLM requests
- Median/Mean TTR & TTE với standard deviation

*Benchmark Setting:*
- Magma (full hoặc subset 20-30 CVEs đại diện)
- 12h × 4 runs (hoặc 6h × 5 runs) với note resource limit)
- Baselines: AFLGo, DynamicFuzz (re-impl), Attention-AFLGo, IDFuzz, PBFuzz

## Benchmark - Magma
Benchmark Magma được chọn làm benchmark để đo vì: 
- Tính đa dạng của các input: PNG, TIFF, XML, PDF, SQL queries, binary blobs, and PHP-related. Kiểm tra fuzzer có khả năng tạo seed và mutate tốt hay không
- Có đa dạng các logic phức tạp, có thể phân tích được fuzzer hoạt động tốt đối với logic nào: nested formats, checksums, compression, global state, magic values, and input transformations
- Bug class đa dạng, trải đều các loại CWE khác nhau 
- Có cơ chế để kiểm tra độ đo TTR và TTE
## Phương pháp
Vì Hosting LLM inference trên kaggle giới hạn 30 tiếng, để tiết kiệm chi phí, nhóm chúng em fuzz 6 tiếng cho mỗi target, mỗi target fuzz 2 lần.
### Các thí nghiệm:
1. Đo overhead cho 7 target của Magma
2. Thực hiện fuzz 6 tiếng cho mỗi target của Magma, mỗi target fuzz 2 lần, đo các metric về tính năng và chi phí
3. Ablation study: lần lượt cắt bỏ các thành phần: 
  - Prephase seed
  - Prephase mutator
  - Attention distance agent
  - Reassessment
Với thời gian đo và phương pháp đo tương tự: thực hiện fuzz 6 tiếng cho mỗi target của Magma, mỗi target fuzz 2 lần, đo các metric về tính năng và chi phí