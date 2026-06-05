# Phương pháp benchmark:
## Các metric cần đo:
Nhóm metric về chuẩn bị
- Thời gian chuẩn bị (overhead)
Nhóm metric về tính năng:
- Time-to-reach/1 đơn vị thời gian 
- Time-to-exposure/1 đơn vị thời gian 
- Số lượng crash
Nhóm metric về chi phí:
- Input token
- Output token
- Số lần gọi request cho mỗi agent

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