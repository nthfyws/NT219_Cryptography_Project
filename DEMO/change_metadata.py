from PyPDF2 import PdfReader, PdfWriter
import os
input_pdf = input("Nhập đường dẫn file PDF gốc: ").strip()
base = os.path.basename(input_pdf)
output_pdf = f"change_pubkey_{base}"
new_pubkey = input("Nhập public key mới (hoặc chuỗi bất kỳ): ").strip()

reader = PdfReader(input_pdf)
writer = PdfWriter()

# Copy tất cả các trang
for page in reader.pages:
    writer.add_page(page)

# Lấy metadata cũ và sửa public key
metadata = dict(reader.metadata)
metadata['/PublicKey'] = new_pubkey

# Ghi metadata mới vào file PDF mới
writer.add_metadata(metadata)

with open(output_pdf, "wb") as f_out:
    writer.write(f_out)

print(f"Đã thay đổi public key trong metadata của PDF!\nFile mới: {os.path.abspath(output_pdf)}")