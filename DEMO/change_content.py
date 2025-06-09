from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO
import os

input_pdf = input("Nhập đường dẫn file PDF gốc: ").strip()
base = os.path.basename(input_pdf)
output_pdf = f"change_content_{base}"
text = input("Nhập nội dung muốn thêm vào trang mới: ").strip()

# Tạo một trang PDF mới với nội dung text
packet = BytesIO()
c = canvas.Canvas(packet, pagesize=letter)
c.drawString(100, 500, text)
c.save()
packet.seek(0)

# Đọc trang mới vừa tạo
new_page_reader = PdfReader(packet)
new_page = new_page_reader.pages[0]

# Đọc file PDF gốc
reader = PdfReader(input_pdf)
writer = PdfWriter()

# Thêm tất cả các trang cũ
for page in reader.pages:
    writer.add_page(page)

# Thêm trang mới vào cuối
writer.add_page(new_page)

# Giữ nguyên metadata cũ (nếu muốn)
writer.add_metadata(dict(reader.metadata))

with open(output_pdf, "wb") as f_out:
    writer.write(f_out)

print(f"Đã thêm trang mới vào PDF!\nFile mới: {os.path.abspath(output_pdf)}")