from PyPDF2 import PdfReader

reader = PdfReader("signed_Lab_5-Nginx-5.pdf")
metadata = reader.metadata
print("Metadata keys and values:")
for k, v in metadata.items():
    print(f"{k}: {v}")
