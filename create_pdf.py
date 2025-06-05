from reportlab.pdfgen import canvas
import sys

def create_pdf(path):
    c = canvas.Canvas(path)
    c.drawString(100, 750, "This is a signed government document.")
    c.save()
    print(f"PDF created: {path}")

if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "unsigned.pdf"
    create_pdf(output)
