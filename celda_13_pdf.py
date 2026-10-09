# ==============================================================================
# AI-CLAIM — Celda 13/22
# EXPORT PDF: weasyprint/pdfkit/chromium/fallback nativo
# ==============================================================================
import shutil, subprocess, os, time

PDF_ENGINE = None
try:
    from weasyprint import HTML as WeasyHTML
    PDF_ENGINE = "weasyprint"
except ImportError: pass

if PDF_ENGINE is None:
    try:
        import pdfkit
        if shutil.which("wkhtmltopdf"): PDF_ENGINE = "pdfkit"
    except ImportError: pass

if PDF_ENGINE is None and shutil.which("chromium"): PDF_ENGINE = "chromium"
if PDF_ENGINE is None and shutil.which("google-chrome"): PDF_ENGINE = "chrome"


def _convert_weasyprint(html_path, pdf_path):
    WeasyHTML(filename=html_path).write_pdf(pdf_path)
    return pdf_path


def _convert_pdfkit(html_path, pdf_path):
    import pdfkit
    pdfkit.from_file(html_path, pdf_path, options={
        "enable-local-file-access": None, "page-size": "A4", "print-media-type": None})
    return pdf_path


def _convert_chromium(binary, html_path, pdf_path):
    subprocess.run([binary, "--headless", "--disable-gpu", "--no-sandbox",
         "--print-to-pdf=" + pdf_path, "file://" + os.path.abspath(html_path)],
        check=True, capture_output=True)
    return pdf_path


def _extract_text(html_path):
    import re
    with open(html_path, "r", encoding="utf-8") as f: html = f.read()
    html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL)
    html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL)
    html = re.sub(r"<br\s*/?>", "\n", html)
    html = re.sub(r"</(p|div|h1|h2|h3|li|tr|header)>", "\n", html)
    html = re.sub(r"<li>", "  * ", html)
    html = re.sub(r"<[^>]+>", "", html)
    html = (html.replace("&nbsp;", " ").replace("&amp;", "&")
                .replace("&lt;", "<").replace("&gt;", ">"))
    lines = [ln.strip() for ln in html.splitlines()]
    return "\n".join(ln for ln in lines if ln)


def _simple_pdf(text, pdf_path):
    def esc(s):
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    lost = 0
    safe_lines = []
    for raw in text.splitlines():
        try: raw.encode("latin-1")
        except UnicodeEncodeError:
            before = len(raw)
            raw = raw.encode("latin-1", errors="replace").decode("latin-1")
            lost += before
        while len(raw) > 90:
            safe_lines.append(raw[:90]); raw = raw[90:]
        safe_lines.append(raw)
    per_page = 55
    pages = [safe_lines[i:i + per_page] for i in range(0, len(safe_lines), per_page)] or [[""]]
    n = len(pages); first = 4
    page_ids = [first + 2 * i for i in range(n)]
    content_ids = [first + 2 * i + 1 for i in range(n)]
    catalog = b"<< /Type /Catalog /Pages 2 0 R >>"
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    pages_obj = f"<< /Type /Pages /Kids [{kids}] /Count {n} >>".encode()
    font_obj = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
    page_objs, content_objs = [], []
    for pi, page_lines in enumerate(pages):
        pid, cid = page_ids[pi], content_ids[pi]
        page_objs.append((f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                           f"/Resources << /Font << /F1 3 0 R >> >> /Contents {cid} 0 R >>").encode())
        stream = ["BT", "/F1 10 Tf", "12 TL", "40 800 Td"]
        for ln in page_lines: stream.append(f"({esc(ln)}) Tj T*")
        stream.append("ET")
        sb = "\n".join(stream).encode("latin-1", errors="replace")
        content_objs.append(f"<< /Length {len(sb)} >>\nstream\n".encode() + sb + b"\nendstream")
    parts = [(1, catalog), (2, pages_obj), (3, font_obj)]
    for i in range(n):
        parts.append((page_ids[i], page_objs[i]))
        parts.append((content_ids[i], content_objs[i]))
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for oid, data in parts:
        offsets[oid] = len(out)
        out += f"{oid} 0 obj\n".encode() + data + b"\nendobj\n"
    xref = len(out); maxid = max(offsets.keys())
    out += f"xref\n0 {maxid + 1}\n".encode() + b"0000000000 65535 f \n"
    for i in range(1, maxid + 1):
        out += f"{offsets.get(i, 0):010d} 00000 n \n".encode()
    out += b"trailer\n" + f"<< /Size {maxid + 1} /Root 1 0 R >>\n".encode()
    out += b"startxref\n" + f"{xref}\n".encode() + b"%%EOF\n"
    with open(pdf_path, "wb") as f: f.write(out)
    return pdf_path, lost


def html_to_pdf(html_path, pdf_path):
    if PDF_ENGINE == "weasyprint": return _convert_weasyprint(html_path, pdf_path), 0
    if PDF_ENGINE == "pdfkit": return _convert_pdfkit(html_path, pdf_path), 0
    if PDF_ENGINE == "chromium": return _convert_chromium(shutil.which("chromium"), html_path, pdf_path), 0
    if PDF_ENGINE == "chrome": return _convert_chromium(shutil.which("google-chrome"), html_path, pdf_path), 0
    print("  Sin motor real disponible — usando fallback nativo.")
    return _simple_pdf(_extract_text(html_path), pdf_path)


def _run(html_path="ai_claim_real_report.html", pdf_path="ai_claim_real_report.pdf"):
    print("=" * 78)
    print("  EXPORT HTML -> PDF")
    print("=" * 78)
    print(f"\n  Motor: {PDF_ENGINE or 'ninguno (fallback nativo)'}")
    if not os.path.exists(html_path):
        print(f"[ERROR] No existe {html_path} — ejecutar celda 12 primero")
        return None
    t0 = time.perf_counter()
    result, lost_chars = html_to_pdf(html_path, pdf_path)
    dt = (time.perf_counter() - t0) * 1000
    if result and os.path.exists(pdf_path):
        size_pdf = os.path.getsize(pdf_path)
        print(f"\n  [OK] PDF generado en {dt:.0f} ms — {pdf_path} ({size_pdf:,} bytes)")
        if lost_chars:
            print(f"  {lost_chars} líneas con caracteres fuera de Latin-1 reemplazados")
    print("\n" + "=" * 78)
    return result


_run()
