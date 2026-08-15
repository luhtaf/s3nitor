#!/usr/bin/env python3
"""Pembaca wire-format protobuf tanpa file .proto.

Dipakai buat ngeliat bentuk notifikasi SeaweedFS (filer_pb.EventNotification)
di Fase 0. Wire format protobuf itu self-delimiting per field, jadi struktur
(nomor field, tipe, nilai) bisa dibaca tanpa skema — yang nggak bisa cuma
NAMA field-nya.

Ini juga alasan kenapa protobuf nggak bisa di-sniff buat auto-deteksi format:
byte acak sering ke-parse jadi protobuf "valid" dengan unknown field.

Pakai:  ./protoscan.py <file-base64-per-baris>
"""
import base64
import sys

WIRE = {0: "varint", 1: "i64", 2: "bytes", 3: "start", 4: "end", 5: "i32"}


def read_varint(buf, i):
    val = shift = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7
        if shift > 63:
            raise ValueError("varint kepanjangan")
    raise ValueError("varint terpotong")


def looks_like_text(b):
    if not b:
        return False
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(c == "\n" or c == "\t" or 0x20 <= ord(c) < 0x7F for c in s)


def walk(buf, depth=0, out=None):
    """Telusuri pesan; balikin daftar baris terformat."""
    out = out if out is not None else []
    pad = "  " * depth
    i = 0
    while i < len(buf):
        try:
            tag, i = read_varint(buf, i)
        except ValueError:
            out.append(f"{pad}<sisa {len(buf)-i} byte nggak keparse>")
            return out
        field, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = read_varint(buf, i)
            out.append(f"{pad}#{field} varint = {v}")
        elif wt == 1:
            out.append(f"{pad}#{field} i64 = 0x{buf[i:i+8].hex()}")
            i += 8
        elif wt == 5:
            out.append(f"{pad}#{field} i32 = 0x{buf[i:i+4].hex()}")
            i += 4
        elif wt == 2:
            try:
                ln, i = read_varint(buf, i)
            except ValueError:
                out.append(f"{pad}<sisa {len(buf)-i} byte nggak keparse>")
                return out
            if ln > len(buf) - i:      # panjang nggak masuk akal → bukan pesan bersarang
                out.append(f"{pad}<panjang {ln} melebihi sisa buffer>")
                return out
            chunk = buf[i:i + ln]
            i += ln
            if looks_like_text(chunk):
                out.append(f'{pad}#{field} string = "{chunk.decode()}"')
            else:
                # Coba tafsirkan sebagai pesan bersarang; kalau gagal, tampilkan hex.
                try:
                    nested = walk(chunk, depth + 1)
                    if nested and not any("nggak keparse" in n for n in nested):
                        out.append(f"{pad}#{field} message ({ln} byte)")
                        out.extend(nested)
                        continue
                except Exception:
                    pass
                out.append(f"{pad}#{field} bytes[{ln}] = {chunk[:24].hex()}"
                           + ("…" if ln > 24 else ""))
        else:
            out.append(f"{pad}#{field} wire={WIRE.get(wt, wt)} (dilewati)")
            return out
    return out


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(sys.argv[1]) as fh:
        lines = [l.strip() for l in fh if l.strip()]
    if not lines:
        sys.exit("nggak ada pesan di file")
    for n, line in enumerate(lines, 1):
        raw = base64.b64decode(line)
        # kafka-console-consumer.sh nempelin pemisah baris di belakang tiap
        # pesan. Buat payload teks itu nggak kelihatan, tapi buat protobuf byte
        # itu jadi sampah yang bikin parse gagal di akhir pesan.
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        print(f"--- pesan {n} ({len(raw)} byte) ---")
        try:
            for row in walk(raw):
                print(row)
        except Exception as exc:  # jangan matiin seluruh laporan gara-gara 1 pesan
            print(f"  <gagal parse: {exc}>")
            print(f"  hex: {raw[:64].hex()}" + ("…" if len(raw) > 64 else ""))
        print()


if __name__ == "__main__":
    main()
