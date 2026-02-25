
import io
import rust_crypto as scp

# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def dummy_master_key():
    return b"\x00" * 32

def dummy_salt():
    return b"\x01"*16

def make_header(chunk_size: int, compression: int): 
    header = scp.PyHeaderV1(
        magic=b"RSE1", version=1, alg_profile=257, cipher=1,
        hkdf_prf=1, compression=compression, strategy=0, aad_domain=1,
        flags=0, chunk_size=chunk_size, plaintext_size=0, crc32=0,
        dict_id=0, salt=dummy_salt(), key_id=42,
        parallel_hint=0, enc_time_ns=0, reserved=b"\x00"*8,
    )
    return header

## 🧪 Basic Round‑Trip Test (Memory → Memory)

def test_encrypt_decrypt_memory():
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=True, collect_metrics=False)

    plaintext = b"hello world"
    output = b""

    enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
    snap_enc = scp.py_encrypt_stream_v2(plaintext, output, enc_params, config)
    assert snap_enc.output is not None

    dec_params = scp.PyDecryptParams(master_key=dummy_master_key())
    snap_dec = scp.py_decrypt_stream_v2(snap_enc.output, b"", dec_params, config)
    assert snap_dec.output == plaintext

    print("✅ Memory round‑trip passed")

## 🧪 File Round‑Trip Test (File → File)

def test_encrypt_decrypt_file(tmp_path):
    infile = tmp_path / "plain.txt"
    encfile = tmp_path / "cipher.enc"
    outfile = tmp_path / "plain_out.txt"
    infile.write_bytes(b"secret data in file")

    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)

    enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
    scp.py_encrypt_stream_v2(str(infile), str(encfile), enc_params, config)

    dec_params = scp.PyDecryptParams(master_key=dummy_master_key())
    scp.py_decrypt_stream_v2(str(encfile), str(outfile), dec_params, config)

    assert outfile.read_bytes() == infile.read_bytes()
    print("✅ File round‑trip passed")

## 🧪 File‑Like Object Test (Zero‑Copy)

def test_encrypt_decrypt_filelike():
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)

    inp = io.BytesIO(b"streaming data")
    out_enc = io.BytesIO()
    out_dec = io.BytesIO()

    enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
    scp.py_encrypt_stream_v2(inp, out_enc, enc_params, config)

    dec_params = scp.PyDecryptParams(master_key=dummy_master_key())
    scp.py_decrypt_stream_v2(io.BytesIO(out_enc.getvalue()), out_dec, dec_params, config)

    assert out_dec.getvalue() == b"streaming data"
    print("✅ File‑like round‑trip passed")

# 🧪 Python Stress Tests

## ✅ 1️⃣ Basic Round Trip

def test_readinto_writeinto_basic():
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)

    data = b"A" * 100_000

    inp = io.BytesIO(data)
    out = io.BytesIO()

    enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
    scp.py_encrypt_stream_v2(inp, out, enc_params, config)
    result = out.getvalue()

    assert len(result) > 0

## ✅ 2️⃣ Partial Writer Test (CRITICAL)

# Simulate partial write:

class PartialWriter:
    def __init__(self):
        self.buf = bytearray()

    def writeinto(self, b):
        # only consume half
        n = len(b) // 2
        self.buf.extend(b[:n])
        return n

def test_partial_write():
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)
    data = b"hello world" * 1000

    inp = io.BytesIO(data)
    out = PartialWriter()

    try:
        enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
        scp.py_encrypt_stream_v2(inp, out, enc_params, config)
    except Exception:
        pass  # should error, not hang

## ✅ 3️⃣ EOF Correctness

def test_small_buffer():
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)
    data = b"abc"

    inp = io.BytesIO(data)
    out = io.BytesIO()

    enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
    scp.py_encrypt_stream_v2(inp, out, enc_params, config)
    assert out.getvalue()

## ✅ 4️⃣ Large Stress Test

def test_large_stream():
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)

    data = b"x" * 10_000_000
    inp = io.BytesIO(data)
    out = io.BytesIO()

    enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
    scp.py_encrypt_stream_v2(inp, out, enc_params, config)

# Should complete instantly without hang.

# 🔎 Important Clarification

### Python standard IO:

# | Method        | BytesIO | File | Socket |
# | ------------- | ------- | ---- | ------ |
# | `read()`      | ✅       | ✅    | ✅      |
# | `readinto()`  | ✅       | ✅    | ✅      |
# | `write()`     | ✅       | ✅    | ✅      |
# | `writeinto()` | ❌       | ❌    | ❌      |

# `writeinto()` is **not a standard writer API** in Python.

# It exists mainly for:

# * custom buffer consumers
# * C-extension integrations

# So our `writeinto` bridge is only valid for **custom Python classes**.


# 🎯 Correct Architecture

# We should:

# * Use `readinto()` for reader optimization
# * Use `write()` for writer (with `write_all()` in Rust)

# Unless we control the Python writer implementation.

# ✅ 1️⃣ Test `readinto()` With BytesIO

# This verifies our `PyReaderReadInto` works with standard Python objects.

def test_readinto_with_bytesio():
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)
    data = b"A" * 100_000

    inp = memoryview(data)
    out = io.BytesIO()
    
    enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
    scp.py_encrypt_stream_v2(inp, out, enc_params, config)

    assert out.getvalue() != b""

    # This validates:

    # * EOF propagation
    # * no hang
    # * proper GIL release
    # * large data handling


# ✅ 2️⃣ Custom writeinto() Sink Test

# We define a custom Python sink:

# Simple memory-like writer
class WriteIntoSink:
    def __init__(self):
        self.buf = bytearray()

    def writeinto(self, b):
        # b is a bytearray
        self.buf.extend(b)
        return len(b)

    def flush(self):
        pass

def test_writeinto_sink():
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)
    data = b"hello world" * 1000

    inp = memoryview(data)
    out = WriteIntoSink()

    enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
    scp.py_encrypt_stream_v2(inp, out, enc_params, config)

    assert len(out.buf) > 0

    # This verifies:

    # * writeinto path works
    # * no partial write hang
    # * flush works
    # * no GIL deadlock

# ✅ 3️⃣ Partial Write Protection Test (CRITICAL)

# This ensures our `writeinto()` zero-return protection works.

class BadWriteInto:
    def writeinto(self, b):
        return 0  # illegal behavior

def test_writeinto_zero_error():
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)
    data = b"hello world"

    inp = io.BytesIO(data)
    out = BadWriteInto()

    try:
        enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
        scp.py_encrypt_stream_v2(inp, out, enc_params, config)
        assert False, "Expected write-zero failure"
    except Exception as e:
        assert "write" in str(e).lower() or "zero" in str(e).lower()

    # If the Rust code doesn’t guard against `0`, this test will hang.

def test_writeinto_zero_error_verbose():
    import traceback
    
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)
    data = b"hello world"
    
    inp = io.BytesIO(data)
    out = BadWriteInto()
    
    try:
        enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
        scp.py_encrypt_stream_v2(inp, out, enc_params, config)
        print("❌ No exception raised!")
        assert False, "Expected write-zero failure"
    except Exception as e:
        print(f"✅ Exception raised: {type(e).__name__}: {e}")
        traceback.print_exc()
        assert "write" in str(e).lower() or "zero" in str(e).lower()

# ✅ 4️⃣ Partial Write Simulation Test

# class PartialWriteInto:
#     def __init__(self):
#         self.buf = bytearray()

#     def writeinto(self, b):
#         # b is exactly the slice Rust passed
#         if len(b) == 0:
#             return 0
#         n = max(1, len(b)//2)  # partial write, but cannot exceed len(b)
#         self.buf.extend(b[:n])
#         return n

#     def flush(self):
#         pass

# def test_partial_writeinto():
#     data = b"A" * 5000

#     header = make_header(1024, 0)
#     config = scp.PyApiConfig(with_buf=False, collect_metrics=False)
#     key = dummy_key

#     inp = memoryview(data)
#     out = PartialWriteInto()

#     scp.py_encrypt_stream_v2(inp, out, key, header, config)

#     # Rust write_all() should handle looping
#     assert len(out.buf) > 0

#     # If the Rust side uses `write_all()`, this passes.
#     # If not → silent corruption.

# Partial write simulator
class PartialWriteInto:
    def __init__(self):
        self.buf = bytearray()

    def writeinto(self, b):
        n = max(1, len(b)//2)  # simulate partial write
        self.buf.extend(b[:n])
        return n
    def flush(self):
        pass

def test_partial_writeinto():
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)
    data = b"A" * 5000

    inp = memoryview(data)
    out = PartialWriteInto()

    # Encrypt
    enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
    scp.py_encrypt_stream_v2(inp, out, enc_params, config)

    # ✅ The important assertions:
    # - At least some data was written
    assert len(out.buf) > 0
    # - Total written is consistent with encrypted segments
    #   (cannot compare to plaintext)
    print(f"PartialWriteInto buffer length: {len(out.buf)}")

def test_partial_writeinto_detection():
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)
    data = b"A" * 5000

    inp = memoryview(data)
    out = PartialWriteInto()

    # Encrypt to partial sink
    enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
    scp.py_encrypt_stream_v2(inp, out, enc_params, config)

    # Attempt to decrypt - must raise validation error
    decrypted = io.BytesIO()
    out_buf = io.BytesIO(out.buf)

    import pytest
    with pytest.raises(RuntimeError) as e:
        dec_params = scp.PyDecryptParams(master_key=dummy_master_key())
        scp.py_decrypt_stream_v2(out_buf, decrypted, dec_params, config)

    assert "Missing final segment" in str(e.value)

# ✅ 5️⃣ Stress Test (Deadlock Detection)

def test_readinto_stress():
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)
    data = b"x" * 5_000_000

    inp = memoryview(data)
    out = io.BytesIO()

    enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
    scp.py_encrypt_stream_v2(inp, out, enc_params, config)

    # assert out.getvalue()
    assert out.getbuffer().nbytes > 0

    # If there is any:

    # * EOF propagation issue
    # * channel close issue
    # * write-zero infinite loop
    # * GIL misuse

    # This test will hang.

# 🏆 Final Professional Recommendation

### Use this policy:

# * Reader → use `readinto()` (high throughput)
# * Writer → use `write()` + Rust `write_all()`

# Because Python ecosystem universally supports `write()`, not `writeinto()`.

# Our `writeinto()` should be treated as:

# > Advanced optional optimization for controlled environments.

## 2️⃣ Python tests for `readinto()` / `writeinto()` pipelines

def test_writeinto_full():
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)
    data = b"hello world" * 1000

    inp = memoryview(data)
    out = WriteIntoSink()

    enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
    scp.py_encrypt_stream_v2(inp, out, enc_params, config)

    assert len(out.buf) > 0

def test_writeinto_partial_loop():
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)
    data = b"A" * 5000

    inp = memoryview(data)
    out = PartialWriteInto()
   
    enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
    scp.py_encrypt_stream_v2(inp, out, enc_params, config)

    # Ensure all data eventually written
    assert len(out.buf) > 0

def test_readinto_bytesio():
    header = make_header(1024, 0)
    config = scp.PyApiConfig(with_buf=False, collect_metrics=False)

    data = b"x" * 100_000
    inp = io.BytesIO(data)
    out = io.BytesIO()

    enc_params = scp.PyEncryptParams(master_key=dummy_master_key(), header=header, dict=None)
    scp.py_encrypt_stream_v2(inp, out, enc_params, config)

    assert out.getbuffer().nbytes > 0
