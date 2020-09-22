function writeU_Int16LE(buf, value, offset, min, max) {
  value = +value;

  buf[offset++] = value;
  buf[offset++] = (value >>> 8);
  return offset;
}

function writeU_Int32LE(buf, value, offset, min, max) {
  value = +value;

  buf[offset++] = value;
  value = value >>> 8;
  buf[offset++] = value;
  value = value >>> 8;
  buf[offset++] = value;
  value = value >>> 8;
  buf[offset++] = value;
  return offset;
}

function writeBigU_Int64LE(buf, value, offset, min, max) {
  let lo = Number(value & 0xffffffffn);
  buf[offset++] = lo;
  lo = lo >> 8;
  buf[offset++] = lo;
  lo = lo >> 8;
  buf[offset++] = lo;
  lo = lo >> 8;
  buf[offset++] = lo;
  let hi = Number(value >> 32n & 0xffffffffn);
  buf[offset++] = hi;
  hi = hi >> 8;
  buf[offset++] = hi;
  hi = hi >> 8;
  buf[offset++] = hi;
  hi = hi >> 8;
  buf[offset++] = hi;
  return offset;
}

const utf8encoder = new TextEncoder(), utf8decoder = new TextDecoder('utf-8')
export const stringToUtf8 = (string) => utf8encoder.encode(string)
export const utf8ToString = (buffer) => utf8decoder.decode(buffer)


export class Encoder {
  constructor() {
    this.buf = new Uint8Array(16)
    this.offset = 0
  }

  /**
   * Returns the byte array containing the encoded data.
   */
  get buffer() {
    return this.buf.subarray(0, this.offset)
  }

  /**
   * Reallocates the encoder's buffer to be bigger.
   */
  grow(minSize = 0) {
    let newSize = this.buf.byteLength * 4
    while (newSize < minSize) newSize *= 2
    const newBuf = new Uint8Array(newSize)
    newBuf.set(this.buf, 0)
    this.buf = newBuf
    return this
  }

  reserve(extra) {
    const newMinSize = this.offset + extra
    if (newMinSize > this.buf.byteLength) this.grow(newMinSize)
  }

  /**
   * Appends one byte (0 to 255) to the buffer.
   */
  writeByte(value) {
    this.reserve(1)
    this.buf[this.offset] = value
    this.offset += 1
  }

  writeUInt16LE(value) {
    this.reserve(2)
    writeU_Int16LE(this.buf, value, this.offset, 0, 0xffff);
    this.offset += 2
  }

  writeInt32LE(value) {
    this.reserve(4)
    writeU_Int32LE(this.buf, value, this.offset, -0x80000000, 0x7fffffff)
    this.offset += 4
  }
  writeUInt32LE(value) {
    this.reserve(4)
    writeU_Int32LE(this.buf, value, this.offset, 0, 0xffffffff);
    this.offset += 4
  }

  writeBigUInt64LE(value) {
    this.reserve(8)
    writeBigU_Int64LE(this.buf, value, this.offset, 0n, 0xffffffffffffffffn);
    this.offset += 8
  }

  writeUtf8(str) {
    this.append(stringToUtf8(str))
  }

  append(buf) {
    this.reserve(buf.byteLength)
    this.buf.set(buf, this.offset)
    this.offset += buf.byteLength
  }
}

