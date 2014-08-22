/* Copyright (c) 2014 Rolf Timmermans */

/* Documentation of PE/COFF used for Windows executables can be found at:
   http://msdn.microsoft.com/en-us/windows/hardware/gg463119.aspx */

var peOffsetOffset = 0x3c
var peHeader = 0x50450000

var coffOptLengthOffset = 20
var coffOptOffset = 24
var coffMagic = 0x10b
var coffChecksumOffset = 64

var certOffsetOffset = 128
var certLengthOffset = 132

function checksum(buf) {
  var lim = Math.pow(2, 32)
  var checksum = 0

  function update(val) {
    checksum += val
    if (checksum >= lim) {
      checksum = (checksum % lim) + (checksum / lim | 0)
    }
  }

  for (var i = 0, n = buf.length; i < n; i += 4) {
    update(buf.readUInt32LE(i, true))
  }

  if (buf.length % 4 > 0) {
    var end = new Buffer(4).fill(0)
    buf.copy(end, 0, i - 4)
    update(end.readUInt32LE(i, true))
  }

  checksum = (checksum >>> 16) + (checksum & 0xffff)
  checksum = (checksum >>> 16) + checksum
  return (checksum & 0xffff) + buf.length
}

function append(exe, data) {
  if (!Buffer.isBuffer(data)) data = new Buffer(data)

  var peOffset = exe.readUInt8(peOffsetOffset)

  if (exe.readUInt32BE(peOffset) != peHeader) {
    throw new Error("No valid PE header found")
  }

  if (exe.readUInt16LE(peOffset + coffOptLengthOffset) == 0) {
    throw new Error("No optional COFF header found")
  }

  if (exe.readUInt16LE(peOffset + coffOptOffset) != coffMagic) {
    throw new Error("PE format is not PE32")
  }

  var certOffset = exe.readUInt32LE(peOffset + coffOptOffset + certOffsetOffset)
  if (certOffset > 0) {
    /* Certificate found, change certificate lengths. */
    var certLength = exe.readUInt32LE(peOffset + coffOptOffset + certLengthOffset)
    if (exe.readUInt32LE(certOffset) != certLength) {
      throw new Error("Certificate length does not match COFF header")
    }

    var newLength = certLength + data.length
    exe.writeUInt32LE(newLength, peOffset + coffOptOffset + certLengthOffset)
    exe.writeUInt32LE(newLength, certOffset)
  }

  /* Calculate and update checksum of end result. */
  var buf = Buffer.concat([exe, data])
  var offset = peOffset + coffOptOffset + coffChecksumOffset
  buf.writeUInt32LE(0, offset)
  buf.writeUInt32LE(checksum(buf), offset)

  return buf
}

module.exports = {
  append: append
}
