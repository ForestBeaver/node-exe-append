/* Copyright (c) 2014 Rolf Timmermans */

/* Documentation of PE/COFF used for Windows executables can be found at:
   http://msdn.microsoft.com/en-us/windows/hardware/gg463119.aspx */

const peOffsetOffset = 0x3c;
const peHeader = 0x50450000;

const coffOptLengthOffset = 20;
const coffOptOffset = 24;
const coffMagic = 0x10b;
const coffChecksumOffset = 64;

const certOffsetOffset = 128;
const certLengthOffset = 132;

function checksum(buf) {
  const lim = Math.pow(2, 32);
  let checksum = 0;

  function update(val) {
    checksum += val;
    if (checksum >= lim) {
      checksum = (checksum % lim) + ((checksum / lim) | 0);
    }
  }

  let lastIndex = 0;
  for (let i = 0; i < buf.length; i += 4) {
    if (i < buf.length - 4) {
      update(buf.readUInt32LE(i));
    }

    lastIndex = i;
  }

  if (buf.length % 4 > 0) {
    const end = Buffer.alloc(4, 0);
    buf.copy(end, 0, lastIndex - 4);
    if (lastIndex < buf.length - 4) {
      update(end.readUInt32LE(lastIndex));
    } else {
      update();
    }
  }

  checksum = (checksum >>> 16) + (checksum & 0xffff);
  checksum = (checksum >>> 16) + checksum;
  return (checksum & 0xffff) + buf.length;
}

function append(exe, data) {
  if (!Buffer.isBuffer(exe)) throw new Error("Executable should be a buffer");
  if (!Buffer.isBuffer(data)) data = Buffer.from(data);

  const peOffset = exe.readUInt8(peOffsetOffset);

  if (exe.readUInt32BE(peOffset) !== peHeader) {
    throw new Error("No valid PE header found");
  }

  if (exe.readUInt16LE(peOffset + coffOptLengthOffset) === 0) {
    throw new Error("No optional COFF header found");
  }

  if (exe.readUInt16LE(peOffset + coffOptOffset) !== coffMagic) {
    throw new Error("PE format is not PE32");
  }

  const certOffset = exe.readUInt32LE(
    peOffset + coffOptOffset + certOffsetOffset
  );

  if (certOffset > 0) {
    /* Certificate found, change certificate lengths. */
    const certLength = exe.readUInt32LE(
      peOffset + coffOptOffset + certLengthOffset
    );
    if (exe.readUInt32LE(certOffset) !== certLength) {
      throw new Error("Certificate length does not match COFF header");
    }

    const newLength = certLength + data.length;
    exe.writeUInt32LE(newLength, peOffset + coffOptOffset + certLengthOffset);
    exe.writeUInt32LE(newLength, certOffset);
  }

  /* Calculate and update checksum of end result. */
  const buf = Buffer.concat([exe, data]);
  const offset = peOffset + coffOptOffset + coffChecksumOffset;
  buf.writeUInt32LE(0, offset);
  buf.writeUInt32LE(checksum(buf), offset);

  return buf;
}

module.exports = {
  append: append,
};
