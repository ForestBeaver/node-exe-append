const assert = require("chai").assert;
const fs = require("fs");

const exe = require("../lib/exe-append");

describe("append", function () {
  describe("with non buffer", function () {
    it("should throw error if buffer is too short", function () {
      assert.throws(function () {
        exe.append("foo", "bar");
      }, "Executable should be a buffer");
    });
  });

  describe("to bad executable", function () {
    it("should throw error if buffer is too short", function () {
      const binary = Buffer.alloc(10);
      assert.throws(function () {
        exe.append(binary, "bar");
      });
    });

    it("should throw error if no pe header was found", function () {
      const binary = Buffer.alloc(256);
      assert.throws(function () {
        exe.append(binary, "bar");
      }, "No valid PE header found");
    });

    it("should throw error if no coff header was found", function () {
      const binary = fs.readFileSync(
        __dirname + "/fixtures/unsigned-badcoff.exe"
      );
      assert.throws(function () {
        exe.append(binary, "bar");
      }, "No optional COFF header found");
    });

    it("should throw error if format is not pe32", function () {
      const binary = fs.readFileSync(
        __dirname + "/fixtures/unsigned-badmagic.exe"
      );
      assert.throws(function () {
        exe.append(binary, "bar");
      }, "PE format is not PE32");
    });

    it("should throw error if no signature lengths do not match", function () {
      const binary = fs.readFileSync(
        __dirname + "/fixtures/signed-badlength.exe"
      );
      assert.throws(function () {
        exe.append(binary, "bar");
      }, "Certificate length does not match COFF header");
    });
  });

  describe("to unsigned executable", function () {
    const binary = fs.readFileSync(__dirname + "/fixtures/unsigned.exe");
    const appended = exe.append(binary, "foo");

    it("should grow buffer", function () {
      assert.equal(appended.length, binary.length + 3);
    });

    it("should append data", function () {
      assert.equal(appended.slice(binary.length), "foo");
    });

    it("should update checksum", function () {
      assert.equal(appended.readUInt32LE(312), 0x00007803);
    });
  });

  describe("to signed executable", function () {
    const binary = fs.readFileSync(__dirname + "/fixtures/signed.exe");
    const appended = exe.append(binary, "foo");

    it("should grow buffer", function () {
      assert.equal(appended.length, binary.length + 3);
    });

    it("should append data", function () {
      assert.equal(appended.slice(binary.length), "foo");
    });

    it("should update checksum", function () {
      assert.equal(appended.readUInt32LE(312), 0x00007d2b);
    });
  });
});
