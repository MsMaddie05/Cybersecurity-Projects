// ©AngelaMos | 2026
// session.zig

const std = @import("std");
const ck = @import("../ck.zig");
const config = @import("../config.zig");
const digest = @import("../crypto/digest.zig");
const mac = @import("../crypto/mac.zig");
const cipher = @import("../crypto/cipher.zig");
const ecdsa = @import("../crypto/ecdsa.zig");
const rsa = @import("../crypto/rsa.zig");

pub const Find = struct {
    matches: [config.max_objects]ck.CK_OBJECT_HANDLE = undefined,
    count: usize = 0,
    cursor: usize = 0,
    active: bool = false,
};

pub const RsaSig = struct {
    key: ck.CK_OBJECT_HANDLE,
    params: rsa.SignParams,
    sig_len: usize,
};

pub const RsaCrypt = struct {
    key: ck.CK_OBJECT_HANDLE,
    params: rsa.CryptParams,
    out_len: usize,
};

pub const SignOp = union(enum) {
    mac: mac.Mac,
    ec: ecdsa.SignState,
    rsa: RsaSig,

    pub fn update(self: *SignOp, data: []const u8) void {
        switch (self.*) {
            .mac => |*m| m.update(data),
            .ec => |*e| e.update(data),
            .rsa => {},
        }
    }

    pub fn zeroize(self: *SignOp) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const VerifyOp = union(enum) {
    mac: mac.Mac,
    ec: ecdsa.VerifyState,
    rsa: RsaSig,

    pub fn update(self: *VerifyOp, data: []const u8) void {
        switch (self.*) {
            .mac => |*m| m.update(data),
            .ec => |*e| e.update(data),
            .rsa => {},
        }
    }

    pub fn zeroize(self: *VerifyOp) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const EncryptOp = union(enum) {
    aes: cipher.Cipher,
    rsa: RsaCrypt,

    pub fn zeroize(self: *EncryptOp) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const DecryptOp = union(enum) {
    aes: cipher.Cipher,
    rsa: RsaCrypt,

    pub fn zeroize(self: *DecryptOp) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const Session = struct {
    slot: ck.CK_SLOT_ID,
    flags: ck.CK_FLAGS,
    find: Find = .{},
    digest_op: ?digest.Hasher = null,
    sign_op: ?SignOp = null,
    verify_op: ?VerifyOp = null,
    encrypt_op: ?EncryptOp = null,
    decrypt_op: ?DecryptOp = null,

    pub fn endDigest(self: *Session) void {
        if (self.digest_op) |*o| std.crypto.secureZero(u8, std.mem.asBytes(o));
        self.digest_op = null;
    }

    pub fn endSign(self: *Session) void {
        if (self.sign_op) |*o| o.zeroize();
        self.sign_op = null;
    }

    pub fn endVerify(self: *Session) void {
        if (self.verify_op) |*o| o.zeroize();
        self.verify_op = null;
    }

    pub fn endEncrypt(self: *Session) void {
        if (self.encrypt_op) |*o| o.zeroize();
        self.encrypt_op = null;
    }

    pub fn endDecrypt(self: *Session) void {
        if (self.decrypt_op) |*o| o.zeroize();
        self.decrypt_op = null;
    }
};

pub const Table = struct {
    slots: [config.max_sessions]?Session = @splat(null),

    pub fn open(self: *Table, slot: ck.CK_SLOT_ID, flags: ck.CK_FLAGS) ?ck.CK_SESSION_HANDLE {
        for (&self.slots, 0..) |*s, i| {
            if (s.* == null) {
                std.crypto.secureZero(u8, std.mem.asBytes(s));
                s.* = .{ .slot = slot, .flags = flags };
                return @intCast(i + 1);
            }
        }
        return null;
    }

    pub fn get(self: *Table, h: ck.CK_SESSION_HANDLE) ?*Session {
        if (h == 0 or h > config.max_sessions) return null;
        if (self.slots[h - 1]) |*s| return s;
        return null;
    }

    pub fn close(self: *Table, h: ck.CK_SESSION_HANDLE) bool {
        if (h == 0 or h > config.max_sessions) return false;
        if (self.slots[h - 1] == null) return false;
        std.crypto.secureZero(u8, std.mem.asBytes(&self.slots[h - 1]));
        self.slots[h - 1] = null;
        return true;
    }

    pub fn closeAll(self: *Table, slot: ck.CK_SLOT_ID) void {
        for (&self.slots) |*s| {
            if (s.*) |*sp| {
                if (sp.slot == slot) {
                    std.crypto.secureZero(u8, std.mem.asBytes(s));
                    s.* = null;
                }
            }
        }
    }

    pub fn wipeAll(self: *Table) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.slots));
    }

    pub fn anyOpen(self: *Table) bool {
        for (&self.slots) |*s| {
            if (s.* != null) return true;
        }
        return false;
    }

    pub fn count(self: *Table) ck.CK_ULONG {
        var n: ck.CK_ULONG = 0;
        for (&self.slots) |*s| {
            if (s.* != null) n += 1;
        }
        return n;
    }

    pub fn countRw(self: *Table) ck.CK_ULONG {
        var n: ck.CK_ULONG = 0;
        for (&self.slots) |*s| {
            if (s.*) |*sp| {
                if ((sp.flags & ck.CKF_RW_SESSION) != 0) n += 1;
            }
        }
        return n;
    }
};

test "open returns nonzero handles and get resolves them" {
    var t: Table = .{};
    const h1 = t.open(0, ck.CKF_SERIAL_SESSION).?;
    const h2 = t.open(0, ck.CKF_SERIAL_SESSION | ck.CKF_RW_SESSION).?;
    try std.testing.expect(h1 != 0 and h2 != 0 and h1 != h2);
    try std.testing.expectEqual(@as(ck.CK_ULONG, 2), t.count());
    try std.testing.expectEqual(@as(ck.CK_ULONG, 1), t.countRw());
    try std.testing.expect(t.get(h1) != null);
    try std.testing.expect(t.get(9999) == null);
}

test "close frees the slot and closeAll empties the table" {
    var t: Table = .{};
    const h = t.open(0, ck.CKF_SERIAL_SESSION).?;
    try std.testing.expect(t.close(h));
    try std.testing.expect(!t.close(h));
    try std.testing.expect(!t.anyOpen());
    _ = t.open(0, ck.CKF_SERIAL_SESSION);
    t.closeAll(0);
    try std.testing.expect(!t.anyOpen());
}

fn expectAllZero(bytes: []const u8) !void {
    for (bytes) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "EncryptOp.zeroize zeros the AES key material" {
    var op: EncryptOp = .{ .aes = .{ .mode = .cbc, .encrypt = true, .key_len = 32 } };
    const key: []u8 = &op.aes.key_buf;
    @memset(key, 0xAA);
    op.zeroize();
    try expectAllZero(key);
}

test "DecryptOp.zeroize zeros the AES key material" {
    var op: DecryptOp = .{ .aes = .{ .mode = .cbc, .encrypt = false, .key_len = 16 } };
    const key: []u8 = &op.aes.key_buf;
    @memset(key, 0xAA);
    op.zeroize();
    try expectAllZero(key);
}

test "SignOp.zeroize zeros the EC private scalar" {
    const scalar = [_]u8{0xAB} ** 32;
    var op: SignOp = .{ .ec = ecdsa.SignState.init(.p256, ck.CKM_ECDSA, &scalar).? };
    const sc: []u8 = &op.ec.scalar;
    op.zeroize();
    try expectAllZero(sc);
}

test "VerifyOp.zeroize zeros HMAC key state" {
    var op: VerifyOp = .{ .mac = undefined };
    const st: []u8 = std.mem.asBytes(&op.mac);
    @memset(st, 0xCD);
    op.zeroize();
    try expectAllZero(st);
}

test "endEncrypt clears the op and removes the secret from the slot" {
    var t: Table = .{};
    const h = t.open(0, ck.CKF_SERIAL_SESSION).?;
    const sess = t.get(h).?;
    sess.encrypt_op = .{ .aes = .{ .mode = .gcm, .encrypt = true, .key_len = 32 } };
    const key: []u8 = &sess.encrypt_op.?.aes.key_buf;
    @memset(key, 0x5C);
    sess.endEncrypt();
    try std.testing.expect(sess.encrypt_op == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, key, 0x5C) == null);
}

test "close removes an active op's secret from the slot" {
    var t: Table = .{};
    const h = t.open(0, ck.CKF_SERIAL_SESSION).?;
    const sess = t.get(h).?;
    sess.decrypt_op = .{ .aes = .{ .mode = .cbc, .encrypt = false, .key_len = 32 } };
    const key: []u8 = &sess.decrypt_op.?.aes.key_buf;
    @memset(key, 0x5C);
    try std.testing.expect(t.close(h));
    try std.testing.expect(std.mem.indexOfScalar(u8, key, 0x5C) == null);
}

test "wipeAll zeros secret material in every slot" {
    var t: Table = .{};
    const h = t.open(0, ck.CKF_SERIAL_SESSION).?;
    const sess = t.get(h).?;
    sess.sign_op = .{ .mac = undefined };
    const st: []u8 = std.mem.asBytes(&sess.sign_op.?.mac);
    @memset(st, 0xEF);
    t.wipeAll();
    try expectAllZero(st);
}
