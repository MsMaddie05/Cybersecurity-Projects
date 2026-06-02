// ©AngelaMos | 2026
// keymgmt.zig

const std = @import("std");
const ck = @import("../ck.zig");
const config = @import("../config.zig");
const state = @import("../core/state.zig");
const object_store = @import("../core/object_store.zig");
const object = @import("object.zig");
const ecdsa = @import("../crypto/ecdsa.zig");
const rsa = @import("../crypto/rsa.zig");

const Object = object_store.Object;

fn attrBytes(a: ck.CK_ATTRIBUTE) []const u8 {
    const ptr = a.pValue orelse return &.{};
    return @as([*]const u8, @ptrCast(ptr))[0..@intCast(a.ulValueLen)];
}

fn ulongFrom(bytes: []const u8) ?ck.CK_ULONG {
    if (bytes.len != @sizeOf(ck.CK_ULONG)) return null;
    return std.mem.bytesToValue(ck.CK_ULONG, bytes[0..@sizeOf(ck.CK_ULONG)]);
}

pub fn C_GenerateKey(hSession: ck.CK_SESSION_HANDLE, pMechanism: *ck.CK_MECHANISM, pTemplate: [*]ck.CK_ATTRIBUTE, ulCount: ck.CK_ULONG, phKey: *ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.current() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    state.mutex.lock();
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (pMechanism.mechanism != ck.CKM_AES_KEY_GEN) return ck.CKR_MECHANISM_INVALID;

    const allocator = inst.allocator();
    const template = if (ulCount == 0) &[_]ck.CK_ATTRIBUTE{} else pTemplate[0..@intCast(ulCount)];

    var key_len: usize = 0;
    var have_len = false;
    for (template) |a| {
        if (a.type == ck.CKA_VALUE_LEN) {
            const v = ulongFrom(attrBytes(a)) orelse return ck.CKR_ATTRIBUTE_VALUE_INVALID;
            key_len = @intCast(v);
            have_len = true;
        }
    }
    if (!have_len) return ck.CKR_TEMPLATE_INCOMPLETE;
    if (key_len != config.aes_min_key_bytes and key_len != config.aes_max_key_bytes) return ck.CKR_KEY_SIZE_RANGE;

    var obj: Object = .{};
    var moved = false;
    defer if (!moved) obj.deinit(allocator);

    for (template) |a| {
        obj.set(allocator, a.type, attrBytes(a)) catch |e| return object_store.mapSetErr(e);
    }

    var key_bytes: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key_bytes);
    inst.io().randomSecure(key_bytes[0..key_len]) catch return ck.CKR_FUNCTION_FAILED;

    var class_val: ck.CK_OBJECT_CLASS = ck.CKO_SECRET_KEY;
    var type_val: ck.CK_KEY_TYPE = ck.CKK_AES;
    obj.set(allocator, ck.CKA_CLASS, std.mem.asBytes(&class_val)) catch |e| return object_store.mapSetErr(e);
    obj.set(allocator, ck.CKA_KEY_TYPE, std.mem.asBytes(&type_val)) catch |e| return object_store.mapSetErr(e);
    obj.set(allocator, ck.CKA_VALUE, key_bytes[0..key_len]) catch |e| return object_store.mapSetErr(e);
    obj.set(allocator, ck.CKA_LOCAL, &[_]u8{ck.CK_TRUE}) catch |e| return object_store.mapSetErr(e);
    const kgm: ck.CK_MECHANISM_TYPE = ck.CKM_AES_KEY_GEN;
    obj.set(allocator, ck.CKA_KEY_GEN_MECHANISM, std.mem.asBytes(&kgm)) catch |e| return object_store.mapSetErr(e);

    if (!obj.has(ck.CKA_SENSITIVE)) obj.set(allocator, ck.CKA_SENSITIVE, &[_]u8{ck.CK_TRUE}) catch |e| return object_store.mapSetErr(e);
    if (!obj.has(ck.CKA_EXTRACTABLE)) obj.set(allocator, ck.CKA_EXTRACTABLE, &[_]u8{ck.CK_FALSE}) catch |e| return object_store.mapSetErr(e);
    const always_sensitive: u8 = if (obj.getBool(ck.CKA_SENSITIVE)) ck.CK_TRUE else ck.CK_FALSE;
    const never_extractable: u8 = if (!obj.getBool(ck.CKA_EXTRACTABLE)) ck.CK_TRUE else ck.CK_FALSE;
    obj.set(allocator, ck.CKA_ALWAYS_SENSITIVE, &[_]u8{always_sensitive}) catch |e| return object_store.mapSetErr(e);
    obj.set(allocator, ck.CKA_NEVER_EXTRACTABLE, &[_]u8{never_extractable}) catch |e| return object_store.mapSetErr(e);

    object.materializeDefaults(&obj, allocator, ck.CKO_SECRET_KEY) catch |e| return object_store.mapSetErr(e);

    moved = true;
    return object.insertNew(inst, sess, obj, phKey);
}

fn ecParamsFrom(template: []const ck.CK_ATTRIBUTE) ?[]const u8 {
    for (template) |a| {
        if (a.type == ck.CKA_EC_PARAMS) return attrBytes(a);
    }
    return null;
}

fn modulusBitsFrom(template: []const ck.CK_ATTRIBUTE) ?ck.CK_ULONG {
    for (template) |a| {
        if (a.type == ck.CKA_MODULUS_BITS) return ulongFrom(attrBytes(a));
    }
    return null;
}

fn applySensitivityDefaults(obj: *Object, allocator: std.mem.Allocator, kgm: ck.CK_MECHANISM_TYPE) !void {
    try obj.set(allocator, ck.CKA_LOCAL, &[_]u8{ck.CK_TRUE});
    if (!obj.has(ck.CKA_SENSITIVE)) try obj.set(allocator, ck.CKA_SENSITIVE, &[_]u8{ck.CK_TRUE});
    if (!obj.has(ck.CKA_EXTRACTABLE)) try obj.set(allocator, ck.CKA_EXTRACTABLE, &[_]u8{ck.CK_FALSE});
    const always_sensitive: u8 = if (obj.getBool(ck.CKA_SENSITIVE)) ck.CK_TRUE else ck.CK_FALSE;
    const never_extractable: u8 = if (!obj.getBool(ck.CKA_EXTRACTABLE)) ck.CK_TRUE else ck.CK_FALSE;
    try obj.set(allocator, ck.CKA_ALWAYS_SENSITIVE, &[_]u8{always_sensitive});
    try obj.set(allocator, ck.CKA_NEVER_EXTRACTABLE, &[_]u8{never_extractable});
    const m: ck.CK_MECHANISM_TYPE = kgm;
    try obj.set(allocator, ck.CKA_KEY_GEN_MECHANISM, std.mem.asBytes(&m));
}

fn buildEcPublic(obj: *Object, allocator: std.mem.Allocator, template: []const ck.CK_ATTRIBUTE, curve: ecdsa.Curve, point: []const u8) !void {
    for (template) |a| try obj.set(allocator, a.type, attrBytes(a));
    const class_val: ck.CK_OBJECT_CLASS = ck.CKO_PUBLIC_KEY;
    const type_val: ck.CK_KEY_TYPE = ck.CKK_EC;
    try obj.set(allocator, ck.CKA_CLASS, std.mem.asBytes(&class_val));
    try obj.set(allocator, ck.CKA_KEY_TYPE, std.mem.asBytes(&type_val));
    try obj.set(allocator, ck.CKA_EC_PARAMS, curve.oidDer());
    var der_buf: [ecdsa.max_ec_point_der]u8 = undefined;
    try obj.set(allocator, ck.CKA_EC_POINT, ecdsa.wrapEcPoint(&der_buf, point));
    try obj.set(allocator, ck.CKA_LOCAL, &[_]u8{ck.CK_TRUE});
    const kgm: ck.CK_MECHANISM_TYPE = ck.CKM_EC_KEY_PAIR_GEN;
    try obj.set(allocator, ck.CKA_KEY_GEN_MECHANISM, std.mem.asBytes(&kgm));
    try object.materializeDefaults(obj, allocator, ck.CKO_PUBLIC_KEY);
}

fn buildEcPrivate(obj: *Object, allocator: std.mem.Allocator, template: []const ck.CK_ATTRIBUTE, curve: ecdsa.Curve, scalar: []const u8) !void {
    for (template) |a| try obj.set(allocator, a.type, attrBytes(a));
    const class_val: ck.CK_OBJECT_CLASS = ck.CKO_PRIVATE_KEY;
    const type_val: ck.CK_KEY_TYPE = ck.CKK_EC;
    try obj.set(allocator, ck.CKA_CLASS, std.mem.asBytes(&class_val));
    try obj.set(allocator, ck.CKA_KEY_TYPE, std.mem.asBytes(&type_val));
    try obj.set(allocator, ck.CKA_EC_PARAMS, curve.oidDer());
    try obj.set(allocator, ck.CKA_VALUE, scalar);
    try applySensitivityDefaults(obj, allocator, ck.CKM_EC_KEY_PAIR_GEN);
    try object.materializeDefaults(obj, allocator, ck.CKO_PRIVATE_KEY);
}

fn buildRsaPublic(obj: *Object, allocator: std.mem.Allocator, template: []const ck.CK_ATTRIBUTE, g: *const rsa.Generated) !void {
    for (template) |a| try obj.set(allocator, a.type, attrBytes(a));
    const class_val: ck.CK_OBJECT_CLASS = ck.CKO_PUBLIC_KEY;
    const type_val: ck.CK_KEY_TYPE = ck.CKK_RSA;
    const bits: ck.CK_ULONG = g.bits;
    try obj.set(allocator, ck.CKA_CLASS, std.mem.asBytes(&class_val));
    try obj.set(allocator, ck.CKA_KEY_TYPE, std.mem.asBytes(&type_val));
    try obj.set(allocator, ck.CKA_MODULUS, g.n.slice());
    try obj.set(allocator, ck.CKA_PUBLIC_EXPONENT, g.e.slice());
    try obj.set(allocator, ck.CKA_MODULUS_BITS, std.mem.asBytes(&bits));
    try obj.set(allocator, ck.CKA_LOCAL, &[_]u8{ck.CK_TRUE});
    const kgm: ck.CK_MECHANISM_TYPE = ck.CKM_RSA_PKCS_KEY_PAIR_GEN;
    try obj.set(allocator, ck.CKA_KEY_GEN_MECHANISM, std.mem.asBytes(&kgm));
    try object.materializeDefaults(obj, allocator, ck.CKO_PUBLIC_KEY);
}

fn buildRsaPrivate(obj: *Object, allocator: std.mem.Allocator, template: []const ck.CK_ATTRIBUTE, g: *const rsa.Generated) !void {
    for (template) |a| try obj.set(allocator, a.type, attrBytes(a));
    const class_val: ck.CK_OBJECT_CLASS = ck.CKO_PRIVATE_KEY;
    const type_val: ck.CK_KEY_TYPE = ck.CKK_RSA;
    try obj.set(allocator, ck.CKA_CLASS, std.mem.asBytes(&class_val));
    try obj.set(allocator, ck.CKA_KEY_TYPE, std.mem.asBytes(&type_val));
    try obj.set(allocator, ck.CKA_MODULUS, g.n.slice());
    try obj.set(allocator, ck.CKA_PUBLIC_EXPONENT, g.e.slice());
    try obj.set(allocator, ck.CKA_PRIVATE_EXPONENT, g.d.slice());
    try obj.set(allocator, ck.CKA_PRIME_1, g.p.slice());
    try obj.set(allocator, ck.CKA_PRIME_2, g.q.slice());
    try obj.set(allocator, ck.CKA_EXPONENT_1, g.dmp1.slice());
    try obj.set(allocator, ck.CKA_EXPONENT_2, g.dmq1.slice());
    try obj.set(allocator, ck.CKA_COEFFICIENT, g.iqmp.slice());
    try applySensitivityDefaults(obj, allocator, ck.CKM_RSA_PKCS_KEY_PAIR_GEN);
    try object.materializeDefaults(obj, allocator, ck.CKO_PRIVATE_KEY);
}

pub fn C_GenerateKeyPair(hSession: ck.CK_SESSION_HANDLE, pMechanism: *ck.CK_MECHANISM, pPublicKeyTemplate: [*]ck.CK_ATTRIBUTE, ulPublicKeyAttributeCount: ck.CK_ULONG, pPrivateKeyTemplate: [*]ck.CK_ATTRIBUTE, ulPrivateKeyAttributeCount: ck.CK_ULONG, phPublicKey: *ck.CK_OBJECT_HANDLE, phPrivateKey: *ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.current() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    state.mutex.lock();
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;

    const allocator = inst.allocator();
    const pub_template = if (ulPublicKeyAttributeCount == 0) &[_]ck.CK_ATTRIBUTE{} else pPublicKeyTemplate[0..@intCast(ulPublicKeyAttributeCount)];
    const priv_template = if (ulPrivateKeyAttributeCount == 0) &[_]ck.CK_ATTRIBUTE{} else pPrivateKeyTemplate[0..@intCast(ulPrivateKeyAttributeCount)];

    var pub_obj: Object = .{};
    var pub_moved = false;
    defer if (!pub_moved) pub_obj.deinit(allocator);
    var priv_obj: Object = .{};
    var priv_moved = false;
    defer if (!priv_moved) priv_obj.deinit(allocator);

    switch (pMechanism.mechanism) {
        ck.CKM_EC_KEY_PAIR_GEN => {
            const params = ecParamsFrom(pub_template) orelse return ck.CKR_TEMPLATE_INCOMPLETE;
            const curve = ecdsa.curveFromParams(params) orelse return ck.CKR_DOMAIN_PARAMS_INVALID;
            var km = ecdsa.generate(inst.io(), curve) catch return ck.CKR_FUNCTION_FAILED;
            defer std.crypto.secureZero(u8, &km.scalar);
            buildEcPublic(&pub_obj, allocator, pub_template, curve, km.pointBytes()) catch |e| return object_store.mapSetErr(e);
            buildEcPrivate(&priv_obj, allocator, priv_template, curve, km.scalarBytes()) catch |e| return object_store.mapSetErr(e);
        },
        ck.CKM_RSA_PKCS_KEY_PAIR_GEN => {
            const bits = modulusBitsFrom(pub_template) orelse return ck.CKR_TEMPLATE_INCOMPLETE;
            if (bits < config.rsa_min_key_bits or bits > config.rsa_max_key_bits) return ck.CKR_KEY_SIZE_RANGE;
            var g = rsa.generate(@intCast(bits)) catch return ck.CKR_FUNCTION_FAILED;
            defer g.zeroize();
            buildRsaPublic(&pub_obj, allocator, pub_template, &g) catch |e| return object_store.mapSetErr(e);
            buildRsaPrivate(&priv_obj, allocator, priv_template, &g) catch |e| return object_store.mapSetErr(e);
        },
        else => return ck.CKR_MECHANISM_INVALID,
    }

    const pub_is_token = pub_obj.isToken();
    pub_moved = true;
    const pub_rv = object.insertNew(inst, sess, pub_obj, phPublicKey);
    if (pub_rv != ck.CKR_OK) return pub_rv;

    priv_moved = true;
    const priv_rv = object.insertNew(inst, sess, priv_obj, phPrivateKey);
    if (priv_rv != ck.CKR_OK) {
        _ = inst.objects.destroy(allocator, phPublicKey.*);
        if (pub_is_token) object_store.save(inst.io(), allocator, &inst.objects, inst.mk) catch {};
        return priv_rv;
    }
    return ck.CKR_OK;
}

pub fn C_WrapKey(_: ck.CK_SESSION_HANDLE, _: *ck.CK_MECHANISM, _: ck.CK_OBJECT_HANDLE, _: ck.CK_OBJECT_HANDLE, _: ?[*]ck.CK_BYTE, _: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    return ck.CKR_FUNCTION_NOT_SUPPORTED;
}

pub fn C_UnwrapKey(_: ck.CK_SESSION_HANDLE, _: *ck.CK_MECHANISM, _: ck.CK_OBJECT_HANDLE, _: [*]ck.CK_BYTE, _: ck.CK_ULONG, _: [*]ck.CK_ATTRIBUTE, _: ck.CK_ULONG, _: *ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    return ck.CKR_FUNCTION_NOT_SUPPORTED;
}

pub fn C_DeriveKey(_: ck.CK_SESSION_HANDLE, _: *ck.CK_MECHANISM, _: ck.CK_OBJECT_HANDLE, _: ?[*]ck.CK_ATTRIBUTE, _: ck.CK_ULONG, _: *ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    return ck.CKR_FUNCTION_NOT_SUPPORTED;
}
