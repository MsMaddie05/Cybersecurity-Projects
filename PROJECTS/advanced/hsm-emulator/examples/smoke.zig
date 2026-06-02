// ©AngelaMos | 2026
// smoke.zig

const std = @import("std");
const ck = @import("ck");

const GetFunctionList = *const fn (*?*ck.CK_FUNCTION_LIST) callconv(.c) ck.CK_RV;

const default_module = "zig-out/lib/libhsm.so";
const smoke_token = "/tmp/angelamos-hsm-smoke-token.bin";
const smoke_objects = "/tmp/angelamos-hsm-smoke-objects.bin";

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

pub fn main() !void {
    _ = setenv("ANGELAMOS_HSM_TOKEN", smoke_token, 1);
    _ = setenv("ANGELAMOS_HSM_OBJECTS", smoke_objects, 1);
    _ = std.c.unlink(smoke_token);
    _ = std.c.unlink(smoke_objects);
    defer _ = std.c.unlink(smoke_token);
    defer _ = std.c.unlink(smoke_objects);

    var so_pin = "12345678".*;
    var user_pin = "1234".*;
    var new_user_pin = "5678".*;
    var wrong_pin = "0000".*;
    var label: [32]u8 = @splat(' ');
    @memcpy(label[0..11], "smoke-token");

    var lib = try std.DynLib.open(default_module);
    defer lib.close();

    const getFunctionList = lib.lookup(GetFunctionList, "C_GetFunctionList") orelse {
        std.debug.print("smoke: C_GetFunctionList not exported\n", .{});
        return error.SymbolNotFound;
    };

    var list_ptr: ?*ck.CK_FUNCTION_LIST = null;
    try check("C_GetFunctionList", getFunctionList(&list_ptr));
    const f = list_ptr orelse return error.NullFunctionList;

    if (f.version.major != 2 or f.version.minor != 40) return error.UnexpectedVersion;

    try check("C_Initialize", f.C_Initialize.?(null));
    if (f.C_Initialize.?(null) != ck.CKR_CRYPTOKI_ALREADY_INITIALIZED) return error.DoubleInitNotRejected;

    var info: ck.CK_INFO = undefined;
    try check("C_GetInfo", f.C_GetInfo.?(&info));

    var count: ck.CK_ULONG = 0;
    try check("C_GetSlotList(size)", f.C_GetSlotList.?(ck.CK_FALSE, null, &count));
    if (count != 1) return error.UnexpectedSlotCount;
    var slots: [4]ck.CK_SLOT_ID = undefined;
    try check("C_GetSlotList(fill)", f.C_GetSlotList.?(ck.CK_FALSE, &slots, &count));
    const slot = slots[0];

    var slot_info: ck.CK_SLOT_INFO = undefined;
    try check("C_GetSlotInfo", f.C_GetSlotInfo.?(slot, &slot_info));

    var token_info: ck.CK_TOKEN_INFO = undefined;
    try check("C_GetTokenInfo", f.C_GetTokenInfo.?(slot, &token_info));
    if (token_info.flags & ck.CKF_TOKEN_INITIALIZED != 0) return error.TokenShouldStartUninitialized;

    var mech_count: ck.CK_ULONG = 0;
    try check("C_GetMechanismList(size)", f.C_GetMechanismList.?(slot, null, &mech_count));
    if (mech_count == 0) return error.NoMechanisms;

    try check("C_InitToken", f.C_InitToken.?(slot, &so_pin, so_pin.len, &label));
    try check("C_GetTokenInfo(post-init)", f.C_GetTokenInfo.?(slot, &token_info));
    if (token_info.flags & ck.CKF_TOKEN_INITIALIZED == 0) return error.InitTokenDidNotInitialize;

    var h: ck.CK_SESSION_HANDLE = 0;
    try check("C_OpenSession", f.C_OpenSession.?(slot, ck.CKF_SERIAL_SESSION | ck.CKF_RW_SESSION, null, null, &h));

    var si: ck.CK_SESSION_INFO = undefined;
    try check("C_GetSessionInfo", f.C_GetSessionInfo.?(h, &si));
    if (si.state != ck.CKS_RW_PUBLIC_SESSION) return error.UnexpectedPublicState;

    try check("C_Login(SO)", f.C_Login.?(h, ck.CKU_SO, &so_pin, so_pin.len));
    try check("C_GetSessionInfo(SO)", f.C_GetSessionInfo.?(h, &si));
    if (si.state != ck.CKS_RW_SO_FUNCTIONS) return error.UnexpectedSoState;

    try check("C_InitPIN", f.C_InitPIN.?(h, &user_pin, user_pin.len));
    try check("C_Logout(SO)", f.C_Logout.?(h));

    try check("C_GetTokenInfo(post-initpin)", f.C_GetTokenInfo.?(slot, &token_info));
    if (token_info.flags & ck.CKF_USER_PIN_INITIALIZED == 0) return error.UserPinNotInitialized;

    try check("C_Login(USER)", f.C_Login.?(h, ck.CKU_USER, &user_pin, user_pin.len));
    try check("C_GetSessionInfo(USER)", f.C_GetSessionInfo.?(h, &si));
    if (si.state != ck.CKS_RW_USER_FUNCTIONS) return error.UnexpectedUserState;

    try check("C_SetPIN", f.C_SetPIN.?(h, &user_pin, user_pin.len, &new_user_pin, new_user_pin.len));
    try check("C_Logout(USER)", f.C_Logout.?(h));

    try check("C_Login(USER,new)", f.C_Login.?(h, ck.CKU_USER, &new_user_pin, new_user_pin.len));

    var class_data: ck.CK_OBJECT_CLASS = ck.CKO_DATA;
    var ck_true: ck.CK_BBOOL = ck.CK_TRUE;
    var data_label = "smoke-data".*;
    var data_value = "hello-hsm".*;
    var create_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_data, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_LABEL, .pValue = &data_label, .ulValueLen = data_label.len },
        .{ .type = ck.CKA_VALUE, .pValue = &data_value, .ulValueLen = data_value.len },
    };
    var h_data: ck.CK_OBJECT_HANDLE = 0;
    try check("C_CreateObject(data)", f.C_CreateObject.?(h, &create_tmpl, create_tmpl.len, &h_data));
    if (h_data == ck.CK_INVALID_HANDLE) return error.BadObjectHandle;

    var priv_label = "smoke-secret".*;
    var priv_value = "top-secret".*;
    var priv_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_data, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_PRIVATE, .pValue = &ck_true, .ulValueLen = 1 },
        .{ .type = ck.CKA_LABEL, .pValue = &priv_label, .ulValueLen = priv_label.len },
        .{ .type = ck.CKA_VALUE, .pValue = &priv_value, .ulValueLen = priv_value.len },
    };
    var h_priv: ck.CK_OBJECT_HANDLE = 0;
    try check("C_CreateObject(private)", f.C_CreateObject.?(h, &priv_tmpl, priv_tmpl.len, &h_priv));

    var find_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_data, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
    };
    var found: [8]ck.CK_OBJECT_HANDLE = undefined;
    var nfound: ck.CK_ULONG = 0;
    try check("C_FindObjectsInit", f.C_FindObjectsInit.?(h, &find_tmpl, find_tmpl.len));
    try check("C_FindObjects", f.C_FindObjects.?(h, &found, found.len, &nfound));
    try check("C_FindObjectsFinal", f.C_FindObjectsFinal.?(h));
    if (nfound != 2) return error.FindCountWrong;

    var probe = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_VALUE, .pValue = null, .ulValueLen = 0 },
    };
    try check("C_GetAttributeValue(len)", f.C_GetAttributeValue.?(h, h_data, &probe, probe.len));
    if (probe[0].ulValueLen != data_value.len) return error.LenProbeWrong;
    var valbuf: [64]u8 = undefined;
    probe[0].pValue = &valbuf;
    try check("C_GetAttributeValue(fetch)", f.C_GetAttributeValue.?(h, h_data, &probe, probe.len));
    if (!std.mem.eql(u8, valbuf[0..probe[0].ulValueLen], &data_value)) return error.ValueMismatch;

    var new_label = "relabeled!!".*;
    var set_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_LABEL, .pValue = &new_label, .ulValueLen = new_label.len },
    };
    try check("C_SetAttributeValue", f.C_SetAttributeValue.?(h, h_data, &set_tmpl, set_tmpl.len));
    var lblbuf: [32]u8 = undefined;
    var lblq = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_LABEL, .pValue = &lblbuf, .ulValueLen = lblbuf.len },
    };
    try check("C_GetAttributeValue(label)", f.C_GetAttributeValue.?(h, h_data, &lblq, lblq.len));
    if (!std.mem.eql(u8, lblbuf[0..lblq[0].ulValueLen], &new_label)) return error.RelabelFailed;

    var osize: ck.CK_ULONG = 0;
    try check("C_GetObjectSize", f.C_GetObjectSize.?(h, h_data, &osize));
    if (osize == 0) return error.ZeroObjectSize;

    try check("C_DestroyObject", f.C_DestroyObject.?(h, h_data));
    if (f.C_FindObjects.?(h, &found, found.len, &nfound) != ck.CKR_OPERATION_NOT_INITIALIZED) return error.FsmNotEnforced;

    try check("C_Logout(after-objects)", f.C_Logout.?(h));
    try check("C_FindObjectsInit(public)", f.C_FindObjectsInit.?(h, null, 0));
    try check("C_FindObjects(public)", f.C_FindObjects.?(h, &found, found.len, &nfound));
    try check("C_FindObjectsFinal(public)", f.C_FindObjectsFinal.?(h));
    if (nfound != 0) return error.PrivateObjectLeaked;
    if (f.C_GetAttributeValue.?(h, h_priv, &lblq, lblq.len) != ck.CKR_OBJECT_HANDLE_INVALID) return error.PrivateNotGated;

    var ck_false: ck.CK_BBOOL = ck.CK_FALSE;
    var undead_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_data, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_DESTROYABLE, .pValue = &ck_false, .ulValueLen = 1 },
    };
    var h_undead: ck.CK_OBJECT_HANDLE = 0;
    try check("C_CreateObject(undestroyable)", f.C_CreateObject.?(h, &undead_tmpl, undead_tmpl.len, &h_undead));
    if (f.C_DestroyObject.?(h, h_undead) != ck.CKR_ACTION_PROHIBITED) return error.DestroyableGateBroken;

    var immut_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_data, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_MODIFIABLE, .pValue = &ck_false, .ulValueLen = 1 },
    };
    var h_immut: ck.CK_OBJECT_HANDLE = 0;
    try check("C_CreateObject(immutable)", f.C_CreateObject.?(h, &immut_tmpl, immut_tmpl.len, &h_immut));
    var nope = "nope".*;
    var set_immut = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_LABEL, .pValue = &nope, .ulValueLen = nope.len },
    };
    if (f.C_SetAttributeValue.?(h, h_immut, &set_immut, set_immut.len) != ck.CKR_ACTION_PROHIBITED) return error.ModifiableGateBroken;

    if (f.C_FindObjectsInit.?(h, null, 3) != ck.CKR_ARGUMENTS_BAD) return error.ArgsBadNotEnforced;

    var attempt: u8 = 0;
    while (attempt < 3) : (attempt += 1) {
        if (f.C_Login.?(h, ck.CKU_USER, &wrong_pin, wrong_pin.len) != ck.CKR_PIN_INCORRECT) return error.WrongPinNotRejected;
    }
    if (f.C_Login.?(h, ck.CKU_USER, &new_user_pin, new_user_pin.len) != ck.CKR_PIN_LOCKED) return error.LockoutNotEnforced;
    try check("C_GetTokenInfo(locked)", f.C_GetTokenInfo.?(slot, &token_info));
    if (token_info.flags & ck.CKF_USER_PIN_LOCKED == 0) return error.LockFlagNotSet;

    var sha_mech = ck.CK_MECHANISM{ .mechanism = ck.CKM_SHA256, .pParameter = null, .ulParameterLen = 0 };
    try check("C_DigestInit", f.C_DigestInit.?(h, &sha_mech));
    var abc = "abc".*;
    var dg: [64]u8 = undefined;
    var dglen: ck.CK_ULONG = dg.len;
    try check("C_Digest", f.C_Digest.?(h, &abc, abc.len, &dg, &dglen));
    const sha_abc = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    if (dglen != 32 or !std.mem.eql(u8, dg[0..32], &sha_abc)) return error.DigestVectorMismatch;

    var class_secret: ck.CK_OBJECT_CLASS = ck.CKO_SECRET_KEY;
    var ck_yes: ck.CK_BBOOL = ck.CK_TRUE;
    var kt_generic: ck.CK_KEY_TYPE = ck.CKK_GENERIC_SECRET;
    var hkey_val = "secret-hmac-key".*;
    var hmac_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_secret, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_KEY_TYPE, .pValue = &kt_generic, .ulValueLen = @sizeOf(ck.CK_KEY_TYPE) },
        .{ .type = ck.CKA_VALUE, .pValue = &hkey_val, .ulValueLen = hkey_val.len },
        .{ .type = ck.CKA_SIGN, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_VERIFY, .pValue = &ck_yes, .ulValueLen = 1 },
    };
    var h_hmac: ck.CK_OBJECT_HANDLE = 0;
    try check("C_CreateObject(hmac key)", f.C_CreateObject.?(h, &hmac_tmpl, hmac_tmpl.len, &h_hmac));

    var hmac_mech = ck.CK_MECHANISM{ .mechanism = ck.CKM_SHA256_HMAC, .pParameter = null, .ulParameterLen = 0 };
    var hmsg = "authenticate me".*;
    var sig: [64]u8 = undefined;
    var siglen: ck.CK_ULONG = sig.len;
    try check("C_SignInit", f.C_SignInit.?(h, &hmac_mech, h_hmac));
    try check("C_Sign", f.C_Sign.?(h, &hmsg, hmsg.len, &sig, &siglen));
    if (siglen != 32) return error.HmacLenWrong;
    try check("C_VerifyInit", f.C_VerifyInit.?(h, &hmac_mech, h_hmac));
    try check("C_Verify", f.C_Verify.?(h, &hmsg, hmsg.len, &sig, siglen));
    try check("C_VerifyInit(tamper)", f.C_VerifyInit.?(h, &hmac_mech, h_hmac));
    sig[0] ^= 0xff;
    if (f.C_Verify.?(h, &hmsg, hmsg.len, &sig, siglen) != ck.CKR_SIGNATURE_INVALID) return error.HmacTamperNotDetected;

    var kt_aes: ck.CK_KEY_TYPE = ck.CKK_AES;
    var aes_val = [_]u8{0} ** 32;
    for (0..32) |j| aes_val[j] = @intCast(j);
    var aes_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_secret, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_KEY_TYPE, .pValue = &kt_aes, .ulValueLen = @sizeOf(ck.CK_KEY_TYPE) },
        .{ .type = ck.CKA_VALUE, .pValue = &aes_val, .ulValueLen = aes_val.len },
        .{ .type = ck.CKA_ENCRYPT, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_DECRYPT, .pValue = &ck_yes, .ulValueLen = 1 },
    };
    var h_aes: ck.CK_OBJECT_HANDLE = 0;
    try check("C_CreateObject(aes key)", f.C_CreateObject.?(h, &aes_tmpl, aes_tmpl.len, &h_aes));

    var iv = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var cbc_mech = ck.CK_MECHANISM{ .mechanism = ck.CKM_AES_CBC_PAD, .pParameter = &iv, .ulParameterLen = iv.len };
    var aes_pt = "AES round-trip through the Cryptoki ABI".*;
    var aes_ct: [64]u8 = undefined;
    var ctlen: ck.CK_ULONG = aes_ct.len;
    try check("C_EncryptInit", f.C_EncryptInit.?(h, &cbc_mech, h_aes));
    try check("C_Encrypt", f.C_Encrypt.?(h, &aes_pt, aes_pt.len, &aes_ct, &ctlen));
    var aes_back: [64]u8 = undefined;
    var backlen: ck.CK_ULONG = aes_back.len;
    try check("C_DecryptInit", f.C_DecryptInit.?(h, &cbc_mech, h_aes));
    try check("C_Decrypt", f.C_Decrypt.?(h, &aes_ct, ctlen, &aes_back, &backlen));
    if (backlen != aes_pt.len or !std.mem.eql(u8, aes_back[0..backlen], &aes_pt)) return error.AesRoundTripFailed;

    var gen_keylen: ck.CK_ULONG = 32;
    var gen_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_VALUE_LEN, .pValue = &gen_keylen, .ulValueLen = @sizeOf(ck.CK_ULONG) },
    };
    var gen_mech = ck.CK_MECHANISM{ .mechanism = ck.CKM_AES_KEY_GEN, .pParameter = null, .ulParameterLen = 0 };
    var h_gen: ck.CK_OBJECT_HANDLE = 0;
    try check("C_GenerateKey", f.C_GenerateKey.?(h, &gen_mech, &gen_tmpl, gen_tmpl.len, &h_gen));
    var genval_q = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_VALUE, .pValue = null, .ulValueLen = 0 },
    };
    if (f.C_GetAttributeValue.?(h, h_gen, &genval_q, genval_q.len) != ck.CKR_ATTRIBUTE_SENSITIVE) return error.GeneratedKeyNotSensitive;

    var ec_params = [_]u8{ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    var ec_kpgen = ck.CK_MECHANISM{ .mechanism = ck.CKM_EC_KEY_PAIR_GEN, .pParameter = null, .ulParameterLen = 0 };
    var ecpub_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_EC_PARAMS, .pValue = &ec_params, .ulValueLen = ec_params.len },
        .{ .type = ck.CKA_VERIFY, .pValue = &ck_yes, .ulValueLen = 1 },
    };
    var ecpriv_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_SIGN, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_PRIVATE, .pValue = &ck_false, .ulValueLen = 1 },
    };
    var h_ecpub: ck.CK_OBJECT_HANDLE = 0;
    var h_ecpriv: ck.CK_OBJECT_HANDLE = 0;
    try check("C_GenerateKeyPair(EC)", f.C_GenerateKeyPair.?(h, &ec_kpgen, &ecpub_tmpl, ecpub_tmpl.len, &ecpriv_tmpl, ecpriv_tmpl.len, &h_ecpub, &h_ecpriv));

    var ecdsa_mech = ck.CK_MECHANISM{ .mechanism = ck.CKM_ECDSA_SHA256, .pParameter = null, .ulParameterLen = 0 };
    var ecmsg = "sign me over ECDSA P-256".*;
    var ecsig: [128]u8 = undefined;
    var ecsiglen: ck.CK_ULONG = ecsig.len;
    try check("C_SignInit(ECDSA)", f.C_SignInit.?(h, &ecdsa_mech, h_ecpriv));
    try check("C_Sign(ECDSA)", f.C_Sign.?(h, &ecmsg, ecmsg.len, &ecsig, &ecsiglen));
    if (ecsiglen != 64) return error.EcdsaSigLenWrong;
    try check("C_VerifyInit(ECDSA)", f.C_VerifyInit.?(h, &ecdsa_mech, h_ecpub));
    try check("C_Verify(ECDSA)", f.C_Verify.?(h, &ecmsg, ecmsg.len, &ecsig, ecsiglen));
    try check("C_VerifyInit(ECDSA tamper)", f.C_VerifyInit.?(h, &ecdsa_mech, h_ecpub));
    ecsig[0] ^= 0xff;
    if (f.C_Verify.?(h, &ecmsg, ecmsg.len, &ecsig, ecsiglen) != ck.CKR_SIGNATURE_INVALID) return error.EcdsaTamperNotDetected;

    var ecval_q = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_VALUE, .pValue = null, .ulValueLen = 0 },
    };
    if (f.C_GetAttributeValue.?(h, h_ecpriv, &ecval_q, ecval_q.len) != ck.CKR_ATTRIBUTE_SENSITIVE) return error.EcPrivNotSensitive;
    var ecpt_q = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_EC_POINT, .pValue = null, .ulValueLen = 0 },
    };
    try check("C_GetAttributeValue(EC_POINT)", f.C_GetAttributeValue.?(h, h_ecpub, &ecpt_q, ecpt_q.len));
    if (ecpt_q[0].ulValueLen != 67) return error.EcPointLenWrong;

    var rsa_bits: ck.CK_ULONG = 2048;
    var rsa_kpgen = ck.CK_MECHANISM{ .mechanism = ck.CKM_RSA_PKCS_KEY_PAIR_GEN, .pParameter = null, .ulParameterLen = 0 };
    var rsapub_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_MODULUS_BITS, .pValue = &rsa_bits, .ulValueLen = @sizeOf(ck.CK_ULONG) },
        .{ .type = ck.CKA_VERIFY, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_ENCRYPT, .pValue = &ck_yes, .ulValueLen = 1 },
    };
    var rsapriv_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_SIGN, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_DECRYPT, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_PRIVATE, .pValue = &ck_false, .ulValueLen = 1 },
    };
    var h_rsapub: ck.CK_OBJECT_HANDLE = 0;
    var h_rsapriv: ck.CK_OBJECT_HANDLE = 0;
    try check("C_GenerateKeyPair(RSA)", f.C_GenerateKeyPair.?(h, &rsa_kpgen, &rsapub_tmpl, rsapub_tmpl.len, &rsapriv_tmpl, rsapriv_tmpl.len, &h_rsapub, &h_rsapriv));

    var rsa_sha_pkcs = ck.CK_MECHANISM{ .mechanism = ck.CKM_SHA256_RSA_PKCS, .pParameter = null, .ulParameterLen = 0 };
    var rsamsg = "sign me over RSA PKCS#1 v1.5".*;
    var rsasig: [256]u8 = undefined;
    var rsasiglen: ck.CK_ULONG = rsasig.len;
    try check("C_SignInit(RSA)", f.C_SignInit.?(h, &rsa_sha_pkcs, h_rsapriv));
    try check("C_Sign(RSA)", f.C_Sign.?(h, &rsamsg, rsamsg.len, &rsasig, &rsasiglen));
    if (rsasiglen != 256) return error.RsaSigLenWrong;
    try check("C_VerifyInit(RSA)", f.C_VerifyInit.?(h, &rsa_sha_pkcs, h_rsapub));
    try check("C_Verify(RSA)", f.C_Verify.?(h, &rsamsg, rsamsg.len, &rsasig, rsasiglen));
    try check("C_VerifyInit(RSA tamper)", f.C_VerifyInit.?(h, &rsa_sha_pkcs, h_rsapub));
    rsasig[10] ^= 0xff;
    if (f.C_Verify.?(h, &rsamsg, rsamsg.len, &rsasig, rsasiglen) != ck.CKR_SIGNATURE_INVALID) return error.RsaTamperNotDetected;

    var rsa_pkcs = ck.CK_MECHANISM{ .mechanism = ck.CKM_RSA_PKCS, .pParameter = null, .ulParameterLen = 0 };
    var rsapt = "rsa secret".*;
    var rsact: [256]u8 = undefined;
    var rsactlen: ck.CK_ULONG = rsact.len;
    try check("C_EncryptInit(RSA)", f.C_EncryptInit.?(h, &rsa_pkcs, h_rsapub));
    try check("C_Encrypt(RSA)", f.C_Encrypt.?(h, &rsapt, rsapt.len, &rsact, &rsactlen));
    if (rsactlen != 256) return error.RsaCtLenWrong;
    var rsaback: [256]u8 = undefined;
    var rsabacklen: ck.CK_ULONG = rsaback.len;
    try check("C_DecryptInit(RSA)", f.C_DecryptInit.?(h, &rsa_pkcs, h_rsapriv));
    try check("C_Decrypt(RSA)", f.C_Decrypt.?(h, &rsact, rsactlen, &rsaback, &rsabacklen));
    if (rsabacklen != rsapt.len or !std.mem.eql(u8, rsaback[0..rsabacklen], &rsapt)) return error.RsaRoundTripFailed;

    var rsaval_q = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_PRIVATE_EXPONENT, .pValue = null, .ulValueLen = 0 },
    };
    if (f.C_GetAttributeValue.?(h, h_rsapriv, &rsaval_q, rsaval_q.len) != ck.CKR_ATTRIBUTE_SENSITIVE) return error.RsaPrivNotSensitive;

    try check("C_CloseSession", f.C_CloseSession.?(h));
    try check("C_Finalize", f.C_Finalize.?(null));

    std.debug.print("smoke: OK\n", .{});
    std.debug.print("  cryptokiVersion = {d}.{d}\n", .{ info.cryptokiVersion.major, info.cryptokiVersion.minor });
    std.debug.print("  slots           = {d}\n", .{count});
    std.debug.print("  token label     = {s}\n", .{token_info.label});
    std.debug.print("  mechanisms      = {d}\n", .{mech_count});
    std.debug.print("  login + PIN     = init/login/initpin/setpin OK; lockout trips after 3 wrong\n", .{});
    std.debug.print("  objects         = create/find/get(2-call)/set/size/destroy OK; CKA_PRIVATE hidden after logout\n", .{});
    std.debug.print("  object gates    = CKA_DESTROYABLE/CKA_MODIFIABLE=false enforced; FindObjectsInit arg-check OK\n", .{});
    std.debug.print("  crypto          = SHA-256 vector OK; HMAC sign/verify (+tamper) OK; AES-CBC-PAD round-trip OK\n", .{});
    std.debug.print("  keygen          = C_GenerateKey AES OK; generated key CKA_VALUE is sensitive (unextractable)\n", .{});
    std.debug.print("  ecdsa           = C_GenerateKeyPair EC P-256 OK; ECDSA-SHA256 sign/verify (+tamper) OK; priv scalar sensitive\n", .{});
    std.debug.print("  rsa             = C_GenerateKeyPair RSA-2048 OK; SHA256-RSA-PKCS sign/verify (+tamper) + RSA-PKCS enc/dec OK; priv sensitive\n", .{});
}

fn check(name: []const u8, rv: ck.CK_RV) !void {
    if (rv != ck.CKR_OK) {
        std.debug.print("smoke: {s} -> 0x{X}\n", .{ name, rv });
        return error.CryptokiError;
    }
}
