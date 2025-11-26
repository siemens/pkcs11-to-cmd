/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 *   Eugen Kremer <eugen.kremer@siemens.com>
 */

#include "blind_implementations.hpp"
#include "consts.hpp"
#include "debug.hpp"
#include "utils.hpp"

#include <cstdlib>
#include <memory>
#include <set>
#include <string>

#include <openssl/core_names.h>
#include <openssl/cryptoerr_legacy.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/types.h>
#include <openssl/x509.h>

#define CRYPTOKI_EXPORTS
#include <p11-kit/pkcs11.h>

static std::string mechanismToString(CK_MECHANISM_TYPE mechanism)
{
    switch (mechanism) {
    case CKM_RSA_PKCS:
        return "CKM_RSA_PKCS";
    case CKM_SHA256_RSA_PKCS:
        return "CKM_SHA256_RSA_PKCS";
    case CKM_SHA384_RSA_PKCS:
        return "CKM_SHA384_RSA_PKCS";
    case CKM_SHA512_RSA_PKCS:
        return "CKM_SHA512_RSA_PKCS";
    case CKM_SHA1_RSA_PKCS:
        return "CKM_SHA1_RSA_PKCS";
    case CKM_RSA_X_509:
        return "CKM_RSA_X_509";
    case CKM_ECDSA:
        return "CKM_ECDSA";
    case CKM_ECDSA_SHA1:
        return "CKM_ECDSA_SHA1";
    case CKM_ECDSA_SHA256:
        return "CKM_ECDSA_SHA256";
    case CKM_ECDSA_SHA384:
        return "CKM_ECDSA_SHA384";
    case CKM_ECDSA_SHA512:
        return "CKM_ECDSA_SHA512";
    default:
        debug("Unknown mechanism type: %#lx", mechanism);
        return std::string("CKM_AS_VALUE_") + std::to_string(mechanism);
    }
}

static CK_RV copy_safe_(CK_VOID_PTR pDest, CK_ULONG_PTR pDestLen, const void* data, size_t data_len)
{
    if (pDestLen == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }

    if (pDest == nullptr) {
        *pDestLen = data_len;
        return CKR_OK;
    }

    if (*pDestLen < data_len) {
        *pDestLen = CK_UNAVAILABLE_INFORMATION;
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(pDest, data, data_len);
    *pDestLen = data_len;

    return CKR_OK;
}

template <typename TData>
static CK_RV copy_safe(CK_VOID_PTR pDest, CK_ULONG_PTR pDestLen, const TData& data)
{
    return copy_safe_(pDest, pDestLen, &data, sizeof(TData));
}

template <typename TFn, typename TParam>
static CK_RV read_safe(TFn fn, TParam param, CK_VOID_PTR pValue, CK_ULONG_PTR pValueLen)
{
    CK_BYTE_PTR buffer = nullptr;
    CK_ULONG len = fn(param, &buffer);
    CK_RV ret = CKR_FUNCTION_FAILED;
    if (len > 0) {
        ret = copy_safe_(pValue, pValueLen, buffer, len);
    }
    OPENSSL_free(buffer);
    return ret;
}

extern "C" {

CK_RV CK_SPEC C_Finalize(CK_VOID_PTR pReserved)
{
    debug("C_Finalize called");
    return CKR_OK;
}

CK_RV CK_SPEC C_GetInfo(CK_INFO_PTR pInfo)
{
    debug("C_GetInfo called");
    if (!pInfo) {
        return CKR_ARGUMENTS_BAD;
    }

    *pInfo = {};
    pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
    pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
    strncpy((char*)pInfo->manufacturerID, PROVIDER_NAME, sizeof(pInfo->manufacturerID));
    strncpy((char*)pInfo->libraryDescription, PROVIDER_NAME, sizeof(pInfo->libraryDescription));
    pInfo->libraryVersion.major = PROVIDER_VERSION_MAJOR;
    pInfo->libraryVersion.minor = PROVIDER_VERSION_MINOR;
    return CKR_OK;
}

static const std::set<object_type, std::less<>> valid_object_types
    = { object_type::public_key, object_type::private_key, object_type::certificate };

static constexpr CK_SESSION_HANDLE current_slot_session = 1;

struct Session;
static Session* s_session;

struct Session {
    CK_SLOT_ID slotID;
    std::shared_ptr<X509> slotCertificate = nullptr;
    std::set<object_type> foundObjects;
    std::set<object_type>::iterator currentObjectIt;
    std::shared_ptr<FILE> dataFile = nullptr;

    static Session* CreateSession(CK_SLOT_ID slotID, const char* slotCertificateFile)
    {
        if (!isValidFile(slotCertificateFile)) {
            debug("Invalid certificate file: %s", slotCertificateFile);
            return nullptr;
        }

        auto fp = std::shared_ptr<FILE>(fopen(slotCertificateFile, "r"), fclose_conditional);

        if (!fp) {
            debug("Failed to open certificate file: %s", slotCertificateFile);
            return nullptr;
        }

        auto slotCertificate = std::shared_ptr<X509>(PEM_read_X509(fp.get(), nullptr, nullptr, nullptr), X509_free);

        if (!slotCertificate) {
            debug("Failed to read certificate from file: %s", slotCertificateFile);
            return nullptr;
        }

        return new Session { slotID, slotCertificate };
    };

    static Session* From(CK_SESSION_HANDLE hSession)
    {
        if (s_session && hSession == current_slot_session) {
            return s_session;
        }
        return nullptr;
    }

    std::shared_ptr<EVP_PKEY> getPublicKey() const
    {
        EVP_PKEY* pkey = X509_get_pubkey(slotCertificate.get());
        return std::shared_ptr<EVP_PKEY>(pkey, EVP_PKEY_free);
    }

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&&) = delete;
    Session& operator=(Session&&) = delete;
};

CK_RV CK_SPEC C_OpenSession(
    CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR pSession)
{
    debug("C_OpenSession called");
    if (!pSession) {
        return CKR_ARGUMENTS_BAD;
    }

    auto slots = getSlots();
    if (slotID >= slots.size()) {
        debug("C_OpenSession: invalid slot ID");
        return CKR_SLOT_ID_INVALID;
    }

    auto slot = slots[slotID];
    if (slot.empty()) {
        return CKR_SLOT_ID_INVALID;
    }

    if (s_session) {
        return CKR_SESSION_COUNT;
    }

    s_session = Session::CreateSession(slotID, slot.c_str());
    if (!s_session) {
        return CKR_SLOT_ID_INVALID;
    }

    *pSession = current_slot_session;

    return CKR_OK;
}

CK_RV CK_SPEC C_CloseSession(CK_SESSION_HANDLE hSession)
{
    debug("C_CloseSession called");
    if (!s_session || hSession != current_slot_session) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    delete s_session;
    s_session = nullptr;

    return CKR_OK;
}

CK_RV CK_SPEC C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG PinLen)
{
    debug("C_Login called");
    return CKR_OK;
}

CK_RV CK_SPEC C_Logout(CK_SESSION_HANDLE hSession)
{
    debug("C_Logout called");
    return CKR_OK;
}

CK_RV CK_SPEC C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject)
{
    debug("C_SignInit called");

    auto ptr = Session::From(hSession);
    if (!ptr || !pMechanism) {
        return CKR_ARGUMENTS_BAD;
    }

    Session& session = *ptr;

    const char* data_path = getenv(ENV_DATA);
    const char* sig_path = getenv(ENV_SIG);

    if (!data_path || !sig_path) {
        debug("C_Sign: Environment variables missing %s, %s", ENV_DATA, ENV_SIG);
        return CKR_FUNCTION_FAILED;
    }

    auto slots = getSlots();
    if (slots[session.slotID].empty()) {
        debug("C_Sign: Invalid slotID=%d for certificate", session.slotID);
        return CKR_FUNCTION_FAILED;
    }

    session.dataFile = std::shared_ptr<FILE>(fopen(data_path, "wb"), fclose_conditional);
    if (!session.dataFile) {
        debug("C_Sign: Failed to open %s for writing", data_path);
        return CKR_FUNCTION_FAILED;
    }

    auto mechanismStr = mechanismToString(pMechanism->mechanism);
    setenv(ENV_MECHANISM, mechanismStr.c_str(), 1);
    debug("Signing  with mechanism %s", mechanismStr.c_str());

    return CKR_OK;
}

static CK_RV SignUpdate_internal(Session& session, CK_BYTE_PTR pPart, CK_ULONG PartLen)
{
    debug("SignUpdate_internal called");
    if (!session.dataFile) {
        debug("SignUpdate_internal: Session not initialized for signing");
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    debug("SignUpdate_internal: Writing %lu bytes to data file", PartLen);

    if (fwrite(pPart, 1, PartLen, session.dataFile.get()) != PartLen) {
        debug("SignUpdate_internal: Failed to write data");
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV CK_SPEC C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG PartLen)
{
    debug("C_SignUpdate called");
    if (!pPart || PartLen == 0) {
        return CKR_ARGUMENTS_BAD;
    }

    auto ptr = Session::From(hSession);
    if (!ptr) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    Session& session = *ptr;

    return SignUpdate_internal(session, pPart, PartLen);
}

static CK_RV Sign_internal(Session& session, CK_BYTE_PTR pSignature, CK_ULONG_PTR pSignatureLen)
{
    debug("sign_internal called");

    const char* cmd = getenv(ENV_CMD);
    const char* sig_path = getenv(ENV_SIG);

    if (!cmd) {
        debug("sign_internal: Environment variable missing %s", ENV_CMD);
        return CKR_FUNCTION_FAILED;
    }

    session.dataFile.reset(); // Close the data file before calling the command

    auto slots = getSlots();
    setenv(ENV_CERT, slots[session.slotID].c_str(), 1);

    int rc = system(cmd);
    if (rc != 0) {
        debug("sign_internal: failed to execute command '%s' with error code %d", cmd, rc);
        return CKR_FUNCTION_FAILED;
    }

    auto signatureFile = std::shared_ptr<FILE>(fopen(sig_path, "rb"), fclose_conditional);
    if (!signatureFile) {
        debug("sign_internal: Failed to open %s for reading", sig_path);
        return CKR_FUNCTION_FAILED;
    }

    // determine the size of the signature file
    fseek(signatureFile.get(), 0, SEEK_END);
    long sig_len = ftell(signatureFile.get());

    debug("sign_internal: Signature file size=%ld", sig_len);

    if (sig_len <= 0 || (CK_ULONG)sig_len > *pSignatureLen) {
        debug("sign_internal: Signature buffer[%d] too small or invalid signature "
              "size=%d",
            *pSignatureLen, sig_len);

        return CKR_BUFFER_TOO_SMALL;
    }

    fseek(signatureFile.get(), 0, SEEK_SET);
    if (fread(pSignature, 1, sig_len, signatureFile.get()) != (size_t)sig_len) {
        debug("sign_internal: Failed to read signature file");
        return CKR_FUNCTION_FAILED;
    }
    *pSignatureLen = (CK_ULONG)sig_len;

    return CKR_OK;
}

CK_RV CK_SPEC C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pSignatureLen)
{
    debug("C_SignFinal called");

    auto ptr = Session::From(hSession);
    if (!ptr || !pSignature || !pSignatureLen) {
        return CKR_ARGUMENTS_BAD;
    }

    Session& session = *ptr;

    return Sign_internal(session, pSignature, pSignatureLen);
}

CK_RV CK_SPEC C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG DataLen, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{
    debug("C_Sign called");

    auto ptr = Session::From(hSession);
    if (!ptr) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    Session& session = *ptr;

    if (!pData || !pulSignatureLen) {
        return CKR_ARGUMENTS_BAD;
    }

    CK_RV res = SignUpdate_internal(session, pData, DataLen);
    if (res != CKR_OK) {
        debug("C_Sign: SignUpdate_internal failed with error code %d", res);
        return res;
    }

    return Sign_internal(session, pSignature, pulSignatureLen);
}

CK_RV CK_SPEC C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pCount)
{
    debug("C_GetSlotList called");
    if (!pCount) {
        return CKR_ARGUMENTS_BAD;
    }

    auto slots = getSlots();

    *pCount = slots.size();

    if (!pSlotList) {
        return CKR_OK;
    }

    if (*pCount < slots.size()) {
        return CKR_BUFFER_TOO_SMALL;
    }

    for (size_t i = 0; i < slots.size(); ++i) {
        pSlotList[i] = i;
    }
    return CKR_OK;
}

CK_RV CK_SPEC C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pSlotInfo)
{
    debug("C_GetSlotInfo called");

    if (pSlotInfo == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }

    auto slots = getSlots();
    if (slotID >= slots.size()) {
        return CKR_SLOT_ID_INVALID;
    }

    auto& slot = slots[slotID];
    if (slot.empty()) { // empty when no certificate file provided
        *pSlotInfo = {};
        return CKR_OK;
    }

    *pSlotInfo = { {}, {}, CKF_TOKEN_PRESENT, {}, {} };
    auto descLen = std::min(sizeof(pSlotInfo->slotDescription), slot.size());
    memcpy(pSlotInfo->slotDescription, slot.c_str() + slot.length() - descLen, descLen);

    return CKR_OK;
}

CK_RV CK_SPEC C_Initialize(CK_VOID_PTR pInitArgs)
{
    debug("C_Initialize called");

    static bool initialized = false;
    if (initialized) {
        debug("  already initialized");
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    initialized = true;

    if (!debug_enabled) {
        const char* debug_env_var = getenv("P2C_DEBUG");
        if (debug_env_var != nullptr) {
            debug_enabled = std::string(debug_env_var) == "1" || std::string(debug_env_var) == "true"
                || std::string(debug_env_var) == "yes";
            if (debug_enabled) {
                debug("Debug is enabled via environment variable P2C_DEBUG=%s", debug_env_var);
            } else {
                debug("Debug is disabled via environment variable P2C_DEBUG=%s", debug_env_var);
            }
        }
    }

    return CKR_OK;
}

static CK_RV extractKeyAttributeValue(
    Session& session, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen, object_type object);

static CK_RV extractCommonAttributeValue(
    Session& session, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pDestValue, CK_ULONG_PTR pValueDestLen)
{
    switch (attr) {
    case CKA_TOKEN: {
        return copy_safe<CK_BBOOL>(pDestValue, pValueDestLen, CK_TRUE);
    }

    case CKA_ID: {
        auto idBytes = significantBytes(session.slotID);
        return copy_safe_(pDestValue, pValueDestLen, idBytes.data(), idBytes.size());
    }

    case CKA_LABEL: {
        auto label = std::string(PROVIDER_NAME) + "-" + std::to_string(session.slotID);
        return copy_safe_(pDestValue, pValueDestLen, label.c_str(), label.length());
    }
    case CKA_MODULUS:
    case CKA_PUBLIC_EXPONENT:
    case CKA_EC_POINT:
    case CKA_EC_PARAMS:
    case CKA_KEY_TYPE: {
        return extractKeyAttributeValue(session, attr, pDestValue, pValueDestLen, object_type::public_key);
    }
    default: {
        *pValueDestLen = CK_UNAVAILABLE_INFORMATION;
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
    }
    return CKR_OK;
}

static CK_RV copyBNAttribute(unsigned char* pDest, CK_ULONG_PTR pulDestLen, const BIGNUM* bn)
{
    CK_ULONG bnLen = BN_num_bytes(bn);

    if (pulDestLen == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }
    if (pDest == nullptr) {
        *pulDestLen = bnLen;
        return CKR_OK;
    }
    if (*pulDestLen < bnLen) {
        *pulDestLen = CK_UNAVAILABLE_INFORMATION;
        return CKR_BUFFER_TOO_SMALL;
    }
    BN_bn2bin(bn, pDest);
    *pulDestLen = bnLen;

    return CKR_OK;
}

static CK_RV extractKeyAttributeValue(
    Session& session, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValueDest, CK_ULONG_PTR pValueDestLen, object_type object)
{
    switch (attr) {
    case CKA_CLASS: {
        CK_OBJECT_CLASS obj_class =
            // rauc signing fails when following is used
            // object == object_type::private_key ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
            CKO_PRIVATE_KEY;
        return copy_safe(pValueDest, pValueDestLen, obj_class);
    }

    case CKA_SENSITIVE: {
        return copy_safe<CK_BBOOL>(pValueDest, pValueDestLen, CK_TRUE);
    }

    case CKA_EXTRACTABLE: {
        return copy_safe<CK_BBOOL>(pValueDest, pValueDestLen, object == object_type::private_key ? CK_FALSE : CK_TRUE);
    }

    case CKA_SIGN: {
        return copy_safe<CK_BBOOL>(pValueDest, pValueDestLen, CK_TRUE);
    }

    case CKA_KEY_TYPE: {
        auto pkey = session.getPublicKey();

        if (pkey == nullptr) {
            return CKR_FUNCTION_FAILED;
        }

        CK_OBJECT_CLASS key_type;
        switch (EVP_PKEY_base_id(pkey.get())) {
        case EVP_PKEY_RSA:
            key_type = CKK_RSA;
            break;
        case EVP_PKEY_EC:
            key_type = CKK_ECDSA;
            break;
        default:
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }
        return copy_safe(pValueDest, pValueDestLen, key_type);
    }

    case CKA_ALWAYS_AUTHENTICATE: {
        return copy_safe<CK_BBOOL>(pValueDest, pValueDestLen, CK_FALSE);
    }

    case CKA_MODULUS:
    case CKA_PUBLIC_EXPONENT: {
        auto pkey = session.getPublicKey();
        if (pkey == nullptr) {
            return CKR_FUNCTION_FAILED;
        }
        if (EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_RSA) {
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }
        BIGNUM* bn = nullptr;
        auto bn_param = (attr == CKA_MODULUS) ? OSSL_PKEY_PARAM_RSA_N : OSSL_PKEY_PARAM_RSA_E;
        if (!EVP_PKEY_get_bn_param(pkey.get(), bn_param, &bn)) {
            return CKR_FUNCTION_FAILED;
        }

        CK_RV ret = copyBNAttribute((unsigned char*)pValueDest, pValueDestLen, bn);
        BN_free(bn);
        return ret;
    }

    case CKA_EC_POINT: {
        auto pkey = session.getPublicKey();
        if (pkey == nullptr) {
            return CKR_FUNCTION_FAILED;
        }
        if (EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_EC) {
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }

        size_t len = 0;
        if (!EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &len)) {
            return CKR_FUNCTION_FAILED;
        }

        auto buffer = std::shared_ptr<unsigned char>(new unsigned char[len], std::default_delete<unsigned char[]>());
        if (!EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PUB_KEY, buffer.get(), len, &len)) {
            return CKR_FUNCTION_FAILED;
        }

        auto os = std::shared_ptr<ASN1_OCTET_STRING>(ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free);

        ASN1_OCTET_STRING_set(os.get(), buffer.get(), len);

        return read_safe(i2d_ASN1_OCTET_STRING, os.get(), pValueDest, pValueDestLen);
    }

    case CKA_EC_PARAMS: {
        auto pkey = session.getPublicKey();
        if (pkey == nullptr) {
            return CKR_FUNCTION_FAILED;
        }
        if (EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_EC) {
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }

        char group_name[256];
        size_t group_name_len = sizeof(group_name);
        if (!EVP_PKEY_get_utf8_string_param(
                pkey.get(), OSSL_PKEY_PARAM_GROUP_NAME, group_name, sizeof(group_name), &group_name_len)) {
            return CKR_FUNCTION_FAILED;
        }

        auto group = std::shared_ptr<EC_GROUP>(EC_GROUP_new_by_curve_name(OBJ_txt2nid(group_name)), EC_GROUP_free);
        if (!group) {
            return CKR_FUNCTION_FAILED;
        }

        return read_safe(i2d_ECPKParameters, group.get(), pValueDest, pValueDestLen);
    }
    default:
        return extractCommonAttributeValue(session, attr, pValueDest, pValueDestLen);
    }

    return CKR_OK;
}

static CK_RV extractCertificateAttributeValue(
    Session& session, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pValueLen)
{
    const X509* cert = session.slotCertificate.get();

    switch (attr) {
    case CKA_CLASS: {
        return copy_safe(pValue, pValueLen, CKO_CERTIFICATE);
    }

    case CKA_PRIVATE: {
        return copy_safe<CK_BBOOL>(pValue, pValueLen, CK_FALSE);
    }

    case CKA_CERTIFICATE_TYPE: {
        CK_ULONG type = CKC_X_509;
        return copy_safe(pValue, pValueLen, type);
    }

    case CKA_MODIFIABLE: {
        return copy_safe<CK_BBOOL>(pValue, pValueLen, CK_FALSE);
    }

    case CKA_TRUSTED: {
        return copy_safe<CK_BBOOL>(pValue, pValueLen, CK_FALSE);
    }

    case CKA_SUBJECT:
        return read_safe(i2d_X509_NAME, X509_get_subject_name(cert), pValue, pValueLen);

    case CKA_ISSUER:
        return read_safe(i2d_X509_NAME, X509_get_issuer_name(cert), pValue, pValueLen);

    case CKA_SERIAL_NUMBER:
        return read_safe(i2d_ASN1_INTEGER, X509_get0_serialNumber(cert), pValue, pValueLen);

    case CKA_VALUE:
        return read_safe(i2d_X509, cert, pValue, pValueLen);
    default:
        return extractCommonAttributeValue(session, attr, pValue, pValueLen);
    }
    return CKR_OK;
}

static CK_RV extractAttributeForObject(
    Session& session, object_type object, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen)
{
    switch (object) {
    case object_type::public_key:
    case object_type::private_key: {
        return extractKeyAttributeValue(session, attr, pValue, pulValueLen, object);
    }
    case object_type::certificate: {
        return extractCertificateAttributeValue(session, attr, pValue, pulValueLen);
    }
    default:
        break;
    }

    return CKR_OBJECT_HANDLE_INVALID;
}

CK_RV CK_SPEC C_GetAttributeValue(
    CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pAttributes, CK_ULONG ulCount)
{
    debug("C_GetAttributeValue called");
    auto ptr = Session::From(hSession);
    if (!ptr) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!pAttributes || ulCount == 0) {
        return CKR_ARGUMENTS_BAD;
    }

    Session& session = *ptr;

    auto it = valid_object_types.find(hObject);
    if (it == valid_object_types.end()) {
        debug("C_GetAttributeValue: Invalid object handle %lu", hObject);
        return CKR_OBJECT_HANDLE_INVALID;
    }

    auto object = *it;

    if (session.foundObjects.find(object) == session.foundObjects.end()) {
        debug("C_GetAttributeValue: Invalid object %lu", object);
        return CKR_OBJECT_HANDLE_INVALID;
    }

    for (CK_ULONG i = 0; i < ulCount; i++) {
        auto& attr = pAttributes[i];
        debug("C_GetAttributeValue: Getting attribute type=%#lx for object=%lu", attr.type, hObject);
        CK_RV res = extractAttributeForObject(session, object, attr.type, attr.pValue, &attr.ulValueLen);
        if (res != CKR_OK) {
            debug("C_GetAttributeValue: Failed to find attribute type=%#lx for object=%lu", attr.type, hObject);
            return res;
        }
    }
    return CKR_OK;
}

static bool matches(
    Session& session, object_type object, CK_ATTRIBUTE_PTR findObjectsTemplate, CK_ULONG findObjectsTemplateCount)
{
    for (CK_ULONG i = 0; i < findObjectsTemplateCount; i++) {
        auto attr = findObjectsTemplate[i];

        if (attr.type == CKA_CLASS) {
            CK_OBJECT_CLASS* match = (CK_OBJECT_CLASS*)attr.pValue;
            if (*match == CKO_PUBLIC_KEY || *match == CKO_PRIVATE_KEY) {
                continue;
            }
        }

        CK_ULONG buffer_size = 0;

        auto res = extractAttributeForObject(session, object, attr.type, nullptr, &buffer_size);

        if (res != CKR_OK) {
            return false;
        }

        if (buffer_size != attr.ulValueLen) {
            debug("  Object %d has attribute %#lx with size %lu, "
                  "but template expects size %lu",
                object, attr.type, buffer_size, attr.ulValueLen);
            return false;
        }

        std::shared_ptr<unsigned char> buffer(new unsigned char[buffer_size], std::default_delete<unsigned char[]>());

        res = extractAttributeForObject(session, object, attr.type, buffer.get(), &buffer_size);
        if (res != CKR_OK) {
            return false;
        }

        // Compare the attribute value with the template value
        if (memcmp(buffer.get(), attr.pValue, buffer_size) != 0) {
            debug("  Object %d does not match template attribute %#lx", object, attr.type);
            return false;
        }
    }
    return true;
}

CK_RV CK_SPEC C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplates, CK_ULONG ulCount)
{
    debug("C_FindObjectsInit called");
    auto ptr = Session::From(hSession);
    if (!ptr) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    Session& session = *ptr;

    session.foundObjects.clear();

    if (ulCount == 0) {
        // PKCS#11 specification: "To find all objects, set ulCount to 0."
        session.foundObjects.insert(valid_object_types.begin(), valid_object_types.end());
    } else if (pTemplates != nullptr) {
        for (auto object : valid_object_types) {
            if (matches(session, object, pTemplates, ulCount)) {
                session.foundObjects.insert(object);
            }
        }
    }

    session.currentObjectIt = session.foundObjects.begin();

    return CKR_OK;
}

CK_RV CK_SPEC C_FindObjects(
    CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR pObjects, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    debug("C_FindObjects called");
    auto ptr = Session::From(hSession);
    if (!ptr) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    Session& session = *ptr;

    if (!pObjects || !pulObjectCount) {
        return CKR_ARGUMENTS_BAD;
    }

    size_t found_objects = 0;
    while (found_objects < ulMaxObjectCount && session.currentObjectIt != session.foundObjects.end()) {
        pObjects[found_objects] = *session.currentObjectIt;
        found_objects++;
        session.currentObjectIt++;
    }

    *pulObjectCount = found_objects;
    return CKR_OK;
}

CK_RV CK_SPEC C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    debug("C_FindObjectsFinal called");
    return CKR_OK;
}

CK_RV CK_SPEC C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pTokenInfo)
{
    debug("C_GetTokenInfo called");
    if (!pTokenInfo) {
        return CKR_ARGUMENTS_BAD;
    }

    auto slots = getSlots();

    if (slotID >= slots.size()) {
        return CKR_SLOT_ID_INVALID;
    }

    *pTokenInfo = {};

    auto slot = slots[slotID];
    auto labelLen = std::min(sizeof(pTokenInfo->label), slot.length());

    strncpy((char*)pTokenInfo->label, (std::string(PROVIDER_NAME) + "-" + std::to_string(slotID)).c_str(),
        sizeof(pTokenInfo->label));
    strncpy((char*)pTokenInfo->manufacturerID, PROVIDER_NAME, sizeof(pTokenInfo->manufacturerID));
    strncpy((char*)pTokenInfo->model, "sw", sizeof(pTokenInfo->model));
    strncpy(
        (char*)pTokenInfo->serialNumber, ("sn-" + std::to_string(slotID)).c_str(), sizeof(pTokenInfo->serialNumber));

    pTokenInfo->flags = CKF_TOKEN_INITIALIZED;
    pTokenInfo->ulMaxSessionCount = 1; // simplify code by allowing only 1 session
    pTokenInfo->ulSessionCount = 1;
    pTokenInfo->ulMaxRwSessionCount = 1;
    pTokenInfo->ulRwSessionCount = 1;
    pTokenInfo->ulMaxPinLen = 0;
    pTokenInfo->ulMinPinLen = 0;
    pTokenInfo->ulTotalPublicMemory = 0;
    pTokenInfo->ulFreePublicMemory = 0;
    pTokenInfo->ulTotalPrivateMemory = 0;
    pTokenInfo->ulFreePrivateMemory = 0;
    pTokenInfo->hardwareVersion.major = 1;
    pTokenInfo->hardwareVersion.minor = 0;
    pTokenInfo->firmwareVersion.major = 1;
    pTokenInfo->firmwareVersion.minor = 0;
    return CKR_OK;
}

CK_RV CK_SPEC C_CloseAllSessions(CK_SLOT_ID slotID)
{
    debug("C_CloseAllSessions called");
    return CKR_OK;
}

CK_RV CK_SPEC C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    static CK_FUNCTION_LIST functionList = { { 2, 40 }, C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList,
        C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, blind_C_GetMechanismList, blind_C_GetMechanismInfo,
        blind_C_InitToken, blind_C_InitPIN, blind_C_SetPIN, C_OpenSession, C_CloseSession, blind_C_CloseAllSessions,
        blind_C_GetSessionInfo, blind_C_GetOperationState, blind_C_SetOperationState, C_Login, C_Logout,
        blind_C_CreateObject, blind_C_CopyObject, blind_C_DestroyObject, blind_C_GetObjectSize, C_GetAttributeValue,
        blind_C_SetAttributeValue, C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal, blind_C_EncryptInit,
        blind_C_Encrypt, blind_C_EncryptUpdate, blind_C_EncryptFinal, blind_C_DecryptInit, blind_C_Decrypt,
        blind_C_DecryptUpdate, blind_C_DecryptFinal, blind_C_DigestInit, blind_C_Digest, blind_C_DigestUpdate,
        blind_C_DigestKey, blind_C_DigestFinal, C_SignInit, C_Sign, C_SignUpdate, C_SignFinal, blind_C_SignRecoverInit,
        blind_C_SignRecover, blind_C_VerifyInit, blind_C_Verify, blind_C_VerifyUpdate, blind_C_VerifyFinal,
        blind_C_VerifyRecoverInit, blind_C_VerifyRecover, blind_C_DigestEncryptUpdate, blind_C_DecryptDigestUpdate,
        blind_C_SignEncryptUpdate, blind_C_DecryptVerifyUpdate, blind_C_GenerateKey, blind_C_GenerateKeyPair,
        blind_C_WrapKey, blind_C_UnwrapKey, blind_C_DeriveKey, blind_C_SeedRandom, blind_C_GenerateRandom,
        blind_C_GetFunctionStatus, blind_C_CancelFunction, blind_C_WaitForSlotEvent };

    debug("C_GetFunctionList called");
    if (!ppFunctionList) {
        return CKR_ARGUMENTS_BAD;
    }

    *ppFunctionList = &functionList;
    return CKR_OK;
}
}
