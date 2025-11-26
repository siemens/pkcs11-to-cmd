/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 *   Eugen Kremer <eugen.kremer@siemens.com>
 */

#pragma once

#include "debug.hpp"

#define CRYPTOKI_EXPORTS
#include <p11-kit/pkcs11.h>

extern "C" {
// LCOV_EXCL_START
// --- PKCS#11 dummy implementations for all functions ---
#define BLIND_FUNC_IMPL(name, ...)                                                                                     \
    CK_RV CK_SPEC blind_##name(__VA_ARGS__)                                                                            \
    {                                                                                                                  \
        debug("blind_" #name " called");                                                                               \
        return CKR_FUNCTION_NOT_SUPPORTED;                                                                             \
    }

BLIND_FUNC_IMPL(C_GetMechanismList, CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
BLIND_FUNC_IMPL(C_GetMechanismInfo, CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
BLIND_FUNC_IMPL(C_InitToken, CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
BLIND_FUNC_IMPL(C_InitPIN, CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
BLIND_FUNC_IMPL(C_SetPIN, CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
    CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
BLIND_FUNC_IMPL(C_CloseAllSessions, CK_SLOT_ID slotID)
BLIND_FUNC_IMPL(C_GetSessionInfo, CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
BLIND_FUNC_IMPL(
    C_GetOperationState, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
BLIND_FUNC_IMPL(C_SetOperationState, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
    CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
BLIND_FUNC_IMPL(C_CreateObject, CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phObject)
BLIND_FUNC_IMPL(C_CopyObject, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
BLIND_FUNC_IMPL(C_DestroyObject, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
BLIND_FUNC_IMPL(C_GetObjectSize, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
BLIND_FUNC_IMPL(C_SetAttributeValue, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
BLIND_FUNC_IMPL(C_EncryptInit, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
BLIND_FUNC_IMPL(C_Encrypt, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
BLIND_FUNC_IMPL(C_EncryptUpdate, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
BLIND_FUNC_IMPL(
    C_EncryptFinal, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
BLIND_FUNC_IMPL(C_DecryptInit, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
BLIND_FUNC_IMPL(C_Decrypt, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
    CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
BLIND_FUNC_IMPL(C_DecryptUpdate, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
BLIND_FUNC_IMPL(C_DecryptFinal, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
BLIND_FUNC_IMPL(C_DigestInit, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
BLIND_FUNC_IMPL(C_Digest, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
    CK_ULONG_PTR pulDigestLen)
BLIND_FUNC_IMPL(C_DigestUpdate, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
BLIND_FUNC_IMPL(C_DigestKey, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
BLIND_FUNC_IMPL(C_DigestFinal, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
BLIND_FUNC_IMPL(C_SignUpdate, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
BLIND_FUNC_IMPL(C_SignFinal, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
BLIND_FUNC_IMPL(C_SignRecoverInit, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
BLIND_FUNC_IMPL(C_SignRecover, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
BLIND_FUNC_IMPL(C_VerifyInit, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
BLIND_FUNC_IMPL(C_Verify, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
BLIND_FUNC_IMPL(C_VerifyUpdate, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
BLIND_FUNC_IMPL(C_VerifyFinal, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
BLIND_FUNC_IMPL(C_VerifyRecoverInit, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
BLIND_FUNC_IMPL(C_VerifyRecover, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
    CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
BLIND_FUNC_IMPL(C_DigestEncryptUpdate, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
BLIND_FUNC_IMPL(C_DecryptDigestUpdate, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
BLIND_FUNC_IMPL(C_SignEncryptUpdate, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
BLIND_FUNC_IMPL(C_DecryptVerifyUpdate, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
BLIND_FUNC_IMPL(C_GenerateKey, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
BLIND_FUNC_IMPL(C_GenerateKeyPair, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
    CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
BLIND_FUNC_IMPL(C_WrapKey, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey,
    CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
BLIND_FUNC_IMPL(C_UnwrapKey, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey,
    CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
    CK_OBJECT_HANDLE_PTR phKey)
BLIND_FUNC_IMPL(C_DeriveKey, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
BLIND_FUNC_IMPL(C_SeedRandom, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
BLIND_FUNC_IMPL(C_GenerateRandom, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
BLIND_FUNC_IMPL(C_GetFunctionStatus, CK_SESSION_HANDLE hSession)
BLIND_FUNC_IMPL(C_CancelFunction, CK_SESSION_HANDLE hSession)
BLIND_FUNC_IMPL(C_WaitForSlotEvent, CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
// LCOV_EXCL_STOP
}
