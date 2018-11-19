/**
 * @file hestd.h -- HomomorphicEncryption.org API implementation
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2018, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SRC_PKE_LIB_HESTD_H_
#define SRC_PKE_LIB_HESTD_H_

#include <iostream>
#include <fstream>
#include "cryptocontext.h"
#include "palisade.h"
#include "cryptocontexthelper.h"
#include "utils/exception.h"

namespace hestd
{
    namespace palisade = lbcrypto;

    using Ciphertext = palisade::Ciphertext<palisade::DCRTPoly>;
    using ConstCiphertext = palisade::ConstCiphertext<palisade::DCRTPoly>;
    using Plaintext = palisade::Plaintext;
    using ConstPlaintext = palisade::ConstPlaintext;

    class HEStdContext
    {
    public:
        /**
        Context class instances should be created using readContext and
        createContextFromProfile functions.
        */
        HEStdContext() = delete;
        HEStdContext(const HEStdContext &) = delete;
        HEStdContext(HEStdContext &&) = default;
        HEStdContext &operator =(const HEStdContext &) = delete;
        HEStdContext &operator =(HEStdContext &&) = default;
		
		HEStdContext(std::ifstream &stream, const string &userProfile) {

	    	palisade::Serialized	ccSer;

	    	if (palisade::SerializableHelper::StreamToSerialization(stream, &ccSer) == false) {
				PALISADE_THROW( palisade::serialize_error, "Could not read the cryptocontext file" );
			}

			m_cc = palisade::CryptoContextFactory<palisade::DCRTPoly>::DeserializeAndCreateContext(ccSer);

		}

        /**
        Generate public and secret key (depending on mode: symmetric or asymmetric)
        */
        void keyGen() {

        	// Generate a public and private key
        	m_kp = m_cc->KeyGen();

        	// Generate relinearization key(s)
        	m_cc->EvalMultKeyGen(m_kp.secretKey);

        	// Generate evalmult keys for summation
        	m_cc->EvalSumKeyGen(m_kp.secretKey);

        	m_cc->EvalAtIndexKeyGen(m_kp.secretKey,{1,2,3});

        }

        /**
        Read and write secret key.
        */
        void readSK(std::ifstream &stream) {

    		palisade::Serialized	skSer;
    		if (palisade::SerializableHelper::StreamToSerialization(stream, &skSer) == false) {
    			cerr << "Could not read secret key" << endl;
    			return;
    		}

    		m_kp.secretKey = m_cc->deserializeSecretKey(skSer);

        }

        void writeSK(std::ofstream &stream) {

        	palisade::Serialized privK;

			if (m_kp.secretKey->Serialize(&privK)) {
				if (!palisade::SerializableHelper::SerializationToStream(privK, stream)) {
					cerr << "Error writing serialization of private key." << endl;
					return;
				}
			}
			else {
				cerr << "Error serializing private key" << endl;
				return;
			}
        }

        void readPK(std::ifstream &stream) {

    		palisade::Serialized	pkSer;
    		if (palisade::SerializableHelper::StreamToSerialization(stream, &pkSer) == false) {
    			cerr << "Could not read public key" << endl;
    			return;
    		}

    		m_kp.publicKey = m_cc->deserializePublicKey(pkSer);


        }

        void writePK(std::ofstream &stream) {

        	palisade::Serialized pubK;

			if (m_kp.publicKey->Serialize(&pubK)) {
				if (!palisade::SerializableHelper::SerializationToStream(pubK, stream)) {
					cerr << "Error writing serialization of public key." << endl;
					return;
				}
			}
			else {
				cerr << "Error serializing public key" << endl;
				return;
			}

        }

        /**
        Read and write ciphertext.
        */
        void readCiphertext(std::ifstream &stream, Ciphertext ctxt) {

    		palisade::Serialized	ser;
    		if (palisade::SerializableHelper::StreamToSerialization(stream, &ser) == false) {
    			cerr << "Could not read ciphertext" << endl;
    			return;
    		}

    		if (!ctxt->Deserialize(ser)) {
    			cerr << "Could not deserialize ciphertext" << endl;
    			return;
    		}

        }

        void writeCiphertext(ConstCiphertext ctxt, std::ofstream &stream) {

        	palisade::Serialized ser;

			if (ctxt->Serialize(&ser)) {
				if (!palisade::SerializableHelper::SerializationToStream(ser, stream)) {
					cerr << "Error writing serialization of ciphertext." << endl;
					return;
				}
			}
			else {
				cerr << "Error serializing ciphertext." << endl;
				return;
			}

        }

        /**
        Read and write plaintext.
        */
        void readPlaintext(std::ifstream &stream, Plaintext ptxt);
        void writePlaintext(ConstCiphertext ptxt, std::ofstream stream);

        /**
        Encryption and decryption.
        */
        void encrypt(Plaintext ptxtIn, Ciphertext ctxtOut) {
        	*ctxtOut = *(m_cc->Encrypt(m_kp.publicKey,ptxtIn));
        	return;
        }

        void decrypt(ConstCiphertext ctxtIn, Plaintext &ptxtOut) {
        	m_cc->Decrypt(m_kp.secretKey,ctxtIn,&ptxtOut);
        	return;
        }

        /**
        Homomorphic computations.
        */
        void evalAdd(ConstCiphertext ctxtIn1, ConstCiphertext ctxtIn2, Ciphertext ctxtOut) {
        	*ctxtOut = *(m_cc->EvalAdd(ctxtIn1,ctxtIn2));
        	return;
        }

        void evalAddInplace(Ciphertext ctxtIn1, ConstCiphertext ctxtIn2) {
        	*ctxtIn1 = *(m_cc->EvalAdd(ctxtIn1,ctxtIn2));
        	return;
        }

        void evalAdd(ConstCiphertext ctxtIn1, ConstPlaintext ptxtIn2,  Ciphertext ctxtOut) {
        	*ctxtOut = *(m_cc->EvalAdd(ctxtIn1,ptxtIn2));
        	return;
        }

        void evalAddInplace(Ciphertext ctxtIn1, ConstPlaintext ptxtIn2) {
        	*ctxtIn1 = *(m_cc->EvalAdd(ctxtIn1,ptxtIn2));
        	return;
        }

        void evalSub(ConstCiphertext ctxtIn1, ConstCiphertext ctxtIn2, Ciphertext ctxtOut) {
        	*ctxtOut = *(m_cc->EvalSub(ctxtIn1,ctxtIn2));
        	return;
        }

        void evalSubInplace(Ciphertext ctxtIn1, ConstCiphertext ctxtIn2) {
        	*ctxtIn1 = *(m_cc->EvalSub(ctxtIn1,ctxtIn2));
        	return;
        }

        void evalSub(ConstCiphertext ctxtIn1, ConstPlaintext ptxtIn2,  Ciphertext ctxtOut) {
        	*ctxtOut = *(m_cc->EvalSub(ctxtIn1,ptxtIn2));
        	return;
        }

        void evalSubInplace(Ciphertext ctxtIn1, ConstPlaintext ptxtIn2) {
        	*ctxtIn1 = *(m_cc->EvalSub(ctxtIn1,ptxtIn2));
        	return;
        }

        void evalNeg(ConstCiphertext ctxtIn,  Ciphertext ctxtOut) {
        	*ctxtOut = *(m_cc->EvalNegate(ctxtIn));
        	return;
        }

        void evalNegInplace(Ciphertext ctxtIn) {
        	*ctxtIn = *(m_cc->EvalNegate(ctxtIn));
        	return;
        }

        void evalMul(ConstCiphertext ctxtIn1, ConstCiphertext ctxtIn2, Ciphertext ctxtOut) {
        	*ctxtOut = *(m_cc->EvalMult(ctxtIn1,ctxtIn2));
        	return;
        }

        void evalMulInplace(Ciphertext ctxtIn1, ConstCiphertext ctxtIn2) {
        	*ctxtIn1 = *(m_cc->EvalMult(ctxtIn1,ctxtIn2));
        	return;
        }

        void evalMul(ConstCiphertext ctxtIn1, ConstPlaintext ptxtIn2,  Ciphertext ctxtOut) {
        	*ctxtOut = *(m_cc->EvalMult(ctxtIn1,ptxtIn2));
        	return;
        }

        void evalMulInplace(Ciphertext ctxtIn1, ConstPlaintext ptxtIn2) {
        	*ctxtIn1 = *(m_cc->EvalMult(ctxtIn1,ptxtIn2));
        	return;
        }

        //Special functions (temporarily added)

        Ciphertext CreateCiphertext() {
        	return Ciphertext(new palisade::CiphertextImpl<palisade::DCRTPoly>(m_cc));
        }

        Plaintext CreatePlaintext() {
        	return Plaintext(new palisade::PackedEncoding( m_cc->GetElementParams(), m_cc->GetEncodingParams(), {} ) );
        }

        Plaintext CreatePlaintext(const vector<uint64_t>& value) const {
        	return m_cc->MakePackedPlaintext(value);
        }

    private:
        palisade::CryptoContext<palisade::DCRTPoly> m_cc;
        palisade::LPKeyPair<palisade::DCRTPoly> m_kp;
    };

}

#endif /* SRC_PKE_LIB_HESTD_H_ */
