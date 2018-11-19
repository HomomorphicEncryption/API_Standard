#pragma once

#include <memory>
#include <fstream>
#include <utility>
#include <string>

// SEAL includes
#include "seal/context.h"
#include "seal/ciphertext.h"
#include "seal/plaintext.h"
#include "seal/evaluator.h"
#include "seal/encryptor.h"
#include "seal/decryptor.h"
#include "seal/evaluator.h"
#include "seal/keygenerator.h"

namespace hestd
{
    using Plaintext = std::shared_ptr<seal::Plaintext>;
    using Ciphertext = std::shared_ptr<seal::Ciphertext>;
    using ConstPlaintext = const std::shared_ptr<const seal::Plaintext>;
    using ConstCiphertext = const std::shared_ptr<const seal::Ciphertext>;

    class HEStdContext
    {
    public:
        /**
        Creating a context from configuration profile
        */
        HEStdContext(std::ifstream &stream, std::string profile_id);

        HEStdContext(const HEStdContext &) = delete;
        HEStdContext(HEStdContext &&) = default;
        HEStdContext &operator =(const HEStdContext &) = delete;
        HEStdContext &operator =(HEStdContext &&) = default;

        /*
        Non-standard constructor
        */
        HEStdContext(const seal::EncryptionParameters &parms) :
            context_(seal::SEALContext::Create(parms)),
            evaluator_(new seal::Evaluator(context_))
        {
            if (parms.scheme() != seal::scheme_type::BFV)
            {
                throw std::invalid_argument("non-standard scheme");
            }
            if (!context_->parameters_set())
            {
                throw std::invalid_argument("invalid parameters");
            }

            // The relinearization profile should be read from the config
            // profile, but here we just set it.
            rlprof_.reset(new RelinProfile);
            rlprof_->style = RelinStyle::ALWAYS;

            // Note that we still don't have the keys but `style` tells the
            // keyGen to generate the keys.
            rlprof_->rlk = nullptr;

            // This indicates the desired decomposition bit count; also to
            // be read from configuration profile
            rlprof_->dbc = 60;
        }

        /**
        Generate public and secret key according to configuration profile.
        */
        void keyGen()
        {
            seal::KeyGenerator keygen(context_);
            sk_.reset(new seal::SecretKey);
            pk_.reset(new seal::PublicKey);
            *sk_ = keygen.secret_key();
            *pk_ = keygen.public_key();
            encryptor_.reset(new seal::Encryptor(context_, *pk_));
            decryptor_.reset(new seal::Decryptor(context_, *sk_));

            switch (rlprof_->style)
            {
            case RelinStyle::NEVER:
                break;

            case RelinStyle::ALWAYS:
                rlprof_->rlk.reset(new seal::RelinKeys(keygen.relin_keys(rlprof_->dbc)));
                break;

            default:
                throw std::runtime_error("invalid relinearization style");
            }
        }

        /**
        Read and write secret key.
        */
        void readSK(std::ifstream &stream)
        {
            sk_->load(stream);
            decryptor_.reset(new seal::Decryptor(context_, *sk_));
        }

        void writeSK(std::ofstream &stream)
        {
            sk_->save(stream);
        }

        void readPK(std::ifstream &stream)
        {
            pk_->load(stream);
            encryptor_.reset(new seal::Encryptor(context_, *pk_));

            std::unique_ptr<seal::RelinKeys> rlk(new seal::RelinKeys);
            rlk->load(stream);
            if (rlk->decomposition_bit_count() != rlprof_->dbc)
            {
                throw std::runtime_error("dbc mismatch");
            }
            rlprof_->rlk.swap(rlk);
        }

        void writePK(std::ofstream &stream)
        {
            pk_->save(stream);
            rlprof_->rlk->save(stream);
        }

        /**
        Read and write ciphertext.
        */
        void readCiphertext(std::ifstream &stream, Ciphertext ctxt)
        {
            ctxt->load(stream);
        }

        void writeCiphertext(ConstCiphertext ctxt, std::ofstream &stream)
        {
            ctxt->save(stream);
        }

        /**
        Read and write plaintext.
        */
        void readPlaintext(std::ifstream &stream, Plaintext ptxt)
        {
            ptxt->load(stream);
        }

        void writePlaintext(ConstPlaintext ptxt, std::ofstream stream)
        {
            ptxt->save(stream);
        }

        /**
        Encryption and decryption.
        */
        void encrypt(ConstPlaintext ptxtIn, Ciphertext ctxtOut)
        {
            encryptor_->encrypt(*ptxtIn, *ctxtOut);
        }

        void decrypt(ConstCiphertext ctxtIn, Plaintext ptxtOut)
        {
            decryptor_->decrypt(*ctxtIn, *ptxtOut);
        }

        /**
        Homomorphic computations.
        */
        void evalAdd(ConstCiphertext ctxtIn1, ConstCiphertext ctxtIn2, Ciphertext ctxtOut)
        {
            evaluator_->add(*ctxtIn1, *ctxtIn2, *ctxtOut);
        }

        void evalAddInplace(Ciphertext ctxtIn1, ConstCiphertext ctxtIn2)
        {
            evaluator_->add_inplace(*ctxtIn1, *ctxtIn2);
        }

        void evalAdd(ConstCiphertext ctxtIn1, ConstPlaintext ptxtIn2, Ciphertext ctxtOut)
        {
            evaluator_->add_plain(*ctxtIn1, *ptxtIn2, *ctxtOut);
        }

        void evalAddInplace(Ciphertext ctxtIn1, ConstPlaintext ptxtIn2)
        {
            evaluator_->add_plain_inplace(*ctxtIn1, *ptxtIn2);
        }

        void evalSub(ConstCiphertext ctxtIn1, ConstCiphertext ctxtIn2, Ciphertext ctxtOut)
        {
            evaluator_->sub(*ctxtIn1, *ctxtIn2, *ctxtOut);
        }

        void evalSubInplace(Ciphertext ctxtIn1, ConstCiphertext ctxtIn2)
        {
            evaluator_->sub_inplace(*ctxtIn1, *ctxtIn2);
        }

        void evalSub(ConstCiphertext ctxtIn1, ConstPlaintext ptxtIn2, Ciphertext ctxtOut)
        {
            evaluator_->sub_plain(*ctxtIn1, *ptxtIn2, *ctxtOut);

        }

        void evalSubInplace(Ciphertext ctxtIn1, ConstPlaintext ptxtIn2)
        {
            evaluator_->sub_plain_inplace(*ctxtIn1, *ptxtIn2);
        }

        void evalNeg(ConstCiphertext ctxtIn, Ciphertext ctxtOut)
        {
            evaluator_->negate(*ctxtIn, *ctxtOut);
        }

        void evalNegInplace(Ciphertext ctxtIn)
        {
            evaluator_->negate_inplace(*ctxtIn);
        }

        void evalMul(ConstCiphertext ctxtIn1, ConstCiphertext ctxtIn2, Ciphertext ctxtOut)
        {
            if (&*ctxtIn1 == &*ctxtIn2)
            {
                evaluator_->square(*ctxtIn1, *ctxtOut);
            }
            else
            {
                evaluator_->multiply(*ctxtIn1, *ctxtIn2, *ctxtOut);
            }
            evalRelinInplace(ctxtOut);
        }

        void evalMulInplace(Ciphertext ctxtIn1, ConstCiphertext ctxtIn2)
        {
            if (&*ctxtIn1 == &*ctxtIn2)
            {
                evaluator_->square_inplace(*ctxtIn1);
            }
            else
            {
                evaluator_->multiply_inplace(*ctxtIn1, *ctxtIn2);
            }
            evalRelinInplace(ctxtIn1);
        }

        void evalMul(ConstCiphertext ctxtIn1, ConstPlaintext ptxtIn2, Ciphertext ctxtOut)
        {
            evaluator_->multiply_plain(*ctxtIn1, *ptxtIn2, *ctxtOut);
        }

        void evalMulInplace(Ciphertext ctxtIn1, ConstPlaintext ptxtIn2)
        {
            evaluator_->multiply_plain_inplace(*ctxtIn1, *ptxtIn2);
        }

        // Non-standard?
        Ciphertext createCiphertext()
        {
            return Ciphertext(new seal::Ciphertext);
        }

        // Non-standard?
        Plaintext createPlaintext()
        {
            return Plaintext(new seal::Plaintext);
        }

    private:
        enum class RelinStyle : std::uint8_t
        {
            NEVER = 0,
            ALWAYS = 1
        };

        struct RelinProfile
        {
            RelinStyle style = RelinStyle::NEVER;

            std::unique_ptr<seal::RelinKeys> rlk{ nullptr };

            int dbc = 60;
        };

        void evalRelinInplace(Ciphertext ctxtIn)
        {
            switch (rlprof_->style)
            {
            case RelinStyle::NEVER:
                break;

            case RelinStyle::ALWAYS:
            {
                if (!rlprof_->rlk)
                {
                    throw std::runtime_error("RelinKeys are not loaded");
                }
                evaluator_->relinearize_inplace(*ctxtIn, *rlprof_->rlk);
                break;
            }

            default:
                throw std::runtime_error("invalid relinearization style");
            }        
        }

        std::shared_ptr<seal::SEALContext> context_{ nullptr };
        std::shared_ptr<seal::SecretKey> sk_{ nullptr };
        std::shared_ptr<seal::PublicKey> pk_{ nullptr };
        std::shared_ptr<seal::Evaluator> evaluator_{ nullptr };
        std::shared_ptr<seal::Encryptor> encryptor_{ nullptr };
        std::shared_ptr<seal::Decryptor> decryptor_{ nullptr };
        std::unique_ptr<RelinProfile> rlprof_{ nullptr };
    };
}