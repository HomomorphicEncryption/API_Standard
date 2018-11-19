#include "hestd.h"


using namespace std;
using namespace hestd;

int main(int argc, char *argv[]) {

	std::ifstream fin("demoData/cryptocontext0.txt");
	
	HEStdContext context(fin,"profile");

	std::cerr << "\nLoaded profile..." << std::endl;

	context.keyGen();

	std::cerr << "All keys have been generated..." << std::endl;

	std::ofstream foutPK("demoData/pk.txt");
	std::ofstream foutSK("demoData/sk.txt");
	std::ifstream finPK("demoData/pk.txt");
	std::ifstream finSK("demoData/sk.txt");

	context.writePK(foutPK);
	context.writeSK(foutSK);

	std::cerr << "The public and private keys have been serialized..." << std::endl;

	context.readPK(finPK);
	context.readSK(finSK);

	std::cerr << "The public and private keys have been deserialized..." << std::endl;

	std::vector<uint64_t> vectorOfInts1 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext1 = context.CreatePlaintext(vectorOfInts1);

	std::vector<uint64_t> vectorOfInts2 = {12,11,10,9,8,7,6,5,4,3,2,1};
	Plaintext plaintext2 = context.CreatePlaintext(vectorOfInts2);

	std::cerr << "plaintext1 = " << *plaintext1 << std::endl;
	std::cerr << "plaintext2 = " << *plaintext2 << std::endl;

	Ciphertext ct1 = context.CreateCiphertext();
	Ciphertext ct2 = context.CreateCiphertext();

	context.encrypt(plaintext1,ct1);
	context.encrypt(plaintext2,ct2);
	std::cerr << "Encryption is completed..." << std::endl;

	std::ofstream foutCT("demoData/ct.txt");
	std::ifstream finCT("demoData/ct.txt");

	Ciphertext ct3 = context.CreateCiphertext();

	context.writeCiphertext(ct1,foutCT);
	std::cerr << "A ciphertext has been serialized..." << std::endl;
	context.readCiphertext(finCT,ct3);
	std::cerr << "A ciphertext has been deserialized..." << std::endl;

	Ciphertext ctAdd = context.CreateCiphertext();
	context.evalAdd(ct3,ct2,ctAdd);
	std::cerr << "Homomorphic addition is done..." << std::endl;

	context.evalAddInplace(ct1,ct2);
	std::cerr << "Homomorphic in-place addition is done..." << std::endl;

	Ciphertext ctMult = context.CreateCiphertext();
	context.evalMul(ct3,ct2,ctMult);
	std::cerr << "Homomorphic multiplication is done..." << std::endl;

	Plaintext ptAdd = context.CreatePlaintext();
	context.decrypt(ctAdd,ptAdd);
	std::cerr << "Decryption is done..." << std::endl;

	std::cerr << "result after addition = " << *ptAdd << std::endl;

	Plaintext ptAddInplace = context.CreatePlaintext();
	context.decrypt(ct1,ptAddInplace);
	std::cerr << "Decryption is done after in-place addition..." << std::endl;

	std::cerr << "result after in-place addition = " << *ptAddInplace << std::endl;

	Plaintext ptMult = context.CreatePlaintext();
	context.decrypt(ctMult,ptMult);
	std::cerr << "Decryption is done..." << std::endl;

	std::cerr << "result after multiplication = " << *ptMult << std::endl;

	return 0;
}
