package nl.na1.PEMToOpenPGP

import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.bcpg.*
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.math.ec.rfc8032.Ed25519
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder
import org.bouncycastle.openssl.PEMParser
import java.io.FileOutputStream
import java.io.FileReader
import java.io.OutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Security
import java.security.interfaces.EdECPrivateKey
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*

// Used in debugging
fun ByteArray.toHex(): String =
    joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }

/**
 * A simple utility class that converts PEM PKCS8 (OpenSSL) to an Ed25519 PGPPublicKey/PGPSecretKey pair.
 *
 * usage: [-a] identity passphrase pemfile.pem
 *
 * Where identity is the name to be associated with the public key. The keys are placed
 * in the files {pub,secret}.asc if -a (armor) is specified and .bpg otherwise.
 */
//modified from package org.bouncycastle.openpgp.examples class RSAPrivateKeyGenerator
object App {
    private fun exportKeyPair(
        secretOut: OutputStream,
        publicOut: OutputStream,
        keyPair: PGPKeyPair,
        identity: String,
        passPhrase: CharArray,
        armor: Boolean
    ) {
        var secretOut = secretOut
        var publicOut = publicOut
        if (armor) {
            secretOut = ArmoredOutputStream(secretOut)
        }
        val sha1Calc =
            JcaPGPDigestCalculatorProviderBuilder().build()[HashAlgorithmTags.SHA1]
        val secretKey = PGPSecretKey(
            PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity, sha1Calc, null, null,
            JcaPGPContentSignerBuilder(
                keyPair.publicKey.algorithm,
                HashAlgorithmTags.SHA1
            ),
            JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc)
                .setProvider("BC")
                .build(passPhrase)
        )
        secretKey.encode(secretOut)
        secretOut.close()
        if (armor) {
            publicOut = ArmoredOutputStream(publicOut)
        }
        val key = secretKey.publicKey
        key.encode(publicOut)
        publicOut.close()
    }

    @JvmStatic
    fun main(
        args: Array<String>
    ) {
        // Based on https://unix.stackexchange.com/a/276869, modified to support Ed25519
        Security.addProvider(BouncyCastleProvider())

        val flag = if (args.isNotEmpty() && args[0] == "-a") 1 else 0
        if (args.size != flag + 3) {
            println("[-a] identity passphrase pemfile.pem")
            System.exit(0)
        }

        val identity = args[flag]
        val password = args[flag + 1]
        val privateKeyFile = args[flag + 2]

        val rdr = FileReader(privateKeyFile)
        val pk8 = PEMParser(rdr).readObject() as PrivateKeyInfo
        rdr.close()

        val fact = KeyFactory.getInstance("EDDSA")
        val privSpec: KeySpec = PKCS8EncodedKeySpec(pk8.encoded)
        val privateKey = fact.generatePrivate(privSpec) as EdECPrivateKey

        val privateKeyParameters = Ed25519PrivateKeyParameters(privateKey.bytes.get())
        val publicKeyParameters = privateKeyParameters.generatePublicKey()

        val publicKeyBytes = publicKeyParameters.encoded

        assert(Ed25519.validatePublicKeyFull(publicKeyBytes, 0))

        val pointEnc = ByteArray(1 + Ed25519PublicKeyParameters.KEY_SIZE)
        pointEnc[0] = 0x40
        publicKeyBytes.copyInto(pointEnc, 1)

        val bcpgPublicKey =
            EdDSAPublicBCPGKey(GNUObjectIdentifiers.Ed25519, BigInteger(1, pointEnc))

        val now = Date()
        val pgpPublicKey = PGPPublicKey(
            PublicKeyPacket(PGPPublicKey.EDDSA, now, bcpgPublicKey),
            JcaKeyFingerprintCalculator()
        )

        //Copied form JcaPGPKeyConverter.java, getPrivateBCPGKey
        val pInfo = PrivateKeyInfo.getInstance(privateKey.encoded)
        val edSecretBCPGKEY = EdSecretBCPGKey(
            BigInteger(
                1,
                ASN1OctetString.getInstance(pInfo.parsePrivateKey()).octets
            )
        )
        val pgpPrivateKey = PGPPrivateKey(
            pgpPublicKey.keyID,
            pgpPublicKey.publicKeyPacket,
            edSecretBCPGKEY
        )

        val kp = PGPKeyPair(pgpPublicKey, pgpPrivateKey)
        val suffix = arrayOf("bpg", "asc")
        val out1 = FileOutputStream("secret." + suffix[flag])
        val out2 = FileOutputStream("pub." + suffix[flag])
        exportKeyPair(out1, out2, kp, identity, password.toCharArray(), flag > 0)
    }
}
