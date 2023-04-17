package com.antennahouse.us.encryptedconfig

import java.io._
import java.security.{Provider, Security}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp._
import operator.bc.{BcPBESecretKeyDecryptorBuilder,BcPGPDigestCalculatorProvider}
import operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder
import scala.collection.JavaConversions._

object Util {
	def decryptStream(
			in: InputStream,
			keyIn: InputStream,
			passwd: Array[Char]
		): InputStream = {
		Security.getProvider("BC") match {
			case null => Security.addProvider(new BouncyCastleProvider)
		}
		val input = PGPUtil.getDecoderStream(in)
		val pgpF = new PGPObjectFactory(input, new JcaKeyFingerprintCalculator())
		val enc: PGPEncryptedDataList = pgpF.nextObject match {
			case o: PGPEncryptedDataList => o
			case _ => pgpF.nextObject match {
				case o: PGPEncryptedDataList => o
				case _ => null
			}
		}

		// find the secret key
		var sKey: PGPPrivateKey = null
		var pbe: PGPPublicKeyEncryptedData = null
		val pgpSec = new PGPSecretKeyRingCollection(
			PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator())
		val it = enc.getEncryptedDataObjects
		while (sKey == null && it.hasNext) {
			pbe = it.next match {
				case o: PGPPublicKeyEncryptedData => o
				case _ => null
			}
			sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd)
		}
		if (sKey == null) {
			throw new IllegalArgumentException("secret key for message not found.")
		}

		//if (pbe.isIntegrityProtected && !pbe.verify) throw new PGPException("Message verification failed.")

		val clear = pbe.getDataStream((new JcePublicKeyDataDecryptorFactoryBuilder).setProvider("BC").build(sKey))

		val plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator())

		var message: Any = plainFact.nextObject

		message = message match {
			case m: PGPCompressedData =>
				val pgpFact = new PGPObjectFactory(m.getDataStream, new JcaKeyFingerprintCalculator())
				pgpFact.nextObject
			case m =>
				m
		}

		message match {
			case m: PGPLiteralData =>
				m.getInputStream
			case _ =>
				throw new PGPException("message is not a simple encrypted file - type unknown.")
		}
	}

	private def findSecretKey(
			pgpSec: PGPSecretKeyRingCollection,
			keyID: Long,
			pass: Array[Char]
		): PGPPrivateKey = {
		pgpSec.getSecretKey(keyID) match {
			case pgpSecKey: PGPSecretKey => pgpSecKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(
					new BcPGPDigestCalculatorProvider).build(pass))
			case _ => null
		}
	}

	private def readPublicKey(fileName: String): PGPPublicKey = {
		val keyIn = new BufferedInputStream(new FileInputStream(fileName))
		val pubKey = readPublicKey(keyIn)
		keyIn.close
		pubKey
	}

	private def readPublicKey(input: InputStream): PGPPublicKey = {
		val pgpPub = new PGPPublicKeyRingCollection(
				PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator())

		for (ring: PGPPublicKeyRing <- pgpPub.getKeyRings.asInstanceOf[java.util.Iterator[PGPPublicKeyRing]]) {
			for (key: PGPPublicKey <- ring.getPublicKeys.asInstanceOf[java.util.Iterator[PGPPublicKey]]) {
				if (key.isEncryptionKey) {
					return key
				}
			}
		}

		throw new IllegalArgumentException("Can't find encryption key in key ring.")
	}
}

