package com.antennahouse.us.encryptedconfig

import java.io._
import java.util.Properties

class EncryptedProperties(pubKey: InputStream, privKey: InputStream, pass: Array[Char]) extends Properties {
	override def load(inStream: InputStream) {
		super.load(Util.decryptStream(inStream, privKey, pass))
	}

	override def load(reader: Reader) {throw new IOException("Not supported.")}

	override def loadFromXML(in: InputStream) {
		super.load(Util.decryptStream(in, privKey, pass))
	}

	override def save(out: OutputStream, comments: String) {throw new IOException("Not supported.")}

	override def store(out: OutputStream, comments: String) {throw new IOException("Not supported.")}

	override def store(writer: Writer, comments: String) {throw new IOException("Not supported.")}

	override def storeToXML(os: OutputStream, comment: String) {throw new IOException("Not supported.")}
	override def storeToXML(os: OutputStream, comment: String, encoding: String) {throw new IOException("Not supported.")}
}

