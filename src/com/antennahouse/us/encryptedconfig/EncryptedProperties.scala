package com.antennahouse.us.encryptedconfig

import java.io._
import java.util.Properties

class EncryptedProperties(pubKey: InputStream, privKey: InputStream, pass: Array[Char]) extends Properties {

	// https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/Properties.html#load(java.io.InputStream)
        // The input stream is in a simple line-oriented format as specified in load(Reader) and is assumed to use the ISO 8859-1 character encoding; that is each byte is one Latin1 character.
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

