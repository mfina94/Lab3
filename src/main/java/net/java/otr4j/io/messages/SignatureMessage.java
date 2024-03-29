/*
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.java.otr4j.io.messages;

import java.io.IOException;
import java.util.Arrays;

import net.java.otr4j.OtrException;
import net.java.otr4j.crypto.OtrCryptoEngineImpl;
import net.java.otr4j.io.SerializationUtils;

/**
 * 
 * @author George Politis
 */
public class SignatureMessage extends AbstractEncodedMessage {
	// Fields.
	public byte[] xEncrypted;
	public byte[] xEncryptedMAC;

	// Ctor.
	protected SignatureMessage(int messageType, int protocolVersion,
			byte[] xEncrypted, byte[] xEncryptedMAC) {
		super(messageType, protocolVersion);
		this.xEncrypted = xEncrypted;
		this.xEncryptedMAC = xEncryptedMAC;
	}

	public SignatureMessage(int protocolVersion, byte[] xEncrypted,
			byte[] xEncryptedMAC) {
		this(MESSAGE_SIGNATURE, protocolVersion, xEncrypted, xEncryptedMAC);
	}

	// Memthods.
	public byte[] decrypt(byte[] key) throws OtrException {
		return new OtrCryptoEngineImpl().aesDecrypt(key, null, xEncrypted);
	}

	public boolean verify(byte[] key) throws OtrException {
		// Hash the key.
		byte[] xbEncrypted;
		try {
			xbEncrypted = SerializationUtils.writeData(xEncrypted);
		} catch (IOException e) {
			throw new OtrException(e);
		}

		byte[] xEncryptedMAC = new OtrCryptoEngineImpl().sha256Hmac160(
				xbEncrypted, key);
		// Verify signature.
		return Arrays.equals(this.xEncryptedMAC, xEncryptedMAC);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Arrays.hashCode(xEncrypted);
		result = prime * result + Arrays.hashCode(xEncryptedMAC);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		SignatureMessage other = (SignatureMessage) obj;
		if (!Arrays.equals(xEncrypted, other.xEncrypted))
			return false;
		if (!Arrays.equals(xEncryptedMAC, other.xEncryptedMAC))
			return false;
		return true;
	}
}
