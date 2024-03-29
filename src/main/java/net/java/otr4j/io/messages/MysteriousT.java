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

import java.util.Arrays;

import javax.crypto.interfaces.DHPublicKey;

/**
 * @author George Politis
 */
public class MysteriousT {
	// Fields.
	public int protocolVersion;
	public int senderInstanceTag;
	public int receiverInstanceTag;
	public int messageType;
	public int flags;
	public int senderKeyID;
	public int recipientKeyID;
	public DHPublicKey nextDH;
	public byte[] ctr;
	public byte[] encryptedMessage;

	// Ctor.
	public MysteriousT(int protocolVersion, int senderInstanceTag, int receiverInstanceTag,
			int flags, int senderKeyID,
			int recipientKeyID, DHPublicKey nextDH, byte[] ctr,
			byte[] encryptedMessage) {

		this.protocolVersion = protocolVersion;
		this.senderInstanceTag = senderInstanceTag;
		this.receiverInstanceTag = receiverInstanceTag;
		this.messageType = AbstractEncodedMessage.MESSAGE_DATA;
		this.flags = flags;
		this.senderKeyID = senderKeyID;
		this.recipientKeyID = recipientKeyID;
		this.nextDH = nextDH;
		this.ctr = ctr;
		this.encryptedMessage = encryptedMessage;
	}

	// Methods.
	@Override
	public int hashCode() {
		// TODO: Needs work.
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(ctr);
		result = prime * result + Arrays.hashCode(encryptedMessage);
		result = prime * result + flags;
		result = prime * result + messageType;
		result = prime * result + ((nextDH == null) ? 0 : nextDH.hashCode());
		result = prime * result + protocolVersion;
		result = prime * result + recipientKeyID;
		result = prime * result + senderKeyID;
		result = prime * result + senderInstanceTag;
		result = prime * result + receiverInstanceTag;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		// TODO: Needs work.
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		MysteriousT other = (MysteriousT) obj;
		if (!Arrays.equals(ctr, other.ctr))
			return false;
		if (!Arrays.equals(encryptedMessage, other.encryptedMessage))
			return false;
		if (flags != other.flags)
			return false;
		if (messageType != other.messageType)
			return false;
		if (nextDH == null) {
			if (other.nextDH != null)
				return false;
		} else if (!nextDH.equals(other.nextDH))
			return false;
		if (protocolVersion != other.protocolVersion)
			return false;
		if (recipientKeyID != other.recipientKeyID)
			return false;
		if (senderKeyID != other.senderKeyID)
			return false;
		if (senderInstanceTag != other.senderInstanceTag)
			return false;
		if (receiverInstanceTag != other.receiverInstanceTag)
			return false;
		return true;
	}

}
