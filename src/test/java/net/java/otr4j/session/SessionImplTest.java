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
package net.java.otr4j.session;

import java.util.logging.Logger;

import net.java.otr4j.OtrPolicy;
import net.java.otr4j.OtrPolicyImpl;

/**
 * @author George Politis
 */
public class SessionImplTest extends junit.framework.TestCase {

	private static Logger logger = Logger.getLogger(SessionImplTest.class
			.getName());

	public void testMultipleSessions() throws Exception {
		DummyClient bob1 = new DummyClient("Bob@Wonderland");
		bob1.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		DummyClient bob2 = new DummyClient("Bob@Wonderland");
		bob2.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		DummyClient bob3 = new DummyClient("Bob@Wonderland");
		bob3.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		DummyClient alice = new DummyClient("Alice@Wonderland");
		alice.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		Server server = new PriorityServer();
		alice.connect(server);
		bob1.connect(server);
		bob2.connect(server);
		bob3.connect(server);

		ProcessedMessage pMsg;

		bob1.send(alice.getAccount(), "<p>?OTRv23?\n" +
				"<span style=\"font-weight: bold;\">Bob@Wonderland/</span> has requested an <a href=\"http://otr.cypherpunks.ca/\">Off-the-Record private conversation</a>. However, you do not have a plugin to support that.\n" +
				"See <a href=\"http://otr.cypherpunks.ca/\">http://otr.cypherpunks.ca/</a> for more information.</p>");

		pMsg = alice.pollReceivedMessage(); // Query
		pMsg = bob1.pollReceivedMessage(); // DH-Commit
		pMsg = alice.pollReceivedMessage(); // DH-Key
		pMsg = bob1.pollReceivedMessage(); // Reveal signature
		pMsg = alice.pollReceivedMessage(); // Signature

		String msg;

		alice.send(bob1.getAccount(), msg = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");

		if (msg.equals(alice.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = bob1.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		bob2.send(alice.getAccount(), msg = "?OTRv23? Message from another client !");

		pMsg = alice.pollReceivedMessage();
		pMsg = bob2.pollReceivedMessage();
		pMsg = alice.pollReceivedMessage();
		pMsg = bob2.pollReceivedMessage();
		pMsg = alice.pollReceivedMessage();

		bob2.send(alice.getAccount(), msg = "This should be encrypted !");
		if (msg.equals(bob2.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = alice.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		bob3.send(alice.getAccount(), msg = "?OTRv23? Another message from another client !!");
		pMsg = alice.pollReceivedMessage();
		pMsg = bob3.pollReceivedMessage();
		pMsg = alice.pollReceivedMessage();
		pMsg = bob3.pollReceivedMessage();
		pMsg = alice.pollReceivedMessage();

		bob3.send(alice.getAccount(), msg = "This should be encrypted !");
		if (msg.equals(bob3.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = alice.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		bob1.send(alice.getAccount(), msg = "Hey Alice, it means that our communication is encrypted and authenticated.");
		if (msg.equals(bob1.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = alice.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		alice.send(bob1.getAccount(), msg = "Oh, is that all?");
		if (msg.equals(alice.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = bob1.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		bob1.send(alice.getAccount(), msg = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");
		if (msg.equals(bob1.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = alice.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		alice.send(bob1.getAccount(), msg = "Oh really?! pouvons-nous parler en français?");
		if (msg.equals(alice.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = bob1.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		bob1.exit();
		alice.exit();
	}

	public void testQueryStart() throws Exception {
		DummyClient bob = new DummyClient("Bob@Wonderland");
		bob.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		DummyClient alice = new DummyClient("Alice@Wonderland");
		alice.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		Server server = new PriorityServer();
		alice.connect(server);
		bob.connect(server);

		ProcessedMessage pMsg;

		bob.send(alice.getAccount(), "<p>?OTRv23?\n" +
				"<span style=\"font-weight: bold;\">Bob@Wonderland/</span> has requested an <a href=\"http://otr.cypherpunks.ca/\">Off-the-Record private conversation</a>. However, you do not have a plugin to support that.\n" +
				"See <a href=\"http://otr.cypherpunks.ca/\">http://otr.cypherpunks.ca/</a> for more information.</p>");

		pMsg = alice.pollReceivedMessage(); // Query
		pMsg = bob.pollReceivedMessage(); // DH-Commit
		pMsg = alice.pollReceivedMessage(); // DH-Key
		pMsg = bob.pollReceivedMessage(); // Reveal signature
		pMsg = alice.pollReceivedMessage(); // Signature

		if (bob.getSession().getSessionStatus() != SessionStatus.ENCRYPTED
				|| alice.getSession().getSessionStatus() != SessionStatus.ENCRYPTED)
			fail("The session is not encrypted.");

		String msg;

		alice.send(bob.getAccount(), msg = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");

		if (msg.equals(alice.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = bob.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Hey Alice, it means that our communication is encrypted and authenticated.");
		if (msg.equals(bob.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = alice.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh, is that all?");
		if (msg.equals(alice.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = bob.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");
		if (msg.equals(bob.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = alice.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh really?! pouvons-nous parler en français?");
		if (msg.equals(alice.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = bob.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		bob.exit();
		alice.exit();
	}

	public void testForcedStart() throws Exception {
		DummyClient bob = new DummyClient("Bob@Wonderland");
		bob.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		DummyClient alice = new DummyClient("Alice@Wonderland");
		alice.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		Server server = new PriorityServer();
		alice.connect(server);
		bob.connect(server);

		bob.secureSession(alice.getAccount());

		ProcessedMessage pMsg;

		pMsg = alice.pollReceivedMessage(); // Query
		pMsg = bob.pollReceivedMessage(); // DH-Commit
		pMsg = alice.pollReceivedMessage(); // DH-Key
		pMsg = bob.pollReceivedMessage(); // Reveal signature
		pMsg = alice.pollReceivedMessage(); // Signature

		if (bob.getSession().getSessionStatus() != SessionStatus.ENCRYPTED
				|| alice.getSession().getSessionStatus() != SessionStatus.ENCRYPTED)
			fail("The session is not encrypted.");

		String msg;

		alice.send(bob.getAccount(), msg = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");

		if (msg.equals(alice.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = bob.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Hey Alice, it means that our communication is encrypted and authenticated.");
		if (msg.equals(bob.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = alice.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh, is that all?");
		if (msg.equals(alice.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = bob.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");
		if (msg.equals(bob.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = alice.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh really?! pouvons-nous parler en français?");
		if (msg.equals(alice.getConnection().getSentMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals((pMsg = bob.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		bob.exit();
		alice.exit();
	}

	public void testPlaintext() throws Exception {
		DummyClient bob = new DummyClient("Bob@Wonderland");
		bob.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		DummyClient alice = new DummyClient("Alice@Wonderland");
		alice.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		Server server = new PriorityServer();
		alice.connect(server);
		bob.connect(server);

		String msg;

		alice.send(bob.getAccount(), msg = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");

		ProcessedMessage pMsg = bob.pollReceivedMessage();

		if (bob.getSession().getSessionStatus() != SessionStatus.PLAINTEXT
				|| alice.getSession().getSessionStatus() != SessionStatus.PLAINTEXT)
			fail("The session is not plaintext.");

		if (!msg.equals(alice.getConnection().getSentMessage()))
			fail("Message has been altered (but it shouldn't).");

		if (!msg.equals(pMsg.getContent()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Hey Alice, it means that our communication is encrypted and authenticated.");

		if (!msg.equals(bob.getConnection().getSentMessage()))
			fail("Message has been altered (but it shouldn't).");

		if (!msg.equals((pMsg = alice.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh, is that all?");

		if (!msg.equals(alice.getConnection().getSentMessage()))
			fail("Message has been altered (but it shouldn't).");

		if (!msg.equals((pMsg = bob.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");

		if (!msg.equals(bob.getConnection().getSentMessage()))
			fail("Message has been altered (but it shouldn't).");

		if (!msg.equals((pMsg = alice.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh really?! pouvons-nous parler en français?");

		if (!msg.equals(alice.getConnection().getSentMessage()))
			fail("Message has been altered (but it shouldn't).");

		if (!msg.equals((pMsg = bob.pollReceivedMessage()).getContent()))
			fail("Received message is different from the sent message.");

		bob.exit();
		alice.exit();
	}
}
