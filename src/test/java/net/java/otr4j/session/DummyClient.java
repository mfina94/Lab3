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

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Scanner;
import java.util.logging.Logger;

import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.OtrPolicyImpl;
import net.java.otr4j.crypto.OtrCryptoEngineImpl;
import net.java.otr4j.crypto.OtrCryptoException;

import javax.swing.*;
import javax.swing.text.DefaultCaret;

/**
 * OTR Chat Client - University of Iowa Senior Design Lab
 * Matt, Tyler, Eli, Bob
 *
 * Thank you to..
 * @author George Politis & libotr
 */
public class DummyClient implements ActionListener, Runnable{

	//private members already here
	private static Logger logger = Logger.getLogger(SessionImplTest.class
			.getName());
	private final String account;
	private final String recipient;
	private Session session;
	private OtrPolicy policy;
	private Connection connection;
	private MessageProcessor processor;
	private Queue<ProcessedMessage> processedMsgs = new LinkedList<ProcessedMessage>();

	//for display and connection
	private static final String HOST = "127.0.0.1";
	private static final int PORT = 12345;
	private final JFrame f = new JFrame();
	private final JTextField tf = new JTextField(25);
	private final JTextArea ta = new JTextArea(15, 25);
	private final JButton send = new JButton("Send");
	private volatile PrintWriter out;
	private Scanner in;
	private Thread thread;
	private Kind kind;

	public static enum Kind {

		Client(100, "Trying"), Server(500, "Awaiting");
		private int offset;
		private String activity;

		private Kind(int offset, String activity) {
			this.offset = offset;
			this.activity = activity;
		}
	}

	public static void main (String args[]){
		EventQueue.invokeLater(new Runnable() {
			//@Override
			public void run() {
				DummyClient alice = new DummyClient(Kind.Server, "Alice");
				DummyClient bob = new DummyClient(Kind.Client, "Bob");
				try{
					OtrPolicy alicePolicy = new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
							| OtrPolicy.ERROR_START_AKE);
					alice.setPolicy(alicePolicy);

					OtrPolicy bobPolicy = new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
							| OtrPolicy.ERROR_START_AKE);
					bob.setPolicy(bobPolicy);

					bob.start();
					alice.start();

					Server server = new PriorityServer();
					alice.connect(server);
					bob.connect(server);

					//query for otr convo, exchange keys and signatures
					alice.secureSession("Bob");
					bob.pollReceivedMessage();//query
					alice.pollReceivedMessage();//DH_COMMIT
					bob.pollReceivedMessage();//DH-KEY
					alice.pollReceivedMessage();//Reveal Signature
					bob.pollReceivedMessage();//Signature


					if (bob.getSession().getSessionStatus() != SessionStatus.ENCRYPTED
							|| alice.getSession().getSessionStatus() != SessionStatus.ENCRYPTED)
						System.out.println("The session is not encrypted.");
					else {
						System.out.println("Yay");
					}

					String msg;
					alice.send(bob.getAccount(), msg = "Alice: Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");
					alice.display(msg);
					if (msg.equals(alice.getConnection().getSentMessage())){
						System.out.println("Message failed to be sent with encryption");
					}

					alice.send(bob.getAccount(), msg="What did you have for breakfest");
					alice.display(msg);
					alice.getSession().initSmp("What did you have for breakfest","Coffee");
					System.out.println(alice.getSession().isSmpInProgress());

					//bob.getSession().initSmp("What did you have for breakfest","Coffee");
					//System.out.println(bob.getSession().isSmpInProgress());

					//alice.getSession().respondSmp(alice.getSession().getReceiverInstanceTag(),msg,"Coffee");
					//System.out.println(alice.getSession().isSmpInProgress());


					bob.getSession().respondSmp(bob.getSession().getReceiverInstanceTag(),msg,"Coffee");
					System.out.println(bob.getSession().isSmpInProgress());
				}
				catch(OtrException e){
					e.printStackTrace();
				}
				catch(Exception e){
					e.printStackTrace();
				}
				//catch(OtrException e){
				//	e.printStackTrace();
				//}
			}
		});
	}


	//@Override
	public void actionPerformed(ActionEvent ae) {
		try {
			String s = account + ": " + tf.getText();
			if (out != null) {
				send(recipient,s);
			}
			display(s);
			tf.setText("");
		}
		catch (OtrException e)
		{
			e.printStackTrace();
		}
	}

	private void display(final String s) {
		EventQueue.invokeLater(new Runnable() {
			//@Override
			public void run() {
				ta.append(s + "\n");
			}
		});
	}

	public void run() {
		try {
			Socket socket;
			if (kind == Kind.Client) {
				socket = new Socket(HOST, PORT);
			} else {
				ServerSocket ss = new ServerSocket(PORT);
				socket = ss.accept();
			}
			in = new Scanner(socket.getInputStream());
			out = new PrintWriter(socket.getOutputStream(), true);
			display("Connected");
			while (true) {
				//final String disp = session.transformReceiving(in.nextLine());
				//display(disp);
				receive(recipient,in.nextLine());
			}
		} catch (Exception e) {
			display(e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	public DummyClient(Kind kind, String account) {
		if (account.equals("Bob")){
			this.recipient = "Alice";
		}
		else{
			this.recipient = "Bob";
		}

		this.account = account;
		this.kind = kind;
		f.setTitle("Echo " + account);
		f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		f.getRootPane().setDefaultButton(send);
		f.add(tf, BorderLayout.NORTH);
		f.add(new JScrollPane(ta), BorderLayout.CENTER);
		f.add(send, BorderLayout.SOUTH);
		f.setLocation(kind.offset, 300);
		f.pack();
		send.addActionListener(this);
		ta.setLineWrap(true);
		ta.setWrapStyleWord(true);
		DefaultCaret caret = (DefaultCaret) ta.getCaret();
		caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
		display(kind.activity + HOST + " on port " + PORT);
		thread = new Thread(this, kind.toString());
	}

	public void start() {
		f.setVisible(true);
		thread.start();
	}

	public Session getSession() {
		return session;
	}

	public String getAccount() {
		return account;
	}

	public void setPolicy(OtrPolicy policy) {
		this.policy = policy;
	}

	public void send(String recipient, String s) throws OtrException {
		if (session == null) {
			final SessionID sessionID = new SessionID(account, recipient, "DummyProtocol");
			session = new SessionImpl(sessionID, new DummyOtrEngineHostImpl());
		}

		String msg="";
		String[] outgoingMessage = session.transformSending(s, (List<TLV>) null);
		for (String part : outgoingMessage) {
			connection.send(recipient, part);
			msg=msg+part;
		}
		if (!msg.equals("") || msg != null || out != null){
			out.println(msg);
		}
	}

	public void exit() throws OtrException {
		this.processor.stop();
		if (session != null)
			session.endSession();
	}

	public void receive(String sender, String s) throws OtrException {
		this.processor.enqueue(sender, s);
	}

	public void connect(Server server) {
		this.processor = new MessageProcessor();
		new Thread(this.processor).start();
		this.connection = server.connect(this);
	}

	public void secureSession(String recipient) throws OtrException {
		if (session == null) {
			final SessionID sessionID = new SessionID(account, recipient, "DummyProtocol");
			session = new SessionImpl(sessionID, new DummyOtrEngineHostImpl());
		}

		session.startSession();
	}

	public Connection getConnection() {
		return connection;
	}

	public ProcessedMessage pollReceivedMessage() {
		synchronized (processedMsgs) {
			ProcessedMessage m;
			while ((m = processedMsgs.poll()) == null) {
				try {
					processedMsgs.wait();
				} catch (InterruptedException e) {
				}
			}

			return m;
		}
	}

	class MessageProcessor implements Runnable {
		private final Queue<Message> messageQueue = new LinkedList<Message>();
		private boolean stopped;
		private boolean first = false;

		private void process(Message m) throws OtrException {
			if (session == null) {
				final SessionID sessionID = new SessionID(account, m.getSender(), "DummyProtocol");
				session = new SessionImpl(sessionID, new DummyOtrEngineHostImpl());
			}

			String receivedMessage = session.transformReceiving(m.getContent());
			if (!first) {
				display(receivedMessage);
				first = true;
			}
			else{
				first =false;
			}
			synchronized (processedMsgs) {
				processedMsgs.add(new ProcessedMessage(m, receivedMessage));
				processedMsgs.notify();
			}
		}

		public void run() {
			synchronized (messageQueue) {
				while (true) {

					Message m = messageQueue.poll();

					if (m == null) {
						try {
							messageQueue.wait();
						} catch (InterruptedException e) {

						}
					} else {
						try {
							process(m);
						} catch (OtrException e) {
							e.printStackTrace();
						}
					}

					if (stopped)
						break;
				}
			}
		}

		public void enqueue(String sender, String s) {
			synchronized (messageQueue) {
				messageQueue.add(new Message(sender, s));
				messageQueue.notify();
			}
		}

		public void stop() {
			stopped = true;

			synchronized (messageQueue) {
				messageQueue.notify();
			}
		}
	}

	class DummyOtrEngineHostImpl implements OtrEngineHost {

		public void injectMessage(SessionID sessionID, String msg) throws OtrException {

			connection.send(sessionID.getUserID(), msg);

			String msgDisplay = (msg.length() > 10) ? msg.substring(0, 10)
					+ "..." : msg;
			logger.finest("IM injects message: " + msgDisplay);
		}

		public void smpError(SessionID sessionID, int tlvType, boolean cheated)
				throws OtrException {
			logger.severe("SM verification error with user: " + sessionID);
		}

		public void smpAborted(SessionID sessionID) throws OtrException {
			logger.severe("SM verification has been aborted by user: "
					+ sessionID);
		}

		public void finishedSessionMessage(SessionID sessionID, String msgText) throws OtrException {
			logger.severe("SM session was finished. You shouldn't send messages to: "
					+ sessionID);
		}

		public void finishedSessionMessage(SessionID sessionID) throws OtrException {
			logger.severe("SM session was finished. You shouldn't send messages to: "
					+ sessionID);
		}

		public void requireEncryptedMessage(SessionID sessionID, String msgText)
				throws OtrException {
			logger.severe("Message can't be sent while encrypted session is not established: "
					+ sessionID);
		}

		public void unreadableMessageReceived(SessionID sessionID)
				throws OtrException {
			logger.warning("Unreadable message received from: " + sessionID);
		}

		public void unencryptedMessageReceived(SessionID sessionID, String msg)
				throws OtrException {
			logger.warning("Unencrypted message received: " + msg + " from "
					+ sessionID);
		}

		public void showError(SessionID sessionID, String error)
				throws OtrException {
			logger.severe("IM shows error to user: " + error);
		}

		public String getReplyForUnreadableMessage() {
			return "You sent me an unreadable encrypted message.";
		}

		public void sessionStatusChanged(SessionID sessionID) {
			// don't care.
		}

		public KeyPair getLocalKeyPair(SessionID paramSessionID) {
			KeyPairGenerator kg;
			try {
				kg = KeyPairGenerator.getInstance("DSA");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				return null;
			}
			return kg.genKeyPair();
		}

		public OtrPolicy getSessionPolicy(SessionID ctx) {
			return policy;
		}

		public void askForSecret(SessionID sessionID, String question) {
			logger.finest("Ask for secret from: " + sessionID + ", question: "
					+ question);
		}

		public void verify(SessionID sessionID, boolean approved) {
			logger.finest("Session was verified: " + sessionID);
			if (!approved)
				logger.finest("Your answer for the question was verified."
						+ "You should ask your opponent too or check shared secret.");
		}

		public void unverify(SessionID sessionID) {
			logger.finest("Session was not verified: " + sessionID);
		}

		public byte[] getLocalFingerprintRaw(SessionID sessionID) {
			try {
				return new OtrCryptoEngineImpl()
						.getFingerprintRaw(getLocalKeyPair(sessionID)
								.getPublic());
			} catch (OtrCryptoException e) {
				e.printStackTrace();
			}
			return null;
		}

		public void askForSecret(SessionID sessionID, InstanceTag receiverTag, String question) {

		}

		public void verify(SessionID sessionID, String fingerprint, boolean approved) {

		}

		public void unverify(SessionID sessionID, String fingerprint) {

		}

		public String getReplyForUnreadableMessage(SessionID sessionID) {
			return null;
		}

		public String getFallbackMessage(SessionID sessionID) {
			return null;
		}

		public void messageFromAnotherInstanceReceived(SessionID sessionID) {

		}

		public void multipleInstancesDetected(SessionID sessionID) {

		}

		public String getFallbackMessage() {
			return "Off-the-Record private conversation has been requested. However, you do not have a plugin to support that.";
		}
		
		public FragmenterInstructions getFragmenterInstructions(SessionID sessionID) {
			return new FragmenterInstructions(FragmenterInstructions.UNLIMITED,
					FragmenterInstructions.UNLIMITED);
		}
	}
}
