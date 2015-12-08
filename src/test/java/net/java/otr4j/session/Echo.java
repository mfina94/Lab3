package net.java.otr4j.session;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.List;
import java.util.logging.Logger;
import javax.swing.*;
import javax.swing.text.DefaultCaret;

import net.java.otr4j.crypto.OtrCryptoEngineImpl;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.session.*;
import net.java.otr4j.*;

/**
 * Created by mfina on 12/6/2015.
 */
public class Echo implements ActionListener, Runnable {

    private static Logger logger = Logger.getLogger(SessionImplTest.class
            .getName());
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
    private final String name;
    private final String account;
    private Connection connection;
    private Session session;
    private OtrPolicy policy;
    private MessageProcessor processor;
    private Queue<ProcessedMessage> processedMsgs = new LinkedList<ProcessedMessage>();



    public Session getSession() {return session;}

    public String getAccount() {return account;}

    public void setPolicy(OtrPolicy policy) {this.policy=policy;}

    public void secureSession() throws OtrException{
        if (session == null) {
            String recipient;
            if (name.equals("Bob")) {
                recipient = "Alice";
            }
            else
            {
                recipient = "Bob";
            }
            final SessionID sessionID = new SessionID(name, recipient, "DummyProtocol");
            session = new SessionImpl(sessionID, new DummyOtrEngineHostImpl());
        }

        session.startSession();
    }

    public static enum Kind {

        Client(100, "Trying"), Server(500, "Awaiting");
        private int offset;
        private String activity;

        private Kind(int offset, String activity) {
            this.offset = offset;
            this.activity = activity;
        }
    }

    public Echo(Kind kind, String name) {
        this.name = name;
        this.account=name;
        this.kind = kind;
        f.setTitle("Echo " + name);
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

    //@Override
    public void actionPerformed(ActionEvent ae) {
        try {
            String s = name + ": " + tf.getText();
            if (out != null) {
                out.println(send(s));
            }
            display(s);
            tf.setText("");
        }
        catch (OtrException e)
        {
            e.printStackTrace();
        }
    }

    public String send(String s)throws OtrException{
        if (session == null) {
            String recipient;
            if (name.equals("Bob")) {
                recipient = "Alice";
            }
            else
            {
                recipient = "Bob";
            }
            final SessionID sessionID = new SessionID(name, recipient, "DummyProtocol");
            session = new SessionImpl(sessionID, new DummyOtrEngineHostImpl());
        }
        String messageToSend = "";
        String[] outgoingMessage = session.transformSending(s, (java.util.List<TLV>) null);
        for (String part : outgoingMessage) {
            messageToSend = messageToSend + part;
        }
        return messageToSend;
    }

    //@Override
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
                final String disp = session.transformReceiving(in.nextLine());
                display(disp);
                //display(in.nextLine());
            }
        } catch (Exception e) {
            display(e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    public void receive(String sender, String s) throws OtrException {
        this.processor.enqueue(sender, s);
    }

    public void sendM(String recipient, String s) throws OtrException {
        if (session == null) {
            final SessionID sessionID = new SessionID(account, recipient, "DummyProtocol");
            session = new SessionImpl(sessionID, new DummyOtrEngineHostImpl());
        }

        String[] outgoingMessage = session.transformSending(s, (List<TLV>) null);
        for (String part : outgoingMessage) {
            connection.send(recipient, part);
        }
    }

    public void connect(Server server) {
        this.processor = new MessageProcessor();
        new Thread(this.processor).start();
        //this.connection = server.connect(this);
    }

    private void display(final String s) {
        EventQueue.invokeLater(new Runnable() {
                //@Override
                public void run() {
                    ta.append(s + "\n");
                }
            });
    }

    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            //@Override
            public void run() {
                Echo alice = new Echo(Kind.Server, "Alice");
                Echo bob = new Echo(Kind.Client, "Bob");
                try{
                    OtrPolicy alicePolicy = new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
                            | OtrPolicy.ERROR_START_AKE);
                    alicePolicy.setRequireEncryption(true);
                    alice.setPolicy(alicePolicy);

                    OtrPolicy bobPolicy = new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
                            | OtrPolicy.ERROR_START_AKE);
                    bobPolicy.setRequireEncryption(true);
                    bob.setPolicy(bobPolicy);


                    Server server = new PriorityServer();
                    alice.connect(server);
                    bob.connect(server);
                    ProcessedMessage pMsg;

                    String query = "<p>?OTRv23?\n" +
                            "<span style=\"font-weight: bold;\">Bob@Wonderland/</span> has requested an <a href=\"http://otr.cypherpunks.ca/\">Off-the-Record private conversation</a>. However, you do not have a plugin to support that.\n" +
                            "See <a href=\"http://otr.cypherpunks.ca/\">http://otr.cypherpunks.ca/</a> for more information.</p>";

                    bob.sendM(alice.getAccount(), query);

                    pMsg = alice.pollReceivedMessage(); // Query
                    pMsg = bob.pollReceivedMessage(); // DH-Commit
                    pMsg = alice.pollReceivedMessage(); // DH-Key
                    pMsg = bob.pollReceivedMessage(); // Reveal signature
                    pMsg = alice.pollReceivedMessage(); // Signature

                    if (bob.getSession().getSessionStatus() != SessionStatus.ENCRYPTED
                            || alice.getSession().getSessionStatus() != SessionStatus.ENCRYPTED)
                        System.out.println("The session is not encrypted.");
                    else {
                        System.out.println("YAY!");
                    }

                    alice.secureSession();
                    bob.secureSession();
                    alice.start();
                    bob.start();
                }
                catch(OtrException e){
                    e.printStackTrace();
                }
            }
        });
    }

    class DummyOtrEngineHostImpl implements OtrEngineHost {

        public void injectMessage(SessionID sessionID, String msg) throws OtrException {

            //socket.send(sessionID.getUserID(), msg);

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

        private void process(Message m) throws OtrException {
            if (session == null) {
                final SessionID sessionID = new SessionID(name, m.getSender(), "DummyProtocol");
                session = new SessionImpl(sessionID, new DummyOtrEngineHostImpl());
            }

            String receivedMessage = session.transformReceiving(m.getContent());
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

}
