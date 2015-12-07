package net.java.otr4j;

import net.java.otr4j.session.*;

import java.util.Scanner;
import java.util.logging.Logger;


/**
 * Created by mfina on 12/2/2015.
 */

import net.java.otr4j.session.DummyClient;
import net.java.otr4j.session.PriorityServer;


public class LaunchClient {

    private static Logger logger = Logger.getLogger(SessionImplTest.class
            .getName());

    public static void main (String args[]) {
        DummyClient alice = new DummyClient("Alice@Wonderland");
        alice.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
                | OtrPolicy.ERROR_START_AKE));

        DummyClient bob = new DummyClient("Bob@Wonderland");
        bob.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
                | OtrPolicy.ERROR_START_AKE));

        Server server = new PriorityServer();
        ProcessedMessage pMsg;

        alice.connect(server);
        bob.connect(server);

        System.out.println("here");
        try {
            /*
            bob.secureSession(alice.getAccount());
            System.out.println("here");
            alice.secureSession(bob.getAccount());
            System.out.println("here");*/

            bob.send(alice.getAccount(), "message");

            System.out.println(alice.pollReceivedMessage().getContent());
            alice.send(bob.getAccount(), "hi");
            System.out.println(bob.pollReceivedMessage().getContent());
            System.out.println(alice.pollReceivedMessage().getContent());
            System.out.println(bob.pollReceivedMessage().getContent());
            System.out.println(alice.pollReceivedMessage().getContent());
            /*
            System.out.println("here1");
            pMsg = alice.pollReceivedMessage(); // Query
            System.out.println("here2");
            pMsg = bob.pollReceivedMessage(); // DH-Commit
            System.out.println("here3");
            pMsg = alice.pollReceivedMessage(); // DH-Key
            System.out.println("here4");
            pMsg = bob.pollReceivedMessage(); // Reveal signature
            System.out.println("here5");
            pMsg = alice.pollReceivedMessage(); // Signature*/

            System.out.println("\n\nhere");
            alice.send(bob.getAccount(), "lalalalala");

            System.out.println(bob.pollReceivedMessage().getContent());
        }
        catch (OtrException e){
            System.out.println("crash");
        }
        catch(Exception e){
            e.printStackTrace();
        }
        /*
        String account = "bob";

        DummyClient chat = new DummyClient(account);
        Scanner sc = new Scanner(System.in);

        String input = sc.nextLine();
        try {
            chat.secureSession("Fred");
            chat.send("Fred", input);
        }
        catch (OtrException e) {

        }*/
    }
}
