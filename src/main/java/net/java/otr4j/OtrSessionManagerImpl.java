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

package net.java.otr4j;

import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import net.java.otr4j.session.Session;
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.SessionImpl;

/**
 * 
 * @author George Politis
 * 
 */
public class OtrSessionManagerImpl implements OtrSessionManager {

	public OtrSessionManagerImpl(OtrEngineHost host) {
		if (host == null)
			throw new IllegalArgumentException("OtrEgineHost is required.");

		this.setHost(host);
	}

	private OtrEngineHost host;
	private Map<SessionID, Session> sessions;

	public Session getSession(SessionID sessionID) {

		if (sessionID == null || sessionID.equals(SessionID.Empty))
			throw new IllegalArgumentException();

		if (sessions == null)
			sessions = new Hashtable<SessionID, Session>();

		if (!sessions.containsKey(sessionID)) {
			Session session = new SessionImpl(sessionID, getHost());
			sessions.put(sessionID, session);

			session.addOtrEngineListener(new OtrEngineListener() {

				public void sessionStatusChanged(SessionID sessionID) {
					for (OtrEngineListener l : listeners)
						l.sessionStatusChanged(sessionID);
				}

				public void multipleInstancesDetected(SessionID sessionID) {
					for (OtrEngineListener l : listeners)
						l.multipleInstancesDetected(sessionID);
				}
				
				public void outgoingSessionChanged(SessionID sessionID) {
					for (OtrEngineListener l : listeners)
						l.outgoingSessionChanged(sessionID);
				}
			});
			return session;
		} else
			return sessions.get(sessionID);
	}

	private void setHost(OtrEngineHost host) {
		this.host = host;
	}

	private OtrEngineHost getHost() {
		return host;
	}

	private List<OtrEngineListener> listeners = new Vector<OtrEngineListener>();

	public void addOtrEngineListener(OtrEngineListener l) {
		synchronized (listeners) {
			if (!listeners.contains(l))
				listeners.add(l);
		}
	}

	public void removeOtrEngineListener(OtrEngineListener l) {
		synchronized (listeners) {
			listeners.remove(l);
		}
	}
}
