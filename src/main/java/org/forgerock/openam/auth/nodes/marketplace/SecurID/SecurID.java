/*
 * This code is to be used exclusively in connection with ForgeRock’s software or services. 
 * ForgeRock only offers ForgeRock software or services to legal entities who have entered 
 * into a binding license agreement with ForgeRock. 
 */

package org.forgerock.openam.auth.nodes.marketplace.SecurID;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.UUID;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.PasswordCallback;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.authentication.callbacks.PollingWaitCallback;
import org.forgerock.openam.authentication.callbacks.StringAttributeInputCallback;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.openam.utils.qr.GenerationUtils;
import org.forgerock.util.i18n.PreferredLocales;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.sm.RequiredValueValidator;

@Node.Metadata(outcomeProvider = SecurID.SecurIDOutcomeProvider.class, configClass = SecurID.Config.class, tags = {"multi-factor authentication", "marketplace", "trustnetwork" })
public class SecurID extends AbstractDecisionNode {

	private final Logger logger = LoggerFactory.getLogger(SecurID.class);
	private String loggerPrefix = "[SecurID]" + SecurIDPlugin.logAppender;
	private static final String BUNDLE = SecurID.class.getName();
	private final Config config;
	private static final String SUCCESS = "SUCCESS";
	private static final String ERROR = "ERROR";
	private static final String FAILURE = "FAILURE";
	private static final String NOTENROLLED = "NOTENROLLED";
	private static final String CANCEL = "CANCEL";

	private static final String initializeAppend = "/authn/initialize";
	private static final String verifyAppend = "/authn/verify";

	// Cap on how much of an RSA response body we put in a log line.
	private static final int LOG_BODY_LIMIT = 2000;

	// These used to be static finals, but ConfirmationCallback is mutable and setSelectedIndex()
	// was being called on the shared instances. Two concurrent authentications could then see
	// each other's button state. Build a fresh one per request instead.
	private static ConfirmationCallback newNextCancelCallback() {
		return new ConfirmationCallback(ConfirmationCallback.INFORMATION, new String[] { "Next", "Cancel" }, 0);
	}

	private static ConfirmationCallback newCancelOnlyCallback() {
		ConfirmationCallback cb = new ConfirmationCallback(ConfirmationCallback.INFORMATION, new String[] { "Cancel" }, 0);
		cb.setSelectedIndex(100);// so cancel doesnt looked pressed by default
		return cb;
	}

	/**
	 * Configuration for the node.
	 */
	public interface Config {

		@Attribute(order = 100, validators = { RequiredValueValidator.class })
		default String baseURL() {
			return "https://yourtenant.securid.com/mfa/v1_1";
		}

		@Attribute(order = 200, validators = { RequiredValueValidator.class })
		String clientID();

		@Attribute(order = 300)
		String assurancePolicy();

		@Attribute(order = 400, validators = { RequiredValueValidator.class })
		@Password
		String clientKey();

		@Attribute(order = 500, validators = { RequiredValueValidator.class })
		default boolean verifySSL() {
			return false;
		}

		@Attribute(order = 600, validators = { RequiredValueValidator.class })
		default String thePrompt() {
			return "Select your preferred MFA";
		}

		@Attribute(order = 700, validators = { RequiredValueValidator.class })
		default String theWaitingForResponseMessage() {
			return "Waiting for your response";
		}

		@Attribute(order = 800, validators = { RequiredValueValidator.class })
		default String theNextTokencodePrompt() {
			return "Wait for the code on your token to change, then enter the new code";
		}

	}

	@Inject
	public SecurID(@Assisted Config config) {
		this.config = config;
	}

	@Override
	public Action process(TreeContext context) {
		try {
			NodeState ns = context.getStateFor(this);
			if (!context.hasCallbacks()) {
				// First time here. Initialize and display choice. Considered step 0
				logger.debug(loggerPrefix + "process() - no callbacks present, starting initialization");

				// first get the response from the call
				JSONObject fromPost = doInitialize(context);

				return startChoice(fromPost, ns);

			} else {
				// check if we just came from step 0, which indicates the user has selected there MFA path
				// otherwise, we are already on a MFA path and either verifying or waiting for a push completion
				logger.debug(loggerPrefix + "process() - callbacks present, P1ProtectStep: " + ns.get("P1ProtectStep").asInteger());

				// check if they hit cancel button first.
				if (cancelPushed(context, ns)) {
					logger.debug(loggerPrefix + "process() - cancel pushed, going to CANCEL");
					cleanSS(ns);
					return Action.goTo(CANCEL).build();
				}

				switch (ns.get("P1ProtectStep").asInteger().intValue()) {
				case 0:// they just picked which MFA they want to use put them on the right path
						// depending on choice, we need to show them either input screen or make the push and show a spinner, or QR code and set P1ProtectStep accordingly
					logger.debug(loggerPrefix + "process() - switch case 0 (MFA choice selection)");
					List<Callback> choiceSelectedCallbacks = choiceSelected(context, ns);
					return Action.send(choiceSelectedCallbacks).build();
				case 1:// they went with RSA SecurID or Athenticate Tokencode or emergency
						// we just got back here, so that means they sent us a token
					logger.debug(loggerPrefix + "process() - switch case 1 (tokencode input)");
					return handleTokenVerifyResult(checkToken(context), ns, 1);

				case 2:// they went with Approve or Device Biometrics
						// we just got back here, so that means the poll wait timed out
					logger.debug(loggerPrefix + "process() - switch case 2 (push/biometrics approval)");
					return checkApproval(ns, 2, ns.get("p1Choice").asString());

				case 3:// they went with QR code
						// we just got back here, so that means the poll wait timed out
					logger.debug(loggerPrefix + "process() - switch case 3 (QR code)");
					return checkApproval(ns, 3, ns.get("p1Choice").asString());

				case 4:// they went with Voice or SMS
					logger.debug(loggerPrefix + "process() - switch case 4 (Voice/SMS tokencode)");
					return handleTokenVerifyResult(checkToken(context), ns, 4);

				default:
					logger.error(loggerPrefix + "process() - unrecognised P1ProtectStep: "
							+ ns.get("P1ProtectStep").asInteger() + ", going to ERROR");
					cleanSS(ns);
					return Action.goTo(ERROR).build();
				}
				// Every switch branch returns, including default, so there is no fall-through to a
				// trailing ERROR any more -- an unhandled step is named in the log instead.
			}

		} catch (Exception ex) {
			String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
			cleanSS(context.getStateFor(this));
			logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
			context.getStateFor(this).putTransient(loggerPrefix + "Exception", new Date() + ": " + ex.getMessage());
			context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", new Date() + ": " + stackTrace);
			return Action.goTo(ERROR).withHeader("Error occurred").withErrorMessage(ex.getMessage()).build();
		}
	}
	
	
	
	private Action startChoice(JSONObject fromPost, NodeState ns) throws Exception{

		String attemptCode = fromPost.optString("attemptResponseCode", null);
		logger.debug(loggerPrefix + "startChoice() - entry, attemptResponseCode: " + attemptCode
				+ ", methodResponseCode: " + methodResponseCode(fromPost));

		if (attemptCode == null) {
			logger.error(loggerPrefix + "startChoice() - no attemptResponseCode in response, going to ERROR. Response: "
					+ bodyForLog(fromPost));
			cleanSS(ns);
			return Action.goTo(ERROR).build();
		}

		// now check if MFA needed
		if (attemptCode.equalsIgnoreCase("SUCCESS")) {
			logger.debug(loggerPrefix + "startChoice() - MFA not needed, going to SUCCESS");
			cleanSS(ns);
			return Action.goTo(SUCCESS).build();
		}

		// RSA refused the attempt outright -- unknown user, disabled or unassigned token,
		// locked account, policy denial. This used to fall through to the choice lookup, which
		// then found zero choices and reported NOTENROLLED. That sends the journey down the
		// wrong branch and hides the real reason, so call it what it is.
		if (attemptCode.equalsIgnoreCase("FAIL")) {
			logger.error(loggerPrefix + "startChoice() - RSA rejected the attempt. attemptResponseCode: " + attemptCode
					+ ", methodResponseCode: " + methodResponseCode(fromPost) + ", response: " + bodyForLog(fromPost));
			cleanSS(ns);
			return Action.goTo(FAILURE).build();
		}

		// determine if user is registered for at least one MFA
		ArrayList<String> choices = getChoices(fromPost);
		choices.trimToSize();
		if (choices.size() == 0) {
			logger.error(loggerPrefix + "startChoice() - RSA offered no usable authentication methods, going to "
					+ "NOTENROLLED. attemptResponseCode: " + attemptCode + ", response: " + bodyForLog(fromPost));
			cleanSS(ns);
			return Action.goTo(NOTENROLLED).build();
		}

		// if users only has one MFA choice, go to that choice and start next step after initialize
		if (choices.size() == 1) {
			logger.debug(loggerPrefix + "startChoice() - single choice auto-selected: " + choices.get(0));
			ns.putShared("inResponseTo", getDataFromContext(fromPost, "messageId"));
			ns.putShared("authnAttemptId", getDataFromContext(fromPost, "authnAttemptId"));
			ns.putShared("p1Choice", choices.get(0));
			List<Callback> callbacks = choiceSelectedHelper(choices.get(0), ns);
			return Action.send(callbacks).build();
		}

		// if here, then user has at least two MFA choice enrolled. We need to let them choose which one
		logger.debug(loggerPrefix + "startChoice() - multiple choices presented, count: " + choices.size());
		List<Callback> callbacks = completeInitialize(ns, choices, fromPost);
		return Action.send(callbacks).build();

	}
	

	private Action checkApproval(NodeState ns, int step, String theChoice) throws Exception {
		logger.debug(loggerPrefix + "checkApproval() - entry, step: " + step + ", theChoice: " + theChoice);
		Action retVal = null;

		List<Callback> callbacks = new ArrayList<>();

		JsonValue refJV = ns.get("PingReferenceId");
		String ref = null;
		if (refJV != null && refJV.isString()) {
			ref = refJV.asString();
		}
		JSONObject fromPost = makePushPost(ns, theChoice, ref);
		ns.putShared("inResponseTo", getDataFromContext(fromPost, "messageId"));
		ns.putShared("authnAttemptId", getDataFromContext(fromPost, "authnAttemptId"));
		ns.putShared("PingReferenceId", getPushRef(fromPost, theChoice));

		String attemptCode = fromPost.optString("attemptResponseCode", null);
		String methodCode = methodResponseCode(fromPost);
		logger.debug(loggerPrefix + "checkApproval() - attemptResponseCode: " + attemptCode + ", methodResponseCode: "
				+ methodCode);

		if (attemptCode == null) {
			logger.error(loggerPrefix + "checkApproval() - no attemptResponseCode in response, going to ERROR. Response: "
					+ bodyForLog(fromPost));
			cleanSS(ns);
			retVal = Action.goTo(ERROR).build();
		}

		else if (attemptCode.equalsIgnoreCase("SUCCESS")) {// check if fromPost has success
			logger.debug(loggerPrefix + "checkApproval() - SUCCESS");
			cleanSS(ns);
			retVal = Action.goTo(SUCCESS).build();

		}

		else if (attemptCode.equalsIgnoreCase("CHALLENGE") && "SUCCESS".equalsIgnoreCase(methodCode)) {
			// approved, but RSA wants a further method before it will call the attempt done
			logger.debug(loggerPrefix + "checkApproval() - approved, RSA issued a follow-on challenge");
			retVal = startChoice(fromPost, ns);
		}
		else if (attemptCode.equalsIgnoreCase("FAIL") || "FAIL".equalsIgnoreCase(methodCode)) {
			logger.error(loggerPrefix + "checkApproval() - denied. attemptResponseCode: " + attemptCode
					+ ", methodResponseCode: " + methodCode + ", response: " + bodyForLog(fromPost));
			cleanSS(ns);
			retVal = Action.goTo(FAILURE).build();
		}
		else {
			logger.debug(loggerPrefix + "checkApproval() - still pending, polling again");
			if (step == 3) {
				String url = getQRURL(fromPost);
				callbacks.add(generateQRCallback(url));
			}
			PollingWaitCallback pwc = new PollingWaitCallback("5000", config.theWaitingForResponseMessage());
			callbacks.add(pwc);

			ConfirmationCallback cancelCallback = newCancelOnlyCallback();
			callbacks.add(cancelCallback);

			ns.putShared("confirmationCB", cancelCallback.getOptions());
			ns.putShared("P1ProtectStep", step);

			retVal = Action.send(callbacks).build();
		}

		return retVal;
	}

	/**
	 * Shared handling for an /authn/verify response that came back from a tokencode prompt
	 * (P1ProtectStep 1 and 4). RSA can answer in three interesting ways:
	 *
	 * <ul>
	 * <li>{@code SUCCESS} — done.</li>
	 * <li>{@code CHALLENGE} + method {@code SUCCESS} — the code was accepted but RSA wants
	 * another method before it will finish. This is how SECURID_NEXT_TOKENCODE and New PIN
	 * arrive, so hand back to the choice machinery.</li>
	 * <li>{@code CHALLENGE} + method {@code FAIL} — the code was wrong and RSA is still willing
	 * to take another attempt, so re-prompt in place.</li>
	 * </ul>
	 *
	 * The last two cases used to be collapsed together and both routed to FAILURE, which meant a
	 * single mistyped tokencode ended the journey and a Next Tokencode challenge was never shown.
	 */
	private Action handleTokenVerifyResult(JSONObject result, NodeState ns, int step) throws Exception {
		String attemptCode = result.optString("attemptResponseCode", null);
		String methodCode = methodResponseCode(result);
		String theChoice = ns.get("p1Choice").asString();
		logger.debug(loggerPrefix + "handleTokenVerifyResult() - step: " + step + ", p1Choice: " + theChoice
				+ ", attemptResponseCode: " + attemptCode + ", methodResponseCode: " + methodCode);

		if (attemptCode == null) {
			logger.error(loggerPrefix + "handleTokenVerifyResult() - no attemptResponseCode in verify response, going "
					+ "to FAILURE. Response: " + bodyForLog(result));
			cleanSS(ns);
			return Action.goTo(FAILURE).build();
		}

		if (attemptCode.equalsIgnoreCase("SUCCESS")) {
			logger.debug(loggerPrefix + "handleTokenVerifyResult() - SUCCESS");
			cleanSS(ns);
			return Action.goTo(SUCCESS).build();
		}

		if (attemptCode.equalsIgnoreCase("CHALLENGE") && "SUCCESS".equalsIgnoreCase(methodCode)) {
			logger.debug(loggerPrefix + "handleTokenVerifyResult() - code accepted, RSA issued a follow-on challenge");
			return startChoice(result, ns);
		}

		if (attemptCode.equalsIgnoreCase("CHALLENGE")) {
			// Wrong code, but the attempt is still open. Ask again rather than failing the journey.
			// No local retry counter on purpose: RSA owns the retry budget. Once its policy is
			// exhausted it answers attemptResponseCode FAIL and we fall through to FAILURE below,
			// and the attempt expires on its own at authnAttemptTimeout regardless.
			logger.debug(loggerPrefix + "handleTokenVerifyResult() - code rejected, RSA still accepting attempts, "
					+ "re-prompting for " + theChoice + ". Response: " + bodyForLog(result));
			return rePromptForTokencode(result, ns, theChoice, step);
		}

		logger.error(loggerPrefix + "handleTokenVerifyResult() - terminal failure. attemptResponseCode: " + attemptCode
				+ ", methodResponseCode: " + methodCode + ", response: " + bodyForLog(result));
		cleanSS(ns);
		return Action.goTo(FAILURE).build();
	}

	/**
	 * Re-send the tokencode prompt for the same choice, staying on the same P1ProtectStep.
	 */
	private Action rePromptForTokencode(JSONObject result, NodeState ns, String theChoice, int step) throws Exception {
		// The next verify has to reference the messageId of THIS response. Leaving the previous
		// one in state gets the retry rejected as out of sequence, which looks identical to a
		// wrong tokencode from the journey's point of view.
		ns.putShared("inResponseTo", getDataFromContext(result, "messageId"));
		ns.putShared("authnAttemptId", getDataFromContext(result, "authnAttemptId"));

		List<Callback> callbacks = new ArrayList<>();
		callbacks.add(new PasswordCallback(promptFor(theChoice), true));
		ConfirmationCallback confirmation = newNextCancelCallback();
		callbacks.add(confirmation);

		ns.putShared("confirmationCB", confirmation.getOptions());
		ns.putShared("P1ProtectStep", step);

		return Action.send(callbacks).build();
	}

	/**
	 * Label for the tokencode input. RSA gives us a method id, not something worth showing a user,
	 * so the Next Tokencode case gets its own configurable prompt.
	 */
	private String promptFor(String theChoice) {
		if ("SECURID_NEXT_TOKENCODE".equalsIgnoreCase(theChoice))
			return config.theNextTokencodePrompt();
		return theChoice;
	}

	/**
	 * {@code methodResponseCode} for the first credential validation result, or null when RSA did
	 * not send one. {@code getJSONArray} throws on a missing key, and RSA legitimately omits
	 * {@code credentialValidationResults} on the first challenge of an attempt, so every read of
	 * this field goes through here.
	 */
	private String methodResponseCode(JSONObject fromPost) {
		if (fromPost == null)
			return null;
		JSONArray results = fromPost.optJSONArray("credentialValidationResults");
		if (results == null || results.length() == 0)
			return null;
		JSONObject first = results.optJSONObject(0);
		if (first == null)
			return null;
		return first.optString("methodResponseCode", null);
	}

	/**
	 * Response body for a log line, truncated. RSA's initialize/verify responses echo method ids
	 * and status codes but never the submitted tokencode or PIN, so this is safe to log.
	 */
	private String bodyForLog(JSONObject fromPost) {
		if (fromPost == null)
			return "<null>";
		String body = fromPost.toString();
		if (body.length() <= LOG_BODY_LIMIT)
			return body;
		return body.substring(0, LOG_BODY_LIMIT) + "...<truncated, " + body.length() + " chars>";
	}

	// TODO Need to make these a bit more unique.
	private void cleanSS(NodeState ns) {
		ns.remove("p1Choice");
		ns.remove("P1choices");
		ns.remove("P1ProtectStep");
		ns.remove("confirmationCB");
		ns.remove("inResponseTo");
		ns.remove("authnAttemptId");
		ns.remove("PingReferenceId");
	}

	private boolean cancelPushed(TreeContext context, NodeState ns) {
		boolean retVal = false;
		JsonValue jv = ns.get("confirmationCB");
		for (Iterator<? extends Callback> thisIt = context.getAllCallbacks().iterator(); thisIt.hasNext();) {
			Callback thisCallback = thisIt.next();
			if (thisCallback instanceof ConfirmationCallback) {
				ConfirmationCallback cc = (ConfirmationCallback) thisCallback;
				int theSelection = cc.getSelectedIndex();
				if (theSelection == 100)// means cancel was not hit
					break;
				String buttonPushed = (String) jv.asList().get(cc.getSelectedIndex());
				if (buttonPushed.equalsIgnoreCase("cancel")) {
					retVal = true;
				}
				break;
			}
		}
		return retVal;
	}

	private JSONObject checkToken(TreeContext context) throws Exception {
		NodeState ns = context.getStateFor(this);

		HttpPost post = new HttpPost(config.baseURL() + verifyAppend);
		JsonValue theContextBody = getContext(ns.get("inResponseTo").asString(), ns.get("authnAttemptId").asString());
		JsonValue theBody = new JsonValue(new LinkedHashMap<String, Object>(1));
		theBody.put("context", theContextBody);
		String theChoice = ns.get("p1Choice").asString();
		logger.debug(loggerPrefix + "checkToken() - verifying choice: " + theChoice);

		String token = "";
		for (Iterator<? extends Callback> thisIt = context.getAllCallbacks().iterator(); thisIt.hasNext();) {
			Callback thisCallback = thisIt.next();
			if (thisCallback instanceof StringAttributeInputCallback) {
				StringAttributeInputCallback cb = (StringAttributeInputCallback) thisCallback;
				token = cb.getValue();
				break;
			}
			else if(thisCallback instanceof PasswordCallback) {
				PasswordCallback pc = (PasswordCallback) thisCallback;
				token = String.copyValueOf(pc.getPassword());
				break;
			}
			
		}

		if (theChoice.equalsIgnoreCase("Emergency Tokencode"))
			theBody.add("subjectCredentials", getSubCred("EMERGENCY_TOKENCODE", token));
		else if (theChoice.equalsIgnoreCase("RSA SecurID"))
			theBody.add("subjectCredentials", getSubCred("SECURID", token));
		else if (theChoice.equalsIgnoreCase("Authenticate Tokencode"))
			theBody.add("subjectCredentials", getSubCred("TOKEN", token));
		else if (theChoice.equalsIgnoreCase("Voice Tokencode"))
			theBody.add("subjectCredentials", getSubCred("VOICE", token));
		else if (theChoice.equalsIgnoreCase("SMS Tokencode"))
			theBody.add("subjectCredentials", getSubCred("SMS", token));
		else if (theChoice.equalsIgnoreCase("RSA SecurID New PIN"))
			theBody.add("subjectCredentials", getSubCred("SECURID_NEW_PIN", token));
		else if (theChoice.equalsIgnoreCase("SECURID_NEWPIN"))
			theBody.add("subjectCredentials", getSubCred("SECURID_NEWPIN", token));
		else if (theChoice.equalsIgnoreCase("SECURID"))
			theBody.add("subjectCredentials", getSubCred("SECURID", token));
		else if (theChoice.equalsIgnoreCase("SECURID_NEXT_TOKENCODE"))
			theBody.add("subjectCredentials", getSubCred("SECURID_NEXT_TOKENCODE", token));
		else {
			// Without a match we would POST a bare context, and RSA answers that with a generic
			// failure that looks exactly like a wrong tokencode.
			logger.error(loggerPrefix + "checkToken() - no subjectCredentials mapping for choice: " + theChoice);
			throw new NodeProcessException("No RSA credential mapping for choice: " + theChoice);
		}

		// Length only. The tokencode itself must never reach a log.
		logger.debug(loggerPrefix + "checkToken() - submitting " + token.length() + " character code for " + theChoice);

		post.setEntity(new StringEntity(theBody.toString()));

		JSONObject jo = doPost(post);
		logger.debug(loggerPrefix + "checkToken() - doPost returned, attemptResponseCode: "
				+ jo.optString("attemptResponseCode", null) + ", methodResponseCode: " + methodResponseCode(jo));
		return jo;
	}

	private List<Callback> choiceSelected(TreeContext context, NodeState ns) throws Exception {
		// they just picked which MFA they want to use put them on the right path
		// depending on choice, we need to show them either input screen or make the push and show a spinner, or QR code and set P1ProtectStep accordingly
		List<Callback> callbacks = new ArrayList<>();

		for (Iterator<? extends Callback> thisIt = context.getAllCallbacks().iterator(); thisIt.hasNext();) {
			Callback thisCallback = thisIt.next();
			String theChoice = "";
			if (thisCallback instanceof ChoiceCallback) {
				ChoiceCallback cb = (ChoiceCallback) thisCallback;
				JsonValue jv = ns.get("P1choices");
				List<String> theList = jv.asList(String.class);
				theChoice = theList.get(cb.getSelectedIndexes()[0]);
				logger.debug(loggerPrefix + "choiceSelected() - user selected choice: " + theChoice);
				ns.remove("P1choices");
				ns.putShared("p1Choice", theChoice);
				callbacks = choiceSelectedHelper(theChoice, ns);
				break;
			}
		}
		return callbacks;
	}

	private List<Callback> choiceSelectedHelper(String theChoice, NodeState ns) throws Exception {
		logger.debug(loggerPrefix + "choiceSelectedHelper() - routing choice: " + theChoice);
		List<Callback> callbacks = new ArrayList<>();
		switch (theChoice) {
		case "RSA SecurID":
		case "Authenticate Tokencode":
		case "Emergency Tokencode":
		case "RSA SecurID New PIN":
		case "SECURID_NEWPIN":
		case "SECURID":
		case "SECURID_NEXT_TOKENCODE":
			// need to show them an input screen
			logger.debug(loggerPrefix + "choiceSelectedHelper() - entering tokencode input path for choice: " + theChoice);
			PasswordCallback pc = new PasswordCallback(promptFor(theChoice), true);
			ConfirmationCallback tokencodeConfirmation = newNextCancelCallback();
			callbacks.add(pc);
			callbacks.add(tokencodeConfirmation);
			ns.putShared("P1ProtectStep", 1);
			ns.putShared("confirmationCB", tokencodeConfirmation.getOptions());
			break;
		case "Device Biometrics":
		case "Approve":
			logger.debug(loggerPrefix + "choiceSelectedHelper() - entering push/biometrics path for choice: " + theChoice);
			callbacks.addAll(pushSetup(theChoice, ns, 2));
			break;
		case "QR Code":
			// need to show them a QR code and a wait till done
			logger.debug(loggerPrefix + "choiceSelectedHelper() - entering QR code path for choice: " + theChoice);
			callbacks.addAll(pushSetup(theChoice, ns, 3));
			break;

		case "Voice Tokencode":
		case "SMS Tokencode":
			logger.debug(loggerPrefix + "choiceSelectedHelper() - entering voice/SMS path for choice: " + theChoice);
			callbacks.addAll(vOrSSetup(theChoice, ns, 4));
			break;

		default:
			// Falling through here used to return an empty callback list, and Action.send() with
			// nothing in it fails further downstream with no hint as to why. Name the method
			// instead so the log says which RSA method id we do not handle.
			logger.error(loggerPrefix + "choiceSelectedHelper() - unhandled RSA authentication method: " + theChoice);
			throw new NodeProcessException("Unhandled RSA authentication method: " + theChoice);
		}
		return callbacks;
	}
	
	private List<Callback> vOrSSetup(String theChoice, NodeState ns, int step) throws Exception{
		logger.debug(loggerPrefix + "vOrSSetup() - entry, theChoice: " + theChoice + ", step: " + step);
		List<Callback> callbacks = new ArrayList<>();

		ConfirmationCallback confirmation = newNextCancelCallback();
		ns.putShared("confirmationCB", confirmation.getOptions());
		ns.putShared("P1ProtectStep", step);
		HttpPost post = new HttpPost(config.baseURL() + verifyAppend);
		JsonValue theContextBody = getContext(ns.get("inResponseTo").asString(), ns.get("authnAttemptId").asString());
		JsonValue theBody = new JsonValue(new LinkedHashMap<String, Object>(1));
		theBody.put("context", theContextBody);

		if (theChoice.equalsIgnoreCase("SMS Tokencode"))
			theBody.add("subjectCredentials", getSubCredVOrS("SMS"));

		if (theChoice.equalsIgnoreCase("Voice Tokencode"))
			theBody.add("subjectCredentials", getSubCredVOrS("VOICE"));

		post.setEntity(new StringEntity(theBody.toString()));
		// Send init call to SecurID
		JSONObject fromPost = doPost(post);
		logger.debug(loggerPrefix + "vOrSSetup() - doPost returned, attemptResponseCode: "
				+ fromPost.optString("attemptResponseCode", null) + ", methodResponseCode: "
				+ methodResponseCode(fromPost));
		ns.putShared("inResponseTo", getDataFromContext(fromPost, "messageId"));
		ns.putShared("authnAttemptId", getDataFromContext(fromPost, "authnAttemptId"));

		//StringAttributeInputCallback tokenCode = new StringAttributeInputCallback("smsvoiceToken", theChoice, null, true);
		PasswordCallback pc = new PasswordCallback(theChoice, true);

		callbacks.add(pc);
		callbacks.add(confirmation);
		return callbacks;
	}

	private List<Callback> pushSetup(String theChoice, NodeState ns, int step) throws Exception {
		logger.debug(loggerPrefix + "pushSetup() - entry, theChoice: " + theChoice + ", step: " + step);
		List<Callback> callbacks = new ArrayList<>();

		ConfirmationCallback cancelCallback = newCancelOnlyCallback();
		ns.putShared("confirmationCB", cancelCallback.getOptions());
		ns.putShared("P1ProtectStep", step);
		JsonValue refJV = ns.get("PingReferenceId");
		String ref = null;
		if (refJV != null && refJV.isString()) {
			ref = refJV.asString();
		}
		JSONObject fromPost = makePushPost(ns, theChoice, ref);
		logger.debug(loggerPrefix + "pushSetup() - makePushPost returned, attemptResponseCode: "
				+ fromPost.optString("attemptResponseCode", null) + ", methodResponseCode: "
				+ methodResponseCode(fromPost));
		ns.putShared("inResponseTo", getDataFromContext(fromPost, "messageId"));
		ns.putShared("authnAttemptId", getDataFromContext(fromPost, "authnAttemptId"));
		ns.putShared("PingReferenceId", getPushRef(fromPost, theChoice));

		if (step == 3) {
			String url = getQRURL(fromPost);
			callbacks.add(generateQRCallback(url));
		}
		PollingWaitCallback pwc = new PollingWaitCallback("5000", config.theWaitingForResponseMessage());
		callbacks.add(pwc);
		callbacks.add(cancelCallback);

		return callbacks;
	}

	/**
	 * referenceId for the in-flight push/QR challenge, or "" if there isn't one. Every level of
	 * this structure is optional: a terminal response (SUCCESS or FAIL) carries no
	 * challengeMethods at all, and this is called before we know which kind of response we got.
	 */
	private String getPushRef(JSONObject fromPost, String theChoice) {
		String retVal = "";

		JSONObject challengeMethods = fromPost.optJSONObject("challengeMethods");
		if (challengeMethods == null)
			return retVal;
		JSONArray theChallenges = challengeMethods.optJSONArray("challenges");
		if (theChallenges == null)
			return retVal;

		for (int i = 0; i < theChallenges.length(); i++) {
			JSONObject thisChallenge = theChallenges.optJSONObject(i);
			if (thisChallenge == null)
				continue;
			JSONArray requiredMethods = thisChallenge.optJSONArray("requiredMethods");
			if (requiredMethods == null || requiredMethods.length() == 0)
				continue;
			JSONObject thisJO = requiredMethods.optJSONObject(0);
			if (thisJO == null)
				continue;
			// displayName is null for some methods, in which case methodId is what we matched on
			// when we built the choice list, so match on it here too.
			String name = thisJO.optString("displayName", null);
			if (name == null)
				name = thisJO.optString("methodId", null);
			if (name == null || !name.equalsIgnoreCase(theChoice))
				continue;

			JSONArray versions = thisJO.optJSONArray("versions");
			if (versions == null || versions.length() == 0)
				break;
			retVal = versions.getJSONObject(0).optString("referenceId", "");
			break;
		}
		if (retVal.isEmpty())
			logger.debug(loggerPrefix + "getPushRef() - no referenceId found for choice: " + theChoice);
		return retVal;
	}

	private String getQRURL(JSONObject fromPost) {
		JSONArray results = fromPost.optJSONArray("credentialValidationResults");
		if (results == null || results.length() == 0) {
			logger.error(loggerPrefix + "getQRURL() - no credentialValidationResults in response: " + bodyForLog(fromPost));
			return "";
		}
		JSONArray authnAttributes = results.getJSONObject(0).optJSONArray("authnAttributes");
		if (authnAttributes == null || authnAttributes.length() == 0) {
			logger.error(loggerPrefix + "getQRURL() - no authnAttributes in response: " + bodyForLog(fromPost));
			return "";
		}
		return authnAttributes.getJSONObject(0).optString("value", "");
	}

	private Callback generateQRCallback(String text) {
		return new ScriptTextOutputCallback(GenerationUtils.getQRCodeGenerationJavascriptForAuthenticatorAppRegistration("callback_0", text));
	}

	private JSONObject makePushPost(NodeState ns, String theChoice, String refID) throws Exception {
		// need to send verify
		HttpPost post = new HttpPost(config.baseURL() + verifyAppend);
		JsonValue theContextBody = getContext(ns.get("inResponseTo").asString(), ns.get("authnAttemptId").asString());
		JsonValue theBody = new JsonValue(new LinkedHashMap<String, Object>(1));
		theBody.put("context", theContextBody);
		if (theChoice.equalsIgnoreCase("Device Biometrics"))
			theBody.add("subjectCredentials", getSubCred("FINGERPRINT", refID));
		else if (theChoice.equalsIgnoreCase("Approve"))
			theBody.add("subjectCredentials", getSubCred("APPROVE", refID));// if approval
		else if (theChoice.equalsIgnoreCase("QR Code"))
			theBody.add("subjectCredentials", getSubCred("QRCODE", refID));// if QR Code

		post.setEntity(new StringEntity(theBody.toString()));
		// Send init call to SecurID
		return doPost(post);
	}

	private JSONArray getSubCred(String methodId, String value) {
		Map<String, Object> theMethMap = new LinkedHashMap<String, Object>(1);
		theMethMap.put("methodId", methodId);
		JSONArray subCreds = new JSONArray();

		if (methodId.equalsIgnoreCase("EMERGENCY_TOKENCODE") || methodId.equalsIgnoreCase("SECURID") || methodId.equalsIgnoreCase("TOKEN") || methodId.equalsIgnoreCase("SMS") || methodId.equalsIgnoreCase("VOICE") ||  methodId.equalsIgnoreCase("SECURID_NEW_PIN") ||  methodId.equalsIgnoreCase("SECURID_NEWPIN") || methodId.equalsIgnoreCase("SECURID_NEXT_TOKENCODE")) {
			Map<String, Object> contextBody = new LinkedHashMap<String, Object>(1);
			contextBody.put("name", methodId);
			contextBody.put("value", value);
			contextBody.put("dataType", "STRING");
			JSONArray collectedInputs = new JSONArray();
			collectedInputs.put(contextBody);
			theMethMap.put("collectedInputs", collectedInputs);
		}

		if (methodId.equalsIgnoreCase("FINGERPRINT") || methodId.equalsIgnoreCase("APPROVE") || methodId.equalsIgnoreCase("QRCODE")) {
			theMethMap.put("referenceId", value);
		}

		subCreds.put(theMethMap);
		return subCreds;
	}
	
	
	private JSONArray getSubCredVOrS(String methodId) {
		Map<String, Object> theMethMap = new LinkedHashMap<String, Object>(1);
		theMethMap.put("methodId", methodId);
		JSONArray subCreds = new JSONArray();

		Map<String, Object> contextBody = new LinkedHashMap<String, Object>(1);
		contextBody.put("name", methodId);
		JSONArray collectedInputs = new JSONArray();
		collectedInputs.put(contextBody);
		theMethMap.put("collectedInputs", collectedInputs);

		subCreds.put(theMethMap);
		return subCreds;
	}
	

	private JSONObject doInitialize(TreeContext context) throws Exception {
		NodeState ns = context.getStateFor(this);
		String username = ns.get("username").asString();
		if (StringUtils.isEmpty(username)) {
			logger.error(loggerPrefix + "doInitialize() - username missing in shared state, throwing NodeProcessException");
			throw new NodeProcessException("username does not exist in sharedsate");
		}

		HttpPost post = new HttpPost(config.baseURL() + initializeAppend);
		JsonValue theBody = getInitializeBody(config.clientID(), username, config.assurancePolicy());
		post.setEntity(new StringEntity(theBody.toString()));

		// Send init call to SecurID
		JSONObject fromPost = doPost(post);
		logger.debug(loggerPrefix + "doInitialize() - doPost returned for subject '" + username
				+ "', attemptResponseCode: " + fromPost.optString("attemptResponseCode", null)
				+ ", methodResponseCode: " + methodResponseCode(fromPost));
		return fromPost;

	}

	private List<Callback> completeInitialize(NodeState ns, ArrayList<String> choices, JSONObject fromPost) throws Exception {
		// Save things to TransientState
		ns.putShared("inResponseTo", getDataFromContext(fromPost, "messageId"));
		ns.putShared("authnAttemptId", getDataFromContext(fromPost, "authnAttemptId"));
		ns.putShared("P1choices", choices);
		ns.putShared("P1ProtectStep", 0);

		List<Callback> callbacks = new ArrayList<>();

		// Then send to screen options
		ChoiceCallback cc = new ChoiceCallback(config.thePrompt(), Arrays.copyOf(choices.toArray(), choices.size(), String[].class), 0, false);
		// ConfirmationCallback confirmationCallback = new ConfirmationCallback(ConfirmationCallback.INFORMATION, new String[]{"Next", "Cancel"}, 0);

		ConfirmationCallback confirmation = newNextCancelCallback();
		callbacks.add(cc);
		callbacks.add(confirmation);
		ns.putShared("confirmationCB", confirmation.getOptions());
		return callbacks;
	}

	private JsonValue getInitializeBody(String clientID, String subject, String assurance) {

		JsonValue body = new JsonValue(new LinkedHashMap<String, Object>(1));

		body.put("authnAttemptTimeout", 180);
		body.put("clientId", clientID);
		body.put("subjectName", subject);
		body.put("lang", "us_EN");
		body.put("assurancePolicyId", assurance);

		JsonValue contextBody = new JsonValue(new LinkedHashMap<String, Object>(1));
		contextBody.put("messageId", UUID.randomUUID().toString());

		body.put("context", contextBody);

		return body;

	}

	private JsonValue getContext(String inResponseTo, String authnAttemptId) {
		JsonValue contextBody = new JsonValue(new LinkedHashMap<String, Object>(1));
		contextBody.put("authnAttemptId", authnAttemptId);
		contextBody.put("messageId", UUID.randomUUID().toString());
		contextBody.put("inResponseTo", inResponseTo);
		return contextBody;
	}

	private String getDataFromContext(JSONObject data, String key) throws NodeProcessException {
		JSONObject theContext = data.optJSONObject("context");
		if (theContext == null) {
			logger.error(loggerPrefix + "getDataFromContext() - RSA response carries no context object, so the attempt "
					+ "cannot be continued. Response: " + bodyForLog(data));
			throw new NodeProcessException("RSA response contained no context object");
		}
		String returnValue = theContext.optString(key, null);
		if (returnValue == null) {
			logger.error(loggerPrefix + "getDataFromContext() - RSA response context carries no '" + key
					+ "'. Context: " + bodyForLog(theContext));
			throw new NodeProcessException("RSA response context contained no " + key);
		}
		return returnValue;
	}

	private JSONObject doPost(HttpPost post) throws Exception {
		JSONObject retVal = null;
		CloseableHttpClient httpClient = null;
		try {
			post.addHeader("Content-Type", "application/json");
			post.setHeader("client-key", config.clientKey());
			if (!config.verifySSL()) {
				// Create a trust manager that does not validate certificate chains
				//httpClient = HttpClients.custom().setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build();
				httpClient = HttpClients.
						custom()
						.setSSLContext(
								SSLContextBuilder.
								create().
								loadTrustMaterial(
										TrustAllStrategy.INSTANCE)
								.build())
						.setSSLHostnameVerifier(
								NoopHostnameVerifier.INSTANCE)
						.build();
			} else {
				httpClient = HttpClientBuilder.create().build();
			}

			HttpResponse response = httpClient.execute(post);
			logger.debug(loggerPrefix + "doPost() - URL: " + post.getURI().toString() + ", HTTP status: " + response.getStatusLine().getStatusCode());

			HttpEntity entity = response.getEntity();
			String content = EntityUtils.toString(entity);

			retVal = new JSONObject(content);
			// Debug-gated, and RSA never echoes the submitted tokencode or PIN. Without this the
			// only thing a failed authentication leaves behind is a bare response code, which is
			// not enough to tell a wrong code from a method the user has no credential for.
			logger.debug(loggerPrefix + "doPost() - response body: " + bodyForLog(retVal));

		} catch (Exception e) {
			throw new Exception(e.fillInStackTrace());

		} finally {
			if (httpClient != null) {
				try {
					httpClient.close();
				} catch (Exception e) {
					logger.error(loggerPrefix + "Error occurred trying to close the httpClient. Not fatal.");
				}
			}
		}

		return retVal;
	}

	private ArrayList<String> getChoices(JSONObject fromPost) {
		ArrayList<String> retVal = new ArrayList<String>();
		int priority = 2;

		JSONObject challengeMethods = fromPost.optJSONObject("challengeMethods");
		if (challengeMethods == null) {
			logger.debug(loggerPrefix + "getChoices() - response has no challengeMethods object");
			return retVal;
		}
		JSONArray theChallenges = challengeMethods.optJSONArray("challenges");
		if (theChallenges == null) {
			logger.debug(loggerPrefix + "getChoices() - challengeMethods has no challenges array");
			return retVal;
		}

		// TODO Filter and add choices of only ones we support
		for (int i = 0; i < theChallenges.length(); i++) {

			JSONObject thisChallenge = theChallenges.optJSONObject(i);
			JSONArray requiredMethods = thisChallenge == null ? null : thisChallenge.optJSONArray("requiredMethods");
			if (requiredMethods == null || requiredMethods.length() == 0) {
				logger.debug(loggerPrefix + "getChoices() - challenge " + i + " has no requiredMethods, skipping");
				continue;
			}
			JSONObject thisJO = requiredMethods.getJSONObject(0);

			// versions and methodAttributes are both optional -- getJSONArray() throws on a
			// missing key, which used to take out the whole initialize response and surface as
			// ERROR rather than as the method simply being unavailable.
			JSONArray versions = thisJO.optJSONArray("versions");
			JSONArray methAttr = null;
			if (versions != null && versions.length() > 0)
				methAttr = versions.getJSONObject(0).optJSONArray("methodAttributes");

			if (methAttr != null && methAttr.length() > 0
					&& "METHOD_NOT_APPLICABLE".equalsIgnoreCase(methAttr.getJSONObject(0).optString("name", null))) {
				// RSA is telling us this method exists but the user cannot use it right now
				logger.debug(loggerPrefix + "getChoices() - skipping METHOD_NOT_APPLICABLE method: "
						+ thisJO.optString("methodId", "<no methodId>"));
			} else {
				// displayName comes back as JSON null for the SECURID_* methods, in which case the
				// methodId is the only label we have -- that is why the choice a user sees for
				// next tokencode is literally "SECURID_NEXT_TOKENCODE".
				String thisOne = thisJO.optString("displayName", null);
				if (thisOne == null)
					thisOne = thisJO.optString("methodId", null);
				if (thisOne == null) {
					logger.debug(loggerPrefix + "getChoices() - challenge " + i + " has neither displayName nor "
							+ "methodId, skipping");
					continue;
				}

				if (!retVal.contains(thisOne) && 
					(thisOne.equalsIgnoreCase("RSA SecurID") ||
					thisOne.equalsIgnoreCase("Authenticate Tokencode") ||
					thisOne.equalsIgnoreCase("Emergency Tokencode") ||
					thisOne.equalsIgnoreCase("RSA SecurID New PIN") ||
					thisOne.equalsIgnoreCase("Device Biometrics") ||
					thisOne.equalsIgnoreCase("Approve") ||
					thisOne.equalsIgnoreCase("QR Code") ||
					thisOne.equalsIgnoreCase("Voice Tokencode") ||
					thisOne.equalsIgnoreCase("SMS Tokencode") ||
					thisOne.equalsIgnoreCase("SECURID_NEWPIN") ||
					thisOne.equalsIgnoreCase("SECURID") ||
					thisOne.equalsIgnoreCase("SECURID_NEXT_TOKENCODE"))) {
					boolean hasPriority = thisJO.has("priority") && !thisJO.isNull("priority");
					if (retVal.size()>0 && hasPriority) {
						//need to put higher priority first
						int thisPriority = thisJO.getInt("priority");

						if (thisPriority < priority) {
							thisOne = retVal.set(0, thisOne);
							priority = thisPriority;
						}
					}
					else if (hasPriority){
						priority = thisJO.getInt("priority");
					}
					retVal.add(thisOne);
					logger.debug(loggerPrefix + "getChoices() - added eligible choice: " + thisOne);
				} else if (retVal.contains(thisOne)) {
					logger.debug(loggerPrefix + "getChoices() - duplicate choice, already present: " + thisOne);
				} else {
					// RSA offered a method this node has no callback path for. Worth logging by
					// name: an all-unsupported list is what produces a NOTENROLLED outcome, and
					// without this the reason is invisible.
					logger.debug(loggerPrefix + "getChoices() - RSA offered an unsupported method, ignoring: " + thisOne);
				}
			}

		}
		logger.debug(loggerPrefix + "getChoices() - total eligible choices found: " + retVal.size() + " " + retVal);
		return retVal;
	}

	/**
	 * Defines the possible outcomes from this node.
	 */
	public static class SecurIDOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, SecurIDOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(
					new Outcome(SUCCESS, bundle.getString("SuccessOutcome")), 
					new Outcome(FAILURE, bundle.getString("FailureOutcome")), 
					new Outcome(NOTENROLLED, bundle.getString("NotEnrolledOutcome")), 
					new Outcome(CANCEL, bundle.getString("CancelOutcome")), 
					new Outcome(ERROR, bundle.getString("ErrorOutcome")));
		}
	}
}
