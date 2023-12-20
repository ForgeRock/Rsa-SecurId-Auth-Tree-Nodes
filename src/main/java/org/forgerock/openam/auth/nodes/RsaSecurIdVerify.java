/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package org.forgerock.openam.auth.nodes;

import static org.forgerock.http.handler.HttpClientHandler.OPTION_HOSTNAME_VERIFIER;
import static org.forgerock.http.handler.HttpClientHandler.OPTION_TRUST_MANAGERS;
import static org.forgerock.http.protocol.Responses.noopExceptionFunction;
import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.auth.nodes.RSASecurIdUtil.*;
import static org.forgerock.openam.auth.nodes.RSASecurIdUtil.mapToJsonValue;
import static org.forgerock.util.CloseSilentlyFunction.closeSilently;
import static org.forgerock.util.Closeables.closeSilentlyAsync;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;
import java.util.UUID;

import javax.inject.Inject;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.lang.StringUtils;
import org.forgerock.http.HttpApplicationException;
import org.forgerock.http.handler.HttpClientHandler;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.Function;
import org.forgerock.util.Options;
import org.forgerock.util.i18n.PreferredLocales;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.sm.RequiredValueValidator;

@Node.Metadata(outcomeProvider = RsaSecurIdVerify.RsaSecurIdVerifyOutcomeProvider.class,
        configClass = RsaSecurIdVerify.Config.class,
        tags = {"mfa", "multi-factor authentication"})
public class RsaSecurIdVerify extends AbstractDecisionNode {

    private static final String BUNDLE = "org/forgerock/openam/auth/nodes/RsaSecurIdVerify";
    private final Logger logger = LoggerFactory.getLogger(RsaSecurIdVerify.class);
    private final Config config;
    private final Realm realm;
    private final HttpClientHandler clientHandler;
    private String loggerPrefix = "[RSA SecurId Verify][Marketplace] ";

    /**
     * Configuration for the node.
     */
    public interface Config {

        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        default String baseUrl() {
            return "https://securid.example.com/mfa/v1_1";
        }

        @Attribute(order = 200, validators = {RequiredValueValidator.class})
        @Password
        char[] clientKey();

        @Attribute(order = 300, validators = {RequiredValueValidator.class})
        default boolean verifySSL() {return true;};
    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm  The realm the node is in.
     */
    @Inject
    public RsaSecurIdVerify(@Assisted Config config, @Assisted Realm realm, HttpClientHandler clientHandler)
            throws HttpApplicationException {
        this.config = config;
        this.realm = realm;
        if (!config.verifySSL()) {
            // Create a trust manager that does not validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                        public void checkClientTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }
                        public void checkServerTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }
                    }
            };
            Options options = Options.defaultOptions();
            options.set(OPTION_TRUST_MANAGERS, trustAllCerts);
            options.set(OPTION_HOSTNAME_VERIFIER, HttpClientHandler.HostnameVerifier.ALLOW_ALL);
            this.clientHandler = new HttpClientHandler(options);
        } else {
            this.clientHandler = clientHandler;
        }
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        logger.debug("RsaSecurIdVerify started");
        String otp = context.getTransientState(SharedStateConstants.ONE_TIME_PASSWORD).asString();
        if (StringUtils.isEmpty(otp)) {
            logger.error("OTP is empty");
            return Action.goTo(RsaSecurIdVerifyOutcome.ERROR.name()).build();
        }
        Request request;
        try {
            request = new Request().setUri(config.baseUrl() + "/authn/verify");
        } catch (URISyntaxException e) {
            throw new NodeProcessException(e);
        }

        request.setMethod("POST");
        request.addHeaders(new GenericHeader(CLIENT_KEY, String.valueOf(config.clientKey())));
        request.setEntity(createVerifyBody(context.sharedState, otp));
        Promise<Action.ActionBuilder, NodeProcessException> verifyResponse = clientHandler.handle(new RootContext(),
                                                                                                  request)
                                                                                          .thenAlways(
                                                                                                  closeSilentlyAsync(
                                                                                                          request))
                                                                                          .then(closeSilently(
                                                                                                        mapToJsonValue()),
                                                                                                noopExceptionFunction())
                                                                                          .then(
                                                                                                  handleResponse(
                                                                                                          context.sharedState));

        try {
            return verifyResponse.getOrThrow().build();
        } catch (Exception ex) {
			logger.error(loggerPrefix + "Exception occurred: " + ex.getStackTrace());
			context.getStateFor(this).putShared(loggerPrefix + "Exception", new Date() + ": " + ex.getMessage());
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			ex.printStackTrace(pw);
			context.getStateFor(this).putShared(loggerPrefix + "StackTrace", new Date() + ": " + sw.toString());
			return Action.goTo(RsaSecurIdVerifyOutcome.ERROR.name()).build();
        }
        finally {
        	
			try {
				if (request != null) {
					request.close();
				}

				if (clientHandler != null) {
					clientHandler.close();
				}

			} catch (Exception e) {
				// Do Nothing
			}
        	
        	
        }
    }

    private Function<JsonValue, Action.ActionBuilder, NodeProcessException> handleResponse(JsonValue state) {
        return response -> {
            if (StringUtils.equals(response.get(ATTEMPT_RESPONSE_CODE).asString(), SUCCESS) && StringUtils.equals(
                    response.get(ATTEMPT_REASON_CODE).asString(), CREDENTIAL_VERIFIED)) {
                return Action.goTo(RsaSecurIdVerifyOutcome.SUCCESS.name());
            }

            if (StringUtils.equals(response.get(ATTEMPT_RESPONSE_CODE).asString(), FAIL) && StringUtils.equals(
                    response.get(ATTEMPT_REASON_CODE).asString(), VERIFY_ERROR)) {
                return Action.goTo(RsaSecurIdVerifyOutcome.FAIL.name());
            }

            if (StringUtils.equals(response.get(ATTEMPT_RESPONSE_CODE).asString(), CHALLENGE) && StringUtils.equals(
                    response.get(ATTEMPT_REASON_CODE).asString(), AUTHENTICATION_REQUIRED)) {
                JsonValue challenges = response.get(CHALLENGE_METHODS).get(CHALLENGES);

                for (JsonValue challenge : challenges) {
                    if (StringUtils.equals(challenge.get(REQUIRED_METHODS).get(0).get(METHOD_ID).asString(),
                                           SECURID_NEXT_TOKENCODE)) {
                        state.put(AUTHN_ATTEMPT_ID, response.get(CONTEXT).get(AUTHN_ATTEMPT_ID).asString());
                        state.put(MESSAGE_ID, response.get(CONTEXT).get(MESSAGE_ID).asString());
                        state.put(METHOD_ID, SECURID_NEXT_TOKENCODE);
                        return Action.goTo(RsaSecurIdVerifyOutcome.NEXT_TOKENCODE.name());
                    }
                }
            }


            return Action.goTo(RsaSecurIdVerifyOutcome.ERROR.name());


        };
    }


    private JsonValue createVerifyBody(JsonValue sharedState, String otp) {
        return json(object(
                field(RSASecurIdUtil.SUBJECT_CREDENTIALS, array(
                        object(
                                field(METHOD_ID, sharedState.get(METHOD_ID)),
                                field(RSASecurIdUtil.COLLECTED_INPUTS, array(object(
                                        field(RSASecurIdUtil.NAME, sharedState.get(METHOD_ID)),
                                        field(RSASecurIdUtil.VALUE, otp)
                                                                             )
                                )))
                )),
                field(CONTEXT, object(
                        field(MESSAGE_ID, UUID.randomUUID().toString()),
                        field(IN_RESPONSE_TO, sharedState.get(MESSAGE_ID)),
                        field(AUTHN_ATTEMPT_ID, sharedState.get(AUTHN_ATTEMPT_ID)))
                )));
    }

    private enum RsaSecurIdVerifyOutcome {

        SUCCESS("success"),
        NEXT_TOKENCODE("nextTokenCode"),
        FAIL("fail"),
        ERROR("error");

        private final String stringName;

        RsaSecurIdVerifyOutcome(String stringName) {
            this.stringName = stringName;
        }

        @Override
        public String toString() {
            return stringName;
        }
    }


    public static class RsaSecurIdVerifyOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
                                                                       RsaSecurIdVerify.class
                                                                               .getClassLoader());
            return ImmutableList.of(
                    new Outcome(RsaSecurIdVerifyOutcome.SUCCESS.name(), bundle.getString("successOutcome")),
                    new Outcome(RsaSecurIdVerifyOutcome.NEXT_TOKENCODE.name(),
                                bundle.getString("nextTokenCodeOutcome")),
                    new Outcome(RsaSecurIdVerifyOutcome.FAIL.name(), bundle.getString("failOutcome")),
                    new Outcome(RsaSecurIdVerifyOutcome.ERROR.name(), bundle.getString("errorOutcome")));
        }
    }


}
